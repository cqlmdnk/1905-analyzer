# SPDX-License-Identifier: GPL-2.0-or-later
"""Minimal Multi-AP **agent** emulator.

Behavior:

- Sends a Topology Discovery (1905.1) every ``topology_interval_s`` (default 5 s).
- Sends an AP-Autoconfig Search every ``autoconfig_interval_s`` (default
  30 s) until a Response with a matching frequency band is observed.
- Replies to inbound Topology Query, AP-Autoconfig Renew, AP Capability
  Query and AP Metrics Query messages with appropriate canned content.

The state machine here is intentionally minimal — interop testing needs a
peer that *responds*, not full controller-style mesh management.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field

from ieee1905.core import CMDU, MessageType
from ieee1905.core.tlvs import (
    AlMacAddress,
    ApCapability,
    ApMetrics,
    ApOperationalBss,
    ApRadioAdvancedCapabilities,
    ApRadioBasicCapabilities,
    AutoconfigFreqBand,
    CacCapabilities,
    CacRadioCapability,
    ChannelScanCapabilities,
    ChannelScanCapabilityOpClass,
    ChannelScanCapabilityRadio,
    DeviceInformation,
    LocalInterface,
    MacAddress,
    MetricCollectionInterval,
    MultiApProfile,
    OperatingClassCapability,
    OperationalBss,
    OperationalBssRadio,
    Profile2ApCapability,
    SearchedRole,
    SearchedService,
    SupportedService,
    WscFrame,
)
from ieee1905.emulator._common import (
    EmulatorContext,
    build_cmdu,
    run_sniff_loop,
    send_frame,
)
from ieee1905.emulator.wsc import (
    ATTR_ENCRYPTED_SETTINGS,
    ATTR_MESSAGE_TYPE,
    ATTR_PUBLIC_KEY,
    ATTR_REGISTRAR_NONCE,
    RF_BAND_2G,
    RF_BAND_5G,
    RF_BAND_60G,
    WSC_MSG_M2,
    BssCredential,
    WscEnrolleeSession,
    decrypt_encrypted_settings,
    derive_keys,
    parse_attributes,
    parse_credentials,
    verify_authenticator,
)

logger = logging.getLogger(__name__)


_FREQ_BAND_TO_RF_BAND = {
    0x00: RF_BAND_2G,
    0x01: RF_BAND_5G,
    0x02: RF_BAND_60G,
}


@dataclass(slots=True)
class FakeAgent:
    """A minimal EasyMesh agent that talks on ``interface``."""

    interface: str
    al_mac: bytes
    radio_id: bytes
    bssid: bytes
    ssid: bytes = b"emulator-mesh"
    topology_interval_s: float = 5.0
    autoconfig_interval_s: float = 30.0
    freq_band: int = 0x01  # 0=2.4GHz, 1=5GHz, 2=60GHz

    _ctx: EmulatorContext | None = None
    _sniff_thread: threading.Thread | None = None
    _heartbeat_thread: threading.Thread | None = None
    _wsc_session: WscEnrolleeSession | None = None
    _bss_credentials: list[BssCredential] = field(default_factory=list)
    _onboarded: bool = False

    def start(self) -> None:
        self._ctx = EmulatorContext(
            interface=self.interface,
            al_mac=self.al_mac,
            radio_id=self.radio_id,
            bssid=self.bssid,
            ssid=self.ssid,
        )
        self._sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._sniff_thread.start()
        self._heartbeat_thread.start()
        logger.info("FakeAgent started on %s (AL=%s)", self.interface, self.al_mac.hex(":"))

    def stop(self) -> None:
        if self._ctx is not None:
            self._ctx.stop_event.set()
        for t in (self._sniff_thread, self._heartbeat_thread):
            if t is not None:
                t.join(timeout=2.0)
        if self._ctx is not None:
            self._ctx.close_tx_session()
        logger.info("FakeAgent stopped")

    # ---- periodic emissions -------------------------------------------------

    def _heartbeat_loop(self) -> None:
        assert self._ctx is not None
        next_topology = time.monotonic()
        next_autoconfig = time.monotonic()
        while not self._ctx.stop_event.is_set():
            now = time.monotonic()
            if now >= next_topology:
                self._send_topology_discovery()
                next_topology = now + self.topology_interval_s
            if now >= next_autoconfig:
                self._send_autoconfig_search()
                next_autoconfig = now + self.autoconfig_interval_s
            self._ctx.stop_event.wait(timeout=0.5)

    def _send_topology_discovery(self) -> None:
        assert self._ctx is not None
        # IEEE 1905.1 §6.3.1: Topology Discovery carries AL MAC + the MAC
        # of the interface the frame is leaving. Both TLVs are mandatory.
        cmdu_bytes = build_cmdu(
            message_type=MessageType.TOPOLOGY_DISCOVERY.value,
            message_id=self._ctx.next_mid(),
            typed_tlvs=[
                AlMacAddress(al_mac=self.al_mac),
                MacAddress(mac=self.radio_id),
            ],
        )
        try:
            send_frame(self._ctx, cmdu_bytes)
        except Exception as exc:  # noqa: BLE001
            logger.warning("topology discovery send failed: %s", exc)

    def _send_autoconfig_search(self) -> None:
        assert self._ctx is not None
        # IEEE 1905.1 baseline TLVs: AlMacAddress, SearchedRole,
        # AutoconfigFreqBand. EasyMesh R1 adds SupportedService +
        # SearchedService (Multi-AP v1.0 §7.2.2). EasyMesh R2 adds the
        # Multi-AP Profile TLV (v2.0 §17.2.47). We advertise Profile-2.
        cmdu_bytes = build_cmdu(
            message_type=MessageType.AP_AUTOCONFIGURATION_SEARCH.value,
            message_id=self._ctx.next_mid(),
            typed_tlvs=[
                AlMacAddress(al_mac=self.al_mac),
                SearchedRole(role=0x00),
                AutoconfigFreqBand(band=self.freq_band),
                SupportedService(services=[0x01]),  # Multi-AP Agent
                SearchedService(services=[0x00]),  # looking for Controller
                MultiApProfile(profile=0x02),
            ],
        )
        try:
            send_frame(self._ctx, cmdu_bytes)
        except Exception as exc:  # noqa: BLE001
            logger.warning("autoconfig search send failed: %s", exc)

    # ---- inbound message handling ------------------------------------------

    def _sniff_loop(self) -> None:
        assert self._ctx is not None
        run_sniff_loop(self._ctx, self._on_cmdu)

    def _on_cmdu(self, src: bytes, cmdu: CMDU) -> None:
        mtype = cmdu.header.message_type
        if mtype == MessageType.TOPOLOGY_QUERY.value:
            self._reply_topology_response(src, cmdu)
        elif mtype == MessageType.AP_AUTOCONFIGURATION_RESPONSE.value:
            self._on_autoconfig_response(src, cmdu)
        elif mtype == MessageType.AP_AUTOCONFIGURATION_RENEW.value:
            # Renew restarts both halves of onboarding: search again, and
            # forget any cached BSS credentials so the next M2 round can
            # replace them.
            self._wsc_session = None
            self._bss_credentials.clear()
            self._onboarded = False
            self._send_autoconfig_search()
        elif mtype == MessageType.AP_AUTOCONFIGURATION_WSC.value:
            self._on_wsc(src, cmdu)
        elif mtype == MessageType.EM_AP_CAPABILITY_QUERY.value:
            self._reply_ap_capability_report(src, cmdu)
        elif mtype == MessageType.EM_AP_METRICS_QUERY.value:
            self._reply_ap_metrics_response(src, cmdu)

    def _reply_topology_response(self, dst: bytes, query: CMDU) -> None:
        assert self._ctx is not None
        # IEEE 1905.1 §6.4.4: 802.11 media types (0x0100-0x0107) require a
        # 10-byte media-specific info trailer (BSSID + role + channel band +
        # freq indexes). The emulator does not own a real radio so it
        # declares 1000BASE-T (0x0001) — Ethernet entries carry no
        # media-specific payload.
        #
        # Multi-AP v1.0 §7.2.3 + v2.0 §17.2: Topology Response carries
        # Device Information (which already holds the AL MAC),
        # SupportedService, AP Operational BSS, and Multi-AP Profile.
        # A standalone AL MAC Address TLV is not part of the message set.
        cmdu_bytes = build_cmdu(
            message_type=MessageType.TOPOLOGY_RESPONSE.value,
            message_id=query.header.message_id,
            typed_tlvs=[
                DeviceInformation(
                    al_mac=self.al_mac,
                    interfaces=[LocalInterface(mac=self.radio_id, media_type=0x0001)],
                ),
                SupportedService(services=[0x01]),  # Multi-AP Agent
                ApOperationalBss(
                    radios=[
                        OperationalBssRadio(
                            radio_id=self.radio_id,
                            bsses=[OperationalBss(bssid=self.bssid, ssid=self.ssid)],
                        )
                    ]
                ),
                MultiApProfile(profile=0x02),
            ],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    def _reply_ap_capability_report(self, dst: bytes, query: CMDU) -> None:
        assert self._ctx is not None
        # Multi-AP v1.0 §7.2.6 + v2.0 §17.2.x: AP Capability Report carries
        # AP Capability + per-radio AP Radio Basic Capabilities (+ optional
        # HT/VHT/HE caps). EasyMesh R2+ adds three mandatory TLVs:
        # Channel Scan Capabilities (v2.0 §17.2.39), CAC Capabilities
        # (v2.0 §17.2.46), and Profile-2 AP Capability (v2.0 §17.2.49).
        # AP Operational BSS belongs in Topology Response;
        # SupportedFreqBand / SupportedRole belong in AP-Autoconfig
        # Response.
        cmdu_bytes = build_cmdu(
            message_type=MessageType.EM_AP_CAPABILITY_REPORT.value,
            message_id=query.header.message_id,
            typed_tlvs=[
                ApCapability(flags=0xC0),
                ApRadioBasicCapabilities(
                    radio_id=self.radio_id,
                    max_bsses_supported=4,
                    operating_classes=[
                        OperatingClassCapability(
                            op_class=81, max_tx_eirp_dbm=23, non_operable_channels=[]
                        ),
                    ],
                ),
                ChannelScanCapabilities(
                    radios=[
                        ChannelScanCapabilityRadio(
                            radio_id=self.radio_id,
                            flags=0x00,
                            min_scan_interval_s=0,
                            operating_classes=[
                                # Empty channel list = "all channels in this op class".
                                ChannelScanCapabilityOpClass(op_class=81, channels=[]),
                            ],
                        )
                    ]
                ),
                CacCapabilities(
                    country_code=b"US",
                    radios=[
                        # Empty cac_types list = "this radio doesn't support CAC".
                        CacRadioCapability(radio_id=self.radio_id, cac_types=[]),
                    ],
                ),
                Profile2ApCapability(
                    max_prioritization_rules=4,
                    reserved=0,
                    capabilities=0xC0,  # BSS-config-param + byte-count units
                    max_total_number_of_vids=16,
                ),
                MetricCollectionInterval(interval_ms=5000),
            ],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    def _reply_ap_metrics_response(self, dst: bytes, query: CMDU) -> None:
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.EM_AP_METRICS_RESPONSE.value,
            message_id=query.header.message_id,
            typed_tlvs=[
                ApMetrics(
                    bssid=self.bssid,
                    channel_utilization=20,
                    num_associated_stas=0,
                    esp_info=b"\x80\x00\x10\x20",
                ),
            ],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    # ---- WSC M1 / M2 onboarding --------------------------------------------

    def _on_autoconfig_response(self, src: bytes, _cmdu: CMDU) -> None:
        # The Multi-AP Controller has acknowledged our band-matching Search.
        # WPS v2.0 §8.3.1: the enrollee now sends M1 to begin BSS provisioning.
        # One M1 per radio; the emulator owns a single radio.
        self._send_wsc_m1(src)

    def _send_wsc_m1(self, dst: bytes) -> None:
        assert self._ctx is not None
        rf_band = _FREQ_BAND_TO_RF_BAND.get(self.freq_band, RF_BAND_2G)
        session = WscEnrolleeSession(enrollee_mac=self.radio_id, rf_band=rf_band)
        m1_payload = session.build_m1()
        self._wsc_session = session
        # Multi-AP v2.0 §17.1.7: M1 envelope carries Radio Basic Capabilities,
        # the WSC TLV (the M1 frame itself), Profile-2 AP Capability, and AP
        # Radio Advanced Capabilities. No vendor-specific TLVs.
        cmdu_bytes = build_cmdu(
            message_type=MessageType.AP_AUTOCONFIGURATION_WSC.value,
            message_id=self._ctx.next_mid(),
            typed_tlvs=[
                ApRadioBasicCapabilities(
                    radio_id=self.radio_id,
                    max_bsses_supported=4,
                    operating_classes=[
                        OperatingClassCapability(
                            op_class=81, max_tx_eirp_dbm=23, non_operable_channels=[]
                        ),
                    ],
                ),
                WscFrame(wsc_payload=m1_payload),
                Profile2ApCapability(
                    max_prioritization_rules=4,
                    reserved=0,
                    capabilities=0xC0,
                    max_total_number_of_vids=16,
                ),
                ApRadioAdvancedCapabilities(radio_id=self.radio_id, flags=0xC0),
            ],
        )
        try:
            send_frame(self._ctx, cmdu_bytes, dst=dst)
            logger.info("WSC M1 sent to %s", dst.hex(":"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("WSC M1 send failed: %s", exc)

    def _on_wsc(self, _src: bytes, cmdu: CMDU) -> None:
        session = self._wsc_session
        if session is None:
            logger.debug("WSC frame received but no enrollee session is active")
            return
        wsc_payload: bytes | None = None
        for tlv in cmdu.tlvs:
            if tlv.tlv_type == WscFrame.TLV_TYPE:
                wsc_payload = tlv.payload
                break
        if wsc_payload is None:
            return

        try:
            attrs = dict(parse_attributes(wsc_payload))
        except ValueError as exc:
            logger.warning("WSC attributes malformed: %s", exc)
            return

        message_type = attrs.get(ATTR_MESSAGE_TYPE)
        if not message_type or message_type[0] != WSC_MSG_M2:
            logger.debug("WSC frame is not M2 (type=%r) — ignoring", message_type)
            return

        r_pub = attrs.get(ATTR_PUBLIC_KEY)
        r_nonce = attrs.get(ATTR_REGISTRAR_NONCE)
        enc = attrs.get(ATTR_ENCRYPTED_SETTINGS)
        if not (r_pub and r_nonce and enc):
            logger.warning("WSC M2 missing required attribute(s)")
            return

        keys = derive_keys(session, r_pub, r_nonce)
        if not verify_authenticator(keys, session.m1_bytes, wsc_payload):
            logger.warning("WSC M2 Authenticator mismatch — dropping")
            return

        try:
            inner = decrypt_encrypted_settings(keys, enc)
        except ValueError as exc:
            logger.warning("WSC M2 Encrypted Settings rejected: %s", exc)
            return

        new_creds = parse_credentials(inner)
        if not new_creds:
            logger.warning("WSC M2 contained no BSS credentials")
            return

        self._bss_credentials.extend(new_creds)
        self._onboarded = True
        for cred in new_creds:
            logger.info(
                "WSC M2 BSS configured: ssid=%r auth=0x%04x encr=0x%04x",
                cred.ssid.decode("utf-8", "replace"),
                cred.auth_type,
                cred.encr_type,
            )
