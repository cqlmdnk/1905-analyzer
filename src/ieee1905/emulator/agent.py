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
    ApHeCapabilities,
    ApHtCapabilities,
    ApMetrics,
    ApOperationalBss,
    ApRadioAdvancedCapabilities,
    ApRadioBasicCapabilities,
    AutoconfigFreqBand,
    BackhaulStaRadioCapabilities,
    CacCapabilities,
    CacRadioCapability,
    ChannelPreference,
    ChannelPreferenceOpClass,
    ChannelScanCapabilities,
    ChannelScanCapabilityOpClass,
    ChannelScanCapabilityRadio,
    ChannelSelectionResponse,
    DeviceInformation,
    LinkMetricResultCode,
    LocalInterface,
    MacAddress,
    MetricCollectionInterval,
    MultiApProfile,
    OperatingChannelOpClass,
    OperatingChannelReport,
    OperatingClassCapability,
    OperationalBss,
    OperationalBssRadio,
    Profile2ApCapability,
    RadioMetrics,
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
    metrics_interval_s: float = 30.0
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
        # Periodic AP metrics emission only starts once we're onboarded
        # — pre-onboarding, the controller has no BSS context for our
        # MID and discards the metric report.
        next_metrics = time.monotonic() + self.metrics_interval_s
        while not self._ctx.stop_event.is_set():
            now = time.monotonic()
            if now >= next_topology:
                self._send_topology_discovery()
                next_topology = now + self.topology_interval_s
            if now >= next_autoconfig:
                self._send_autoconfig_search()
                next_autoconfig = now + self.autoconfig_interval_s
            if self._onboarded and now >= next_metrics:
                self._send_ap_metrics_unsolicited()
                next_metrics = now + self.metrics_interval_s
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
        elif mtype == MessageType.LINK_METRIC_QUERY.value:
            self._reply_link_metric_response(src, cmdu)
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
        elif mtype == MessageType.EM_MULTI_AP_POLICY_CONFIG_REQUEST.value:
            # Spec requires a 1905 ACK acknowledging policy intake.
            self._send_ack(src, cmdu.header.message_id)
        elif mtype == MessageType.EM_CHANNEL_PREFERENCE_QUERY.value:
            self._reply_channel_preference_report(src, cmdu)
        elif mtype == MessageType.EM_CHANNEL_SELECTION_REQUEST.value:
            self._reply_channel_selection(src, cmdu)
        elif mtype == MessageType.EM_HIGHER_LAYER_DATA.value:
            # We don't terminate higher-layer protocols (DPP, key
            # rotation, etc.) — just ACK so the controller stops retrying.
            self._send_ack(src, cmdu.header.message_id)
        elif mtype == MessageType.EM_BACKHAUL_STA_CAPABILITY_QUERY.value:
            self._reply_backhaul_sta_capability_report(src, cmdu)

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
                # 802.11n/HT cap byte: 2x2 SS, SGI-20+40, HT-40. Bits per
                # Multi-AP v1.0 Table 17-6.
                ApHtCapabilities(radio_id=self.radio_id, flags=0x5E),
                # 802.11ax/HE: minimal MCS map (2x2 1024-QAM = 0xFFFA repeated
                # for 80/160/80+80). Flags advertise 2x2 SS, no 160 MHz,
                # SU/MU beamformer, UL OFDMA, DL OFDMA.
                ApHeCapabilities(
                    radio_id=self.radio_id,
                    supported_he_mcs=b"\xfa\xff",
                    flags=0x40F8,
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

    def _ap_metrics_tlvs(self) -> list[object]:
        """Build the metric TLV list common to solicited and unsolicited reports.

        Multi-AP v2.0 §17.1.14: at minimum one ``ApMetrics`` per BSS.
        We also include ``RadioMetrics`` (R2 §17.2.60) because most
        controllers reject reports that lack per-radio utilization.
        """
        return [
            ApMetrics(
                bssid=self.bssid,
                channel_utilization=20,
                num_associated_stas=0,
                esp_info=b"\x80\x00\x10\x20",
            ),
            RadioMetrics(
                radio_id=self.radio_id,
                # All values dBm/percentage. Noise floor -75 dBm encoded
                # as 220 - 75 = 145 + 35? Actually per spec, noise is u8
                # in dBm units offset by 220 (so 200 == -20 dBm worst).
                noise=180,
                transmit_utilization=15,
                receive_utilization=10,
                receive_other_utilization=5,
            ),
        ]

    def _reply_ap_metrics_response(self, dst: bytes, query: CMDU) -> None:
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.EM_AP_METRICS_RESPONSE.value,
            message_id=query.header.message_id,
            typed_tlvs=self._ap_metrics_tlvs(),
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    def _send_ap_metrics_unsolicited(self) -> None:
        """Push an unsolicited EM_AP_METRICS_RESPONSE to the multicast AL.

        Multi-AP v2.0 §17.1.13 lets agents report metrics on their own
        cadence (``MetricCollectionInterval`` TLV in the capability
        report) so the controller can populate dashboards even without
        polling. The emulator does this once it's onboarded so the
        controller's per-agent metrics view stays fresh.
        """
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.EM_AP_METRICS_RESPONSE.value,
            message_id=self._ctx.next_mid(),
            typed_tlvs=self._ap_metrics_tlvs(),
        )
        try:
            send_frame(self._ctx, cmdu_bytes)
        except Exception as exc:  # noqa: BLE001
            logger.warning("unsolicited AP metrics send failed: %s", exc)

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
        # A controller may stack multiple WSC TLVs in one AP-Autoconfig WSC
        # CMDU — one M2 per provisioned BSS.
        wsc_payloads = [tlv.payload for tlv in cmdu.tlvs if tlv.tlv_type == WscFrame.TLV_TYPE]
        if not wsc_payloads:
            return

        any_success = False
        for wsc_payload in wsc_payloads:
            if self._process_m2(session, wsc_payload):
                any_success = True

        if any_success:
            self._onboarded = True

    def _process_m2(self, session: WscEnrolleeSession, wsc_payload: bytes) -> bool:
        try:
            attrs = dict(parse_attributes(wsc_payload))
        except ValueError as exc:
            logger.warning("WSC attributes malformed: %s", exc)
            return False

        message_type = attrs.get(ATTR_MESSAGE_TYPE)
        if not message_type or message_type[0] != WSC_MSG_M2:
            logger.debug("WSC frame is not M2 (type=%r) — ignoring", message_type)
            return False

        r_pub = attrs.get(ATTR_PUBLIC_KEY)
        r_nonce = attrs.get(ATTR_REGISTRAR_NONCE)
        enc = attrs.get(ATTR_ENCRYPTED_SETTINGS)
        if not (r_pub and r_nonce and enc):
            logger.warning("WSC M2 missing required attribute(s)")
            return False

        keys = derive_keys(session, r_pub, r_nonce)
        if not verify_authenticator(keys, session.m1_bytes, wsc_payload):
            logger.warning("WSC M2 Authenticator mismatch — dropping")
            return False

        try:
            inner = decrypt_encrypted_settings(keys, enc)
        except ValueError as exc:
            logger.warning("WSC M2 Encrypted Settings rejected: %s", exc)
            return False

        new_creds = parse_credentials(inner)
        if not new_creds:
            # Surface the inner attribute layout so the user can see what
            # the controller actually sent (and we can fix the parser).
            seen = sorted({aid for aid, _ in parse_attributes(inner)})
            logger.warning(
                "WSC M2 contained no BSS credentials — inner attrs: %s",
                ", ".join(f"0x{a:04x}" for a in seen),
            )
            return False

        self._bss_credentials.extend(new_creds)
        for cred in new_creds:
            logger.info(
                "WSC M2 BSS configured: ssid=%r auth=0x%04x encr=0x%04x",
                cred.ssid.decode("utf-8", "replace"),
                cred.auth_type,
                cred.encr_type,
            )
        return True

    # ---- Post-onboarding query/response handlers ---------------------------

    def _send_ack(self, dst: bytes, mid: int) -> None:
        """Emit a Multi-AP 1905 ACK CMDU (no TLVs) for ``mid``."""
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.EM_ACK.value,
            message_id=mid,
            typed_tlvs=[],
        )
        try:
            send_frame(self._ctx, cmdu_bytes, dst=dst)
        except Exception as exc:  # noqa: BLE001
            logger.warning("1905 ACK send failed: %s", exc)

    def _reply_link_metric_response(self, dst: bytes, query: CMDU) -> None:
        """Respond to LINK_METRIC_QUERY.

        IEEE 1905.1 §6.3.6: the responder includes one Transmitter and
        one Receiver link metric TLV per neighbor it has. We have no
        peers from the agent's own discovery table, so emit a single
        ``LinkMetricResultCode`` with the "invalid neighbor" code — the
        spec-sanctioned way to say "I have no link metrics to report."
        """
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.LINK_METRIC_RESPONSE.value,
            message_id=query.header.message_id,
            typed_tlvs=[LinkMetricResultCode(result_code=0x00)],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    def _reply_backhaul_sta_capability_report(self, dst: bytes, query: CMDU) -> None:
        """Respond to BACKHAUL_STA_CAPABILITY_QUERY (Multi-AP v2.0 §17.1.32).

        The emulator advertises no backhaul STA — flags=0x00 and no
        backhaul STA MAC. Real agents would set bit 7 and append their
        backhaul-STA MAC.
        """
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.EM_BACKHAUL_STA_CAPABILITY_REPORT.value,
            message_id=query.header.message_id,
            typed_tlvs=[
                BackhaulStaRadioCapabilities(
                    radio_id=self.radio_id,
                    flags=0x00,
                    backhaul_sta_mac=None,
                ),
            ],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    def _reply_channel_preference_report(self, dst: bytes, query: CMDU) -> None:
        """Respond to CHANNEL_PREFERENCE_QUERY with an "all preferred" report.

        Multi-AP v1.0 §17.1.10: at minimum a per-radio Channel Preference
        TLV is required. An empty operating-class list means "no channel
        is non-operable for me", which lets the controller pick any
        spec-default channel.
        """
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.EM_CHANNEL_PREFERENCE_REPORT.value,
            message_id=query.header.message_id,
            typed_tlvs=[
                ChannelPreference(
                    radio_id=self.radio_id,
                    operating_classes=[
                        # Op class 81 (2.4 GHz 20 MHz, ch 1-13). Empty
                        # channel list = "all channels in this op class
                        # carry the same preference".
                        ChannelPreferenceOpClass(op_class=81, channels=[], preference=0xF0),
                    ],
                ),
            ],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    def _reply_channel_selection(self, dst: bytes, query: CMDU) -> None:
        """Respond to CHANNEL_SELECTION_REQUEST.

        Two CMDUs go back per Multi-AP v1.0 §17.1.11+§17.1.12:

        1. CHANNEL_SELECTION_RESPONSE acknowledging the request (one
           ChannelSelectionResponse TLV per radio, response_code=0).
        2. OPERATING_CHANNEL_REPORT confirming the channel actually in use.
        """
        assert self._ctx is not None
        # 1) selection response
        resp_bytes = build_cmdu(
            message_type=MessageType.EM_CHANNEL_SELECTION_RESPONSE.value,
            message_id=query.header.message_id,
            typed_tlvs=[
                ChannelSelectionResponse(radio_id=self.radio_id, response_code=0x00),
            ],
        )
        send_frame(self._ctx, resp_bytes, dst=dst)

        # 2) operating channel report (separate MID — it's an unsolicited
        # post-selection notification, not the request's reply pair).
        report_bytes = build_cmdu(
            message_type=MessageType.EM_OPERATING_CHANNEL_REPORT.value,
            message_id=self._ctx.next_mid(),
            typed_tlvs=[
                OperatingChannelReport(
                    radio_id=self.radio_id,
                    operating_classes=[
                        OperatingChannelOpClass(op_class=81, channel=6),
                    ],
                    current_transmit_power_dbm=20,
                ),
            ],
        )
        send_frame(self._ctx, report_bytes, dst=dst)
