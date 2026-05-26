# SPDX-License-Identifier: GPL-2.0-or-later
"""Multi-AP **agent** emulator with full R3 onboarding.

The emulator implements the agent-side of every CMDU exchange a
Multi-AP R3 controller drives during onboarding and routine operation,
so it can pass strict R3-compliant controller validators without
spamming retries.

Periodic emissions (driven by ``_heartbeat_loop``)

- Topology Discovery — every ``topology_interval_s`` (default 5 s).
- AP-Autoconfig Search — every ``autoconfig_interval_s`` (default
  30 s). The reply is an AP-Autoconfig Response (handled below); on
  receipt we initiate the WSC enrollee handshake.
- AP Metrics Response — every ``metrics_interval_s`` (default 30 s),
  *only after* WSC onboarding has produced at least one BSS credential.

Onboarding (WSC M1 / M2 enrollee, see ``ieee1905.emulator.wsc``)

- AP-Autoconfig Response  -> emit AP-Autoconfig WSC carrying M1.
- AP-Autoconfig WSC (M2)  -> derive WSC keys, verify outer
  Authenticator + inner Key Wrap Authenticator, decrypt Encrypted
  Settings, extract BssCredential(s), mark ``_onboarded`` true.
- AP-Autoconfig Renew     -> drop the cached WSC state, re-search.

Inbound CMDU handlers

- Topology Query                 -> Topology Response (DeviceInfo +
  SupportedService + AP Operational BSS + Multi-AP Profile).
- Link Metric Query              -> Link Metric Response (single
  LinkMetricResultCode "no neighbors").
- AP Capability Query            -> AP Capability Report with ApCap,
  ApRadioBasicCaps, ApHt/HeCaps, ChannelScanCaps, CacCaps,
  Profile2ApCap, MetricCollectionInterval.
- AP Metrics Query               -> AP Metrics Response (ApMetrics +
  RadioMetrics).
- Channel Preference Query       -> Channel Preference Report.
- Channel Selection Request      -> Channel Selection Response + a
  follow-up Operating Channel Report.
- Backhaul STA Capability Query  -> Backhaul STA Capability Report.
- Client Capability Query        -> Client Capability Report
  (result_code=1: no such client).
- Bare 1905 ACK is the reply for: HIGHER_LAYER_DATA,
  MULTI_AP_POLICY_CONFIG_REQUEST, CLIENT_STEERING_REQUEST,
  CLIENT_ASSOCIATION_CONTROL_REQUEST, CHANNEL_SCAN_REQUEST,
  CAC_REQUEST, CAC_TERMINATION, BACKHAUL_STEERING_REQUEST.

Intentional gaps: no multi-radio, no associated clients, no DPP,
no encrypted 1905 transport. Anything outside the list above is
silently dropped.
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
    CacStatusReport,
    ChannelPreference,
    ChannelPreferenceOpClass,
    ChannelScanCapabilities,
    ChannelScanCapabilityOpClass,
    ChannelScanCapabilityRadio,
    ChannelSelectionResponse,
    ClientCapabilityReport,
    DeviceInformation,
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
    ReceiverLinkEntry,
    ReceiverLinkMetric,
    SearchedRole,
    SearchedService,
    SupportedService,
    TransmitterLinkEntry,
    TransmitterLinkMetric,
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
class RadioConfig:
    """One physical radio's per-radio identity and 2.4/5/60 GHz hint.

    The primary radio is constructed implicitly from the FakeAgent's
    ``radio_id`` / ``bssid`` / ``freq_band`` / ``ssid`` fields, so this
    dataclass is only used when the user explicitly adds extra radios via
    ``FakeAgent(extra_radios=[...])``.
    """

    radio_id: bytes
    bssid: bytes
    freq_band: int = 0x01  # 0=2.4 GHz, 1=5 GHz, 2=60 GHz
    op_class: int = 115  # 5 GHz 20 MHz; 2.4 GHz primary uses op_class 81
    ssid: bytes | None = None  # None -> inherit agent ssid (default)

# CMDU types where the spec-mandated reply is just a 1905 ACK with no TLVs.
# Most are "no-op for a fronthaul-only emulator with no clients" cases.
_ACK_ONLY_REQUESTS: frozenset[int] = frozenset({
    MessageType.EM_HIGHER_LAYER_DATA.value,
    MessageType.EM_MULTI_AP_POLICY_CONFIG_REQUEST.value,
    MessageType.EM_CLIENT_STEERING_REQUEST.value,
    MessageType.EM_CLIENT_ASSOCIATION_CONTROL_REQUEST.value,
    MessageType.EM_CHANNEL_SCAN_REQUEST.value,
    MessageType.EM_CAC_REQUEST.value,
    MessageType.EM_CAC_TERMINATION.value,
    MessageType.EM_BACKHAUL_STEERING_REQUEST.value,
})


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
    #: Extra radios beyond the implicit primary one. The agent reports
    #: each radio's basic capability + operating BSS, scan / CAC
    #: capability, and emits per-BSS AP Metrics for them.
    extra_radios: list[RadioConfig] = field(default_factory=list)

    _ctx: EmulatorContext | None = None
    _sniff_thread: threading.Thread | None = None
    _heartbeat_thread: threading.Thread | None = None
    _wsc_session: WscEnrolleeSession | None = None
    _bss_credentials: list[BssCredential] = field(default_factory=list)
    _onboarded: bool = False

    def _radios(self) -> list[RadioConfig]:
        """Return every radio (primary + extras) as a uniform list."""
        primary = RadioConfig(
            radio_id=self.radio_id,
            bssid=self.bssid,
            freq_band=self.freq_band,
            op_class=81 if self.freq_band == 0x00 else 115,
            ssid=self.ssid,
        )
        return [primary, *self.extra_radios]

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
            # Autoconfig Search hunts for a Multi-AP Controller. Once WSC
            # onboarding has produced a BSS credential, we already have
            # one — further Search emissions cause the controller to
            # treat us as a flapping agent and re-run M1/M2 forever.
            # An Autoconfig Renew (handled in _on_cmdu) is the only
            # spec-sanctioned way to restart this side of the handshake.
            if not self._onboarded and now >= next_autoconfig:
                self._send_autoconfig_search()
                next_autoconfig = now + self.autoconfig_interval_s
            if self._onboarded and now >= next_metrics:
                self._send_ap_metrics_unsolicited()
                next_metrics = now + self.metrics_interval_s
            self._ctx.stop_event.wait(timeout=0.5)

    def _send_topology_discovery(self) -> None:
        assert self._ctx is not None
        # IEEE 1905.1 §6.3.1: Topology Discovery carries AL MAC + the MAC
        # of the interface the frame is *leaving on* (must match the
        # Ethernet header source MAC). We have a single interface and
        # send_frame() uses al_mac as the Ethernet source, so the
        # interface-MAC TLV must echo the AL MAC — otherwise a strict
        # controller treats it as a *separate* 1905 neighbor and starts
        # building a phantom ALE entry for it.
        cmdu_bytes = build_cmdu(
            message_type=MessageType.TOPOLOGY_DISCOVERY.value,
            message_id=self._ctx.next_mid(),
            typed_tlvs=[
                AlMacAddress(al_mac=self.al_mac),
                MacAddress(mac=self.al_mac),
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
        mid = cmdu.header.message_id
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
        elif mtype == MessageType.EM_CHANNEL_PREFERENCE_QUERY.value:
            self._reply_channel_preference_report(src, cmdu)
        elif mtype == MessageType.EM_CHANNEL_SELECTION_REQUEST.value:
            self._reply_channel_selection(src, cmdu)
        elif mtype == MessageType.EM_BACKHAUL_STA_CAPABILITY_QUERY.value:
            self._reply_backhaul_sta_capability_report(src, cmdu)
        elif mtype == MessageType.EM_CLIENT_CAPABILITY_QUERY.value:
            self._reply_client_capability_report(src, cmdu)
        elif mtype in _ACK_ONLY_REQUESTS:
            # The spec demands a 1905 ACK but no body — we have nothing
            # to do for higher-layer data, steering, scans, or CAC since
            # the emulator owns no real radio and no clients.
            self._send_ack(src, mid)

    def _operational_bsses_for(self, radio: RadioConfig) -> list[OperationalBss]:
        """Return the BSS list to advertise for one specific radio.

        Post-onboarding the primary radio reflects the BSS(es) the
        controller provisioned in M2 (SSID + BSSID from the WPS
        Credential). Extra radios always report the BSSID/SSID they were
        configured with — the registrar emulator currently provisions
        only the radio matching the M1's MAC Address attribute, which is
        the primary radio.
        """
        if radio.radio_id == self.radio_id and self._bss_credentials:
            return [
                OperationalBss(
                    bssid=(cred.mac_address if cred.mac_address else radio.bssid),
                    ssid=(cred.ssid if cred.ssid else (radio.ssid or self.ssid)),
                )
                for cred in self._bss_credentials
            ]
        return [OperationalBss(bssid=radio.bssid, ssid=(radio.ssid or self.ssid))]

    def _all_operational_bsses(self) -> list[OperationalBssRadio]:
        """Top-level helper: ApOperationalBss radio list for every radio."""
        return [
            OperationalBssRadio(
                radio_id=radio.radio_id, bsses=self._operational_bsses_for(radio)
            )
            for radio in self._radios()
        ]

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
                    # LocalInterface.mac is the *physical* interface MAC of
                    # the entry, not the radio identifier. The emulator
                    # has one interface and its Ethernet source MAC is
                    # the AL MAC, so this must echo al_mac — using
                    # radio_id here makes a strict controller register
                    # the radio as a phantom 1905 ALE.
                    interfaces=[LocalInterface(mac=self.al_mac, media_type=0x0001)],
                ),
                SupportedService(services=[0x01]),  # Multi-AP Agent
                ApOperationalBss(radios=self._all_operational_bsses()),
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
        radios = self._radios()
        tlvs: list[object] = [ApCapability(flags=0xC0)]
        for radio in radios:
            tlvs.append(
                ApRadioBasicCapabilities(
                    radio_id=radio.radio_id,
                    max_bsses_supported=4,
                    operating_classes=[
                        OperatingClassCapability(
                            op_class=radio.op_class,
                            max_tx_eirp_dbm=23,
                            non_operable_channels=[],
                        ),
                    ],
                )
            )
            # 802.11n/HT cap byte: 2x2 SS, SGI-20+40, HT-40. Bits per
            # Multi-AP v1.0 Table 17-6.
            tlvs.append(ApHtCapabilities(radio_id=radio.radio_id, flags=0x5E))
            # 802.11ax/HE: 2x2 MCS, SU/MU beamformer, UL+DL OFDMA.
            tlvs.append(
                ApHeCapabilities(
                    radio_id=radio.radio_id,
                    supported_he_mcs=b"\xfa\xff",
                    flags=0x40F8,
                )
            )
        tlvs.extend([
            ChannelScanCapabilities(
                radios=[
                    ChannelScanCapabilityRadio(
                        radio_id=radio.radio_id,
                        flags=0x00,
                        min_scan_interval_s=0,
                        operating_classes=[
                            # Empty channel list = "all channels in this op class".
                            ChannelScanCapabilityOpClass(op_class=radio.op_class, channels=[]),
                        ],
                    )
                    for radio in radios
                ]
            ),
            CacCapabilities(
                country_code=b"US",
                radios=[
                    # Empty cac_types list = "this radio doesn't support CAC".
                    CacRadioCapability(radio_id=radio.radio_id, cac_types=[])
                    for radio in radios
                ],
            ),
            Profile2ApCapability(
                max_prioritization_rules=4,
                reserved=0,
                capabilities=0xC0,  # BSS-config-param + byte-count units
                max_total_number_of_vids=16,
            ),
            MetricCollectionInterval(interval_ms=5000),
        ])
        cmdu_bytes = build_cmdu(
            message_type=MessageType.EM_AP_CAPABILITY_REPORT.value,
            message_id=query.header.message_id,
            typed_tlvs=tlvs,
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    def _ap_metrics_tlvs(self) -> list[object]:
        """Build the metric TLV list common to solicited and unsolicited reports.

        Multi-AP v2.0 §17.1.14: at minimum one ``ApMetrics`` per BSS.
        Post-onboarding the report must use the BSSID(s) the controller
        provisioned in M2; otherwise the controller's per-radio BSS
        accounting cannot match the metric to a BSS. RadioMetrics
        (R2 §17.2.60) is included once per radio since strict
        controllers reject reports that lack per-radio utilization.
        """
        tlvs: list[object] = []
        for radio in self._radios():
            for bss in self._operational_bsses_for(radio):
                tlvs.append(
                    ApMetrics(
                        bssid=bss.bssid,
                        channel_utilization=20,
                        num_associated_stas=0,
                        esp_info=b"\x80\x00\x10\x20",
                    )
                )
            tlvs.append(
                RadioMetrics(
                    radio_id=radio.radio_id,
                    noise=180,  # spec: u8, dBm offset by 220 (so 200 == -20 dBm worst)
                    transmit_utilization=15,
                    receive_utilization=10,
                    receive_other_utilization=5,
                )
            )
        return tlvs

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
        # WPS v2.0 §7.4 "Enrollee MAC Address" accepts BSSID, radio MAC,
        # or a unique device identifier. Strict Multi-AP controllers
        # treat the value they read here as the
        # enrollee's ALE MAC and create a fresh APDevice entry for it
        # if it differs from the AL MAC they already know from
        # Topology Discovery. Using the AL MAC here keeps the
        # controller's data model coherent — no phantom ALE entry
        # populated with our M1 Manufacturer/AuthFlags fields.
        session = WscEnrolleeSession(enrollee_mac=self.al_mac, rf_band=rf_band)
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

        logger.debug(
            "WSC M2 decrypted inner (%d bytes): %s",
            len(inner),
            inner.hex(),
        )

        new_creds = parse_credentials(inner)
        if not new_creds:
            # Surface the inner attribute layout so the user can see what
            # the controller actually sent (and we can fix the parser).
            seen = [(aid, len(val)) for aid, val in parse_attributes(inner)]
            logger.warning(
                "WSC M2 contained no BSS credentials — inner attrs: %s",
                ", ".join(f"0x{aid:04x}(len={ln})" for aid, ln in seen),
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
        one Receiver link metric TLV per neighbor it has. The Multi-AP
        controller is our only 1905 neighbor — its AL MAC is the source
        of the query — so the response covers exactly that link with
        synthetic-but-plausible Gigabit-Ethernet metrics. Returning only
        a "no neighbors" result code leaves strict R3-compliant
        controllers unable to associate per-link telemetry with our
        agent's BSS.
        """
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.LINK_METRIC_RESPONSE.value,
            message_id=query.header.message_id,
            typed_tlvs=[
                TransmitterLinkMetric(
                    responder_al_mac=self.al_mac,
                    neighbor_al_mac=dst,
                    links=[
                        TransmitterLinkEntry(
                            local_interface_mac=self.al_mac,
                            neighbor_interface_mac=dst,
                            intf_type=0x0001,  # 1000BASE-T
                            has_bridge=False,
                            packet_errors=0,
                            transmitted_packets=100,
                            mac_throughput_mbps=1000,
                            link_availability_pct_x100=10000,  # 100.00%
                            phy_rate_mbps=1000,
                        ),
                    ],
                ),
                ReceiverLinkMetric(
                    responder_al_mac=self.al_mac,
                    neighbor_al_mac=dst,
                    links=[
                        ReceiverLinkEntry(
                            local_interface_mac=self.al_mac,
                            neighbor_interface_mac=dst,
                            intf_type=0x0001,
                            packet_errors=0,
                            packets_received=100,
                            rssi_db=0,  # not wireless
                        ),
                    ],
                ),
            ],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    def _reply_client_capability_report(self, dst: bytes, query: CMDU) -> None:
        """Respond to CLIENT_CAPABILITY_QUERY (Multi-AP v1.0 §17.1.20).

        The emulator owns no associated clients, so the response is a
        single Client Capability Report TLV with result_code=1 (failure)
        — the spec's way to say "no such client".
        """
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.EM_CLIENT_CAPABILITY_REPORT.value,
            message_id=query.header.message_id,
            typed_tlvs=[ClientCapabilityReport(result_code=0x01)],
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
                    radio_id=radio.radio_id, flags=0x00, backhaul_sta_mac=None
                )
                for radio in self._radios()
            ],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    def _reply_channel_preference_report(self, dst: bytes, query: CMDU) -> None:
        """Respond to CHANNEL_PREFERENCE_QUERY with an "all preferred" report.

        Multi-AP v1.0 §17.1.10: at minimum a per-radio Channel Preference
        TLV is required. An empty operating-class list means "no channel
        is non-operable for me", which lets the controller pick any
        spec-default channel. R2 §17.2.41 adds CAC Status Report TLV as
        mandatory — strict controllers reject the report without it. An
        empty CacStatusReport (all three counts zero) is the spec-
        sanctioned way to say "no DFS activity" for a non-DFS radio.
        """
        assert self._ctx is not None
        tlvs: list[object] = [
            ChannelPreference(
                radio_id=radio.radio_id,
                operating_classes=[
                    # Empty channel list = "all channels in this op
                    # class carry the same preference (0xF0 = top)".
                    ChannelPreferenceOpClass(
                        op_class=radio.op_class, channels=[], preference=0xF0
                    ),
                ],
            )
            for radio in self._radios()
        ]
        tlvs.append(CacStatusReport())  # empty: no DFS activity
        cmdu_bytes = build_cmdu(
            message_type=MessageType.EM_CHANNEL_PREFERENCE_REPORT.value,
            message_id=query.header.message_id,
            typed_tlvs=tlvs,
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
        radios = self._radios()
        # 1) selection response — accept on every radio.
        resp_bytes = build_cmdu(
            message_type=MessageType.EM_CHANNEL_SELECTION_RESPONSE.value,
            message_id=query.header.message_id,
            typed_tlvs=[
                ChannelSelectionResponse(radio_id=radio.radio_id, response_code=0x00)
                for radio in radios
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
                    radio_id=radio.radio_id,
                    operating_classes=[
                        OperatingChannelOpClass(
                            op_class=radio.op_class,
                            channel=6 if radio.freq_band == 0x00 else 36,
                        ),
                    ],
                    current_transmit_power_dbm=20,
                )
                for radio in radios
            ],
        )
        send_frame(self._ctx, report_bytes, dst=dst)
