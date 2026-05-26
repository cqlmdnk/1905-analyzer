# SPDX-License-Identifier: GPL-2.0-or-later
"""Multi-AP **controller** emulator with full R3 onboarding.

The emulator implements the controller-side of every CMDU exchange a
Multi-AP R3 agent expects, mirroring the agent emulator phase-by-phase:

Periodic emissions (driven by ``_heartbeat_loop``)

- Topology Discovery — every ``topology_interval_s`` (default 5 s).
- Topology Query — every ``topology_query_interval_s`` (default 30 s)
  per onboarded agent.
- AP Metrics Query — every ``metrics_interval_s`` (default 30 s) per
  onboarded agent.
- Link Metric Query — every ``link_metric_interval_s`` (default 60 s)
  per onboarded agent.

Inbound CMDU handlers

- AP-Autoconfig Search   -> AP-Autoconfig Response (registrar role,
  mirroring the agent's requested band).
- AP-Autoconfig WSC (M1) -> build M2 with a BSS credential
  (SSID/AuthType/EncrType/NetworkKey/BSSID), DH-derive session keys,
  AES-128-CBC encrypt the Encrypted Settings, and emit M2 back.
- Topology Discovery     -> record the agent, schedule Topology Query.
- Topology Response      -> learn the agent's radio identifier.
- EM_AP_CAPABILITY_REPORT -> ACK; mark agent as ONBOARDED on first
  receipt (post-WSC) and push Multi-AP Policy Config.
- EM_CHANNEL_PREFERENCE_REPORT -> ACK + send Channel Selection Request.
- EM_AP_METRICS_RESPONSE -> ACK (telemetry consumed).
- Bare ACK is sent for: LINK_METRIC_RESPONSE, OPERATING_CHANNEL_REPORT,
  CLIENT_CAPABILITY_REPORT, BACKHAUL_STA_CAPABILITY_REPORT,
  STEERING_BTM_REPORT.

WSC role: the controller acts as registrar. One session per inbound M1.
Sessions are kept in ``_wsc_sessions`` only long enough to emit M2;
on Autoconfig Renew the entry is torn down so the next M1 starts fresh.

Intentional gaps: no multi-radio agents, no DPP onboarding, no 1905
encryption, no Channel Scan workflow. Anything outside the list above
is silently dropped.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field

from ieee1905.core import CMDU, MessageType
from ieee1905.core.tlvs import (
    AlMacAddress,
    ApMetricQuery,
    ApRadioIdentifier,
    AutoconfigFreqBand,
    ChannelPreference,
    ChannelPreferenceOpClass,
    Default8021QSettings,
    LinkMetricQuery,
    MacAddress,
    SsidVlanMapping,
    SupportedFreqBand,
    SupportedRole,
    SupportedService,
    TrafficSeparationPolicy,
    TransmitPowerLimit,
    WscFrame,
)
from ieee1905.emulator._common import (
    EmulatorContext,
    build_cmdu,
    run_sniff_loop,
    send_frame,
)
from ieee1905.emulator.wsc import (
    ATTR_RF_BANDS,
    BssCredential,
    WscRegistrarSession,
    build_m2,
    parse_attributes,
)

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AgentState:
    """What the controller knows about one onboarded agent."""

    al_mac: bytes
    radio_id: bytes | None = None
    rf_band: int = 0x01
    onboarded: bool = False
    first_seen: float = 0.0
    last_seen: float = 0.0
    next_topology_query: float = 0.0
    next_metrics_query: float = 0.0
    next_link_metric_query: float = 0.0


@dataclass(slots=True)
class FakeController:
    """A Multi-AP R3 controller emulator that talks on ``interface``."""

    interface: str
    al_mac: bytes
    radio_id: bytes
    bssid: bytes
    ssid: bytes = b"controller-mesh"
    network_key: bytes = b"controller-mesh-psk"
    auth_type: int = 0x0020  # WPA2-PSK
    encr_type: int = 0x0008  # AES
    topology_interval_s: float = 5.0
    topology_query_interval_s: float = 30.0
    metrics_interval_s: float = 30.0
    link_metric_interval_s: float = 60.0

    _ctx: EmulatorContext | None = None
    _sniff_thread: threading.Thread | None = None
    _heartbeat_thread: threading.Thread | None = None
    _agents: dict[bytes, AgentState] = field(default_factory=dict)
    _wsc_sessions: dict[bytes, WscRegistrarSession] = field(default_factory=dict)

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
        logger.info(
            "FakeController started on %s (AL=%s)", self.interface, self.al_mac.hex(":")
        )

    def stop(self) -> None:
        if self._ctx is not None:
            self._ctx.stop_event.set()
        for t in (self._sniff_thread, self._heartbeat_thread):
            if t is not None:
                t.join(timeout=2.0)
        if self._ctx is not None:
            self._ctx.close_tx_session()
        logger.info("FakeController stopped")

    # ---- periodic emissions -------------------------------------------------

    def _heartbeat_loop(self) -> None:
        assert self._ctx is not None
        next_discovery = time.monotonic()
        while not self._ctx.stop_event.is_set():
            now = time.monotonic()
            if now >= next_discovery:
                self._send_topology_discovery()
                next_discovery = now + self.topology_interval_s
            for agent in list(self._agents.values()):
                if not agent.onboarded:
                    continue
                if now >= agent.next_topology_query:
                    self._send_topology_query(agent.al_mac)
                    agent.next_topology_query = now + self.topology_query_interval_s
                if now >= agent.next_metrics_query:
                    self._send_ap_metrics_query(agent.al_mac)
                    agent.next_metrics_query = now + self.metrics_interval_s
                if now >= agent.next_link_metric_query:
                    self._send_link_metric_query(agent.al_mac)
                    agent.next_link_metric_query = now + self.link_metric_interval_s
            self._ctx.stop_event.wait(timeout=0.5)

    def _send_topology_discovery(self) -> None:
        assert self._ctx is not None
        # IEEE 1905.1 §6.3.1: Topology Discovery carries AL MAC + the MAC
        # of the interface the frame is leaving on (which is the AL MAC
        # for a single-interface emulator). SupportedService is a
        # Multi-AP R1+ extension telling peers we're a controller.
        cmdu_bytes = build_cmdu(
            message_type=MessageType.TOPOLOGY_DISCOVERY.value,
            message_id=self._ctx.next_mid(),
            typed_tlvs=[
                AlMacAddress(al_mac=self.al_mac),
                MacAddress(mac=self.al_mac),
                SupportedService(services=[0x00]),  # Multi-AP Controller
            ],
        )
        try:
            send_frame(self._ctx, cmdu_bytes)
        except Exception as exc:  # noqa: BLE001
            logger.warning("controller topology discovery send failed: %s", exc)

    # ---- inbound message handling ------------------------------------------

    def _sniff_loop(self) -> None:
        assert self._ctx is not None
        run_sniff_loop(self._ctx, self._on_cmdu)

    def _on_cmdu(self, src: bytes, cmdu: CMDU) -> None:
        mtype = cmdu.header.message_type
        self._touch_agent(src)
        if mtype == MessageType.AP_AUTOCONFIGURATION_SEARCH.value:
            self._reply_autoconfig_response(src, cmdu)
        elif mtype == MessageType.AP_AUTOCONFIGURATION_WSC.value:
            self._on_wsc_m1(src, cmdu)
        elif mtype == MessageType.TOPOLOGY_DISCOVERY.value:
            self._on_topology_discovery(src, cmdu)
        elif mtype == MessageType.TOPOLOGY_NOTIFICATION.value:
            # Notification means something changed; pull a fresh inventory.
            self._send_topology_query(src)
        elif mtype == MessageType.TOPOLOGY_RESPONSE.value:
            self._on_topology_response(src, cmdu)
        elif mtype == MessageType.EM_AP_CAPABILITY_REPORT.value:
            self._on_ap_capability_report(src, cmdu)
        elif mtype == MessageType.EM_CHANNEL_PREFERENCE_REPORT.value:
            self._on_channel_preference_report(src, cmdu)
        elif mtype == MessageType.EM_AP_METRICS_RESPONSE.value:
            # Acknowledge incoming telemetry so the agent's retry timer
            # resets.
            self._send_ack(src, cmdu.header.message_id)
        elif mtype in _ACK_ONLY_REPORTS:
            self._send_ack(src, cmdu.header.message_id)

    def _touch_agent(self, src: bytes) -> AgentState:
        """Return (and create on first sight) the bookkeeping entry for ``src``."""
        agent = self._agents.get(src)
        now = time.monotonic()
        if agent is None:
            agent = AgentState(al_mac=src, first_seen=now)
            self._agents[src] = agent
            logger.info("new agent observed: %s", src.hex(":"))
        agent.last_seen = now
        return agent

    def _reply_autoconfig_response(self, dst: bytes, query: CMDU) -> None:
        assert self._ctx is not None
        requested_band = 0x01
        for raw in query.tlvs:
            if raw.tlv_type == AutoconfigFreqBand.TLV_TYPE and raw.payload:
                requested_band = raw.payload[0]
                break
        agent = self._touch_agent(dst)
        agent.rf_band = requested_band

        cmdu_bytes = build_cmdu(
            message_type=MessageType.AP_AUTOCONFIGURATION_RESPONSE.value,
            message_id=query.header.message_id,
            typed_tlvs=[
                SupportedRole(role=0x00),  # Registrar
                SupportedFreqBand(band=requested_band),
                SupportedService(services=[0x00]),  # Multi-AP Controller
            ],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    def _on_wsc_m1(self, src: bytes, cmdu: CMDU) -> None:
        """Extract M1, derive session keys, and emit a matching M2."""
        assert self._ctx is not None
        m1_payload: bytes | None = None
        agent_radio_id: bytes | None = None
        for tlv in cmdu.tlvs:
            if tlv.tlv_type == WscFrame.TLV_TYPE and m1_payload is None:
                m1_payload = tlv.payload
            elif (
                tlv.tlv_type == 0x85
                and agent_radio_id is None
                and len(tlv.payload) >= 6
            ):
                # AP Radio Basic Capabilities: radio_id is the first 6 B.
                agent_radio_id = bytes(tlv.payload[:6])
        if m1_payload is None:
            logger.warning("WSC CMDU from %s has no WSC TLV", src.hex(":"))
            return

        try:
            session = WscRegistrarSession.from_m1(m1_payload)
        except ValueError as exc:
            logger.warning("WSC M1 from %s rejected: %s", src.hex(":"), exc)
            return

        attrs = dict(parse_attributes(m1_payload))
        rf_band_attr = attrs.get(ATTR_RF_BANDS)
        rf_band = rf_band_attr[0] if rf_band_attr else 0x01

        credential = BssCredential(
            ssid=self.ssid,
            auth_type=self.auth_type,
            encr_type=self.encr_type,
            network_key=self.network_key,
            mac_address=self.bssid,
        )
        m2_payload = build_m2(session, credential, rf_band=rf_band)

        agent = self._touch_agent(src)
        if agent_radio_id is not None:
            agent.radio_id = agent_radio_id
        self._wsc_sessions[src] = session

        # Multi-AP v2.0 §17.1.7: M2 envelope carries AP_RADIO_IDENTIFIER,
        # Default 802.1Q Settings, Traffic Separation Policy, and one WSC
        # TLV per provisioned BSS.
        radio_id_for_m2 = agent_radio_id if agent_radio_id is not None else session.enrollee_mac
        cmdu_bytes = build_cmdu(
            message_type=MessageType.AP_AUTOCONFIGURATION_WSC.value,
            message_id=self._ctx.next_mid(),
            typed_tlvs=[
                ApRadioIdentifier(radio_id=radio_id_for_m2),
                Default8021QSettings(primary_vlan_id=0, default_pcp=0x00),
                TrafficSeparationPolicy(
                    mappings=[SsidVlanMapping(ssid=self.ssid, vlan_id=0)]
                ),
                WscFrame(wsc_payload=m2_payload),
            ],
        )
        send_frame(self._ctx, cmdu_bytes, dst=src)
        logger.info("WSC M2 sent to %s", src.hex(":"))
        # Once the BSS is provisioned the controller drives the
        # post-onboarding tail itself — Multi-AP v1.0 §17.1 expects an
        # AP Capability Query as the first follow-up so the agent's
        # capability bundle (HT/VHT/HE caps, Profile-2, ChannelScan,
        # CAC, MetricCollectionInterval) hits the data model.
        self._send_ap_capability_query(src)

    def _on_topology_discovery(self, src: bytes, _cmdu: CMDU) -> None:
        # First sighting of a neighbor — pull its full topology so we
        # learn its AP Operational BSS list.
        agent = self._touch_agent(src)
        if agent.first_seen == agent.last_seen:
            self._send_topology_query(src)

    def _on_topology_response(self, src: bytes, cmdu: CMDU) -> None:
        # Pull radio_id from DeviceInformation if we don't know it yet.
        agent = self._touch_agent(src)
        if agent.radio_id is not None:
            return
        for tlv in cmdu.tlvs:
            if tlv.tlv_type == 0x03 and len(tlv.payload) >= 13:
                # DeviceInformation: AL MAC(6) + interface count(1) + first
                # entry MAC(6).
                agent.radio_id = bytes(tlv.payload[7:13])
                break

    def _on_ap_capability_report(self, src: bytes, cmdu: CMDU) -> None:
        agent = self._touch_agent(src)
        # ACK first; then promote agent to ONBOARDED if this is the
        # post-WSC capability report.
        self._send_ack(src, cmdu.header.message_id)
        if not agent.onboarded:
            agent.onboarded = True
            now = time.monotonic()
            agent.next_topology_query = now + self.topology_query_interval_s
            agent.next_metrics_query = now + self.metrics_interval_s
            agent.next_link_metric_query = now + self.link_metric_interval_s
            logger.info("agent %s ONBOARDED", src.hex(":"))
            # Push the policy bundle and ask for channel preferences.
            self._send_multi_ap_policy_config_request(src)
            self._send_channel_preference_query(src)

    def _on_channel_preference_report(self, src: bytes, cmdu: CMDU) -> None:
        self._send_ack(src, cmdu.header.message_id)
        # Trigger a channel selection round on the first reported radio.
        agent = self._agents.get(src)
        if agent is None or agent.radio_id is None:
            return
        self._send_channel_selection_request(src, agent.radio_id)

    # ---- outbound query / report emitters ----------------------------------

    def _send_topology_query(self, dst: bytes) -> None:
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.TOPOLOGY_QUERY.value,
            message_id=self._ctx.next_mid(),
            typed_tlvs=[],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    def _send_ap_capability_query(self, dst: bytes) -> None:
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.EM_AP_CAPABILITY_QUERY.value,
            message_id=self._ctx.next_mid(),
            typed_tlvs=[],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    def _send_multi_ap_policy_config_request(self, dst: bytes) -> None:
        """Push the minimal Multi-AP Policy Config to a freshly-onboarded agent.

        Multi-AP v1.0 §17.1.5: Steering Policy + Metric Reporting Policy
        are the two TLVs the controller always sends. We use empty
        per-radio lists ("no policy override") — the agent answers with
        a 1905 ACK and continues with its post-onboarding flow.
        """
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.EM_MULTI_AP_POLICY_CONFIG_REQUEST.value,
            message_id=self._ctx.next_mid(),
            typed_tlvs=[],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    def _send_channel_preference_query(self, dst: bytes) -> None:
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.EM_CHANNEL_PREFERENCE_QUERY.value,
            message_id=self._ctx.next_mid(),
            typed_tlvs=[],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    def _send_channel_selection_request(self, dst: bytes, radio_id: bytes) -> None:
        """Send a Channel Selection Request pinning op_class 81 / channel 6 / 20 dBm.

        Real controllers select based on the agent's Channel Preference
        Report; the emulator picks a stable 2.4 GHz default so the
        downstream Channel Selection Response and Operating Channel
        Report paths always fire.
        """
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.EM_CHANNEL_SELECTION_REQUEST.value,
            message_id=self._ctx.next_mid(),
            typed_tlvs=[
                ChannelPreference(
                    radio_id=radio_id,
                    operating_classes=[
                        ChannelPreferenceOpClass(op_class=81, channels=[6], preference=0xF0)
                    ],
                ),
                TransmitPowerLimit(radio_id=radio_id, transmit_power_eirp_dbm=20),
            ],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    def _send_ap_metrics_query(self, dst: bytes) -> None:
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.EM_AP_METRICS_QUERY.value,
            message_id=self._ctx.next_mid(),
            typed_tlvs=[ApMetricQuery(bssids=[self.bssid])],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    def _send_link_metric_query(self, dst: bytes) -> None:
        """IEEE 1905.1 §6.3.5: ask the agent for both TX and RX metrics for all neighbors."""
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.LINK_METRIC_QUERY.value,
            message_id=self._ctx.next_mid(),
            typed_tlvs=[
                LinkMetricQuery(neighbor_type=0x00, link_metrics=0x02),
            ],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    def _send_autoconfig_renew(self, dst: bytes) -> None:
        """Tear down the cached WSC state and trigger a fresh M1 from the agent."""
        assert self._ctx is not None
        self._wsc_sessions.pop(dst, None)
        agent = self._agents.get(dst)
        if agent is not None:
            agent.onboarded = False
        cmdu_bytes = build_cmdu(
            message_type=MessageType.AP_AUTOCONFIGURATION_RENEW.value,
            message_id=self._ctx.next_mid(),
            typed_tlvs=[
                AlMacAddress(al_mac=self.al_mac),
                SupportedRole(role=0x00),
                SupportedFreqBand(band=agent.rf_band if agent else 0x01),
            ],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    def _send_ack(self, dst: bytes, mid: int) -> None:
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.EM_ACK.value,
            message_id=mid,
            typed_tlvs=[],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)


# CMDU types whose only required reply is a bare 1905 ACK.
_ACK_ONLY_REPORTS: frozenset[int] = frozenset({
    MessageType.LINK_METRIC_RESPONSE.value,
    MessageType.EM_OPERATING_CHANNEL_REPORT.value,
    MessageType.EM_CLIENT_CAPABILITY_REPORT.value,
    MessageType.EM_BACKHAUL_STA_CAPABILITY_REPORT.value,
    MessageType.EM_CLIENT_STEERING_BTM_REPORT.value,
    MessageType.EM_CHANNEL_SELECTION_RESPONSE.value,
})
