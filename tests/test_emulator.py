# SPDX-License-Identifier: GPL-2.0-or-later
"""DUT emulator smoke tests.

We don't exercise the real wire path (that needs a privileged socket
and a peer device). Instead we verify the response-building logic:
given a synthetic inbound CMDU, the emulator should produce a wire
frame of the expected shape, and we decode it back to confirm.
"""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from ieee1905.cli.main import cli
from ieee1905.core import CMDU, CMDUHeader, MessageType, RawTLV
from ieee1905.core.cmdu import CMDU_HEADER_SIZE, CMDUParseError
from ieee1905.core.tlv import encode_typed
from ieee1905.core.tlvs import AlMacAddress, AutoconfigFreqBand, SearchedRole, WscFrame
from ieee1905.emulator import wsc
from ieee1905.emulator._common import EmulatorContext
from ieee1905.emulator.agent import FakeAgent
from ieee1905.emulator.controller import FakeController
from ieee1905.io.ethernet import EthernetFrame
from tests.test_wsc import _build_m2

AGENT_MAC = b"\x02\xaa\xbb\xcc\xdd\x01"
CONTROLLER_MAC = b"\x02\x00\x00\x00\x00\x01"
RADIO_ID = b"\x02\xaa\xbb\xcc\xee\x01"
BSSID = b"\x02\xaa\xbb\xcc\xff\x01"


def _new_agent() -> FakeAgent:
    agent = FakeAgent(
        interface="lo0",
        al_mac=AGENT_MAC,
        radio_id=RADIO_ID,
        bssid=BSSID,
    )
    agent._ctx = EmulatorContext(
        interface="lo0",
        al_mac=AGENT_MAC,
        radio_id=RADIO_ID,
        bssid=BSSID,
        ssid=agent.ssid,
    )
    return agent


def _new_controller() -> FakeController:
    ctl = FakeController(
        interface="lo0",
        al_mac=CONTROLLER_MAC,
        radio_id=b"\x02\x00\x00\x00\x01\x01",
        bssid=b"\x02\x00\x00\x00\x02\x01",
    )
    ctl._ctx = EmulatorContext(
        interface="lo0",
        al_mac=CONTROLLER_MAC,
        radio_id=ctl.radio_id,
        bssid=ctl.bssid,
        ssid=ctl.ssid,
    )
    return ctl


def _extract_cmdu_from_send(sent_frame_bytes: bytes) -> CMDU:
    eth = EthernetFrame.parse(sent_frame_bytes)
    assert len(eth.payload) >= CMDU_HEADER_SIZE
    return CMDU.from_bytes(eth.payload)


def test_agent_reply_to_topology_query() -> None:
    agent = _new_agent()
    captured: list[bytes] = []

    def fake_send(ctx, cmdu_bytes, *, dst=None):  # type: ignore[no-untyped-def]
        frame = EthernetFrame(
            dst=dst or b"\x01\x80\xc2\x00\x00\x13",
            src=ctx.al_mac,
            ethertype=0x893A,
            payload=cmdu_bytes,
        ).to_bytes()
        captured.append(frame)

    with patch("ieee1905.emulator.agent.send_frame", side_effect=fake_send):
        # CMDU header: version=0, reserved=0, msg_type=0x0002 (Topology Query),
        # mid=0x0042, frag=0, flags=0x80 (last_fragment). Then end-of-message TLV.
        query = CMDU.from_bytes(
            bytes.fromhex("0000000200420080") + b"\x00\x00\x00"
        )
        agent._on_cmdu(CONTROLLER_MAC, query)

    assert len(captured) == 1
    cmdu = _extract_cmdu_from_send(captured[0])
    assert cmdu.header.message_type == MessageType.TOPOLOGY_RESPONSE.value
    # Multi-AP v1.0 §7.2.3 + v2.0 §17.2: Device Information + SupportedService
    # + AP Operational BSS + Multi-AP Profile (no standalone AL MAC TLV; the
    # AL MAC inside Device Information is the authoritative copy). Plus EoM = 5.
    assert len(cmdu.tlvs) == 5
    types = {t.tlv_type for t in cmdu.tlvs}
    assert {0x03, 0x80, 0x83, 0xB3}.issubset(types)
    # AL MAC TLV (0x01) is intentionally absent — controllers reject it.
    assert 0x01 not in types
    # EoM is last per spec.
    assert cmdu.tlvs[-1].tlv_type == 0x00


def test_agent_reply_to_ap_capability_query() -> None:
    agent = _new_agent()
    captured: list[bytes] = []

    def fake_send(ctx, cmdu_bytes, *, dst=None):  # type: ignore[no-untyped-def]
        frame = EthernetFrame(
            dst=dst or b"\x01\x80\xc2\x00\x00\x13",
            src=ctx.al_mac,
            ethertype=0x893A,
            payload=cmdu_bytes,
        ).to_bytes()
        captured.append(frame)

    with patch("ieee1905.emulator.agent.send_frame", side_effect=fake_send):
        query = CMDU.from_bytes(bytes.fromhex("0000800100ff0080") + b"\x00\x00\x00")
        agent._on_cmdu(CONTROLLER_MAC, query)

    assert len(captured) == 1
    cmdu = _extract_cmdu_from_send(captured[0])
    assert cmdu.header.message_type == MessageType.EM_AP_CAPABILITY_REPORT.value


def test_controller_reply_to_autoconfig_search() -> None:
    ctl = _new_controller()
    captured: list[bytes] = []

    def fake_send(ctx, cmdu_bytes, *, dst=None):  # type: ignore[no-untyped-def]
        frame = EthernetFrame(
            dst=dst or b"\x01\x80\xc2\x00\x00\x13",
            src=ctx.al_mac,
            ethertype=0x893A,
            payload=cmdu_bytes,
        ).to_bytes()
        captured.append(frame)

    with patch("ieee1905.emulator.controller.send_frame", side_effect=fake_send):
        # Build an autoconfig search with the AutoconfigFreqBand TLV requesting 5GHz.
        search = CMDU(
            header=CMDUHeader(
                message_type=MessageType.AP_AUTOCONFIGURATION_SEARCH.value, message_id=42
            ),
            tlvs=[
                encode_typed(AlMacAddress(al_mac=AGENT_MAC)),
                encode_typed(SearchedRole(role=0x00)),
                encode_typed(AutoconfigFreqBand(band=0x01)),
                RawTLV(tlv_type=0x00, payload=b""),
            ],
        )
        decoded = CMDU.from_bytes(search.to_bytes(append_end_of_message=False))
        ctl._on_cmdu(AGENT_MAC, decoded)

    assert len(captured) == 1
    cmdu = _extract_cmdu_from_send(captured[0])
    assert cmdu.header.message_type == MessageType.AP_AUTOCONFIGURATION_RESPONSE.value
    # Response carries SupportedRole (0x0F), SupportedFreqBand (0x10), SupportedService (0x80) + EoM.
    types = {t.tlv_type for t in cmdu.tlvs}
    assert {0x0F, 0x10, 0x80}.issubset(types)


def test_cli_emulator_group_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["emulator", "--help"])
    assert result.exit_code == 0, result.output
    assert "agent" in result.output
    assert "controller" in result.output


def _drive_agent_with(query_hex: str) -> list[CMDU]:
    """Helper: feed ``query_hex`` to the agent, return all CMDUs it sent back."""
    agent = _new_agent()
    captured: list[bytes] = []

    def fake_send(ctx, cmdu_bytes, *, dst=None):  # type: ignore[no-untyped-def]
        frame = EthernetFrame(
            dst=dst or b"\x01\x80\xc2\x00\x00\x13",
            src=ctx.al_mac,
            ethertype=0x893A,
            payload=cmdu_bytes,
        ).to_bytes()
        captured.append(frame)

    with patch("ieee1905.emulator.agent.send_frame", side_effect=fake_send):
        query = CMDU.from_bytes(bytes.fromhex(query_hex) + b"\x00\x00\x00")
        agent._on_cmdu(CONTROLLER_MAC, query)
    return [_extract_cmdu_from_send(f) for f in captured]


def test_agent_replies_link_metric_query_with_tx_rx_metrics() -> None:
    # type=0x0005 LINK_METRIC_QUERY, mid=0x0101, flags=0x80 (last, no relay)
    out = _drive_agent_with("0000000501010080")
    assert len(out) == 1
    assert out[0].header.message_type == MessageType.LINK_METRIC_RESPONSE.value
    types = {t.tlv_type for t in out[0].tlvs}
    # Strict 1905.1 §6.3.6: respond with TransmitterLinkMetric (0x09) and
    # ReceiverLinkMetric (0x0A) TLVs for our one 1905 neighbor (the
    # controller). A bare LinkMetricResultCode (0x0C) makes strict
    # derived controllers log "orphan BSS node".
    assert 0x09 in types
    assert 0x0A in types


def test_agent_acks_higher_layer_data() -> None:
    # type=0x8018 EM_HIGHER_LAYER_DATA
    out = _drive_agent_with("0000801801020080")
    assert len(out) == 1
    assert out[0].header.message_type == MessageType.EM_ACK.value
    assert out[0].header.message_id == 0x0102


def test_agent_acks_multi_ap_policy_config_request() -> None:
    # type=0x8003 EM_MULTI_AP_POLICY_CONFIG_REQUEST
    out = _drive_agent_with("0000800301030080")
    assert len(out) == 1
    assert out[0].header.message_type == MessageType.EM_ACK.value
    assert out[0].header.message_id == 0x0103


def test_agent_replies_backhaul_sta_capability_query() -> None:
    # type=0x8027 EM_BACKHAUL_STA_CAPABILITY_QUERY (canonical Multi-AP value)
    out = _drive_agent_with("0000802701040080")
    assert len(out) == 1
    assert out[0].header.message_type == MessageType.EM_BACKHAUL_STA_CAPABILITY_REPORT.value
    types = {t.tlv_type for t in out[0].tlvs}
    assert 0xCB in types  # BackhaulStaRadioCapabilities


def test_agent_replies_channel_preference_query() -> None:
    # type=0x8004 EM_CHANNEL_PREFERENCE_QUERY
    out = _drive_agent_with("0000800401050080")
    assert len(out) == 1
    assert out[0].header.message_type == MessageType.EM_CHANNEL_PREFERENCE_REPORT.value
    types = {t.tlv_type for t in out[0].tlvs}
    assert 0x8B in types  # ChannelPreference


def test_agent_replies_channel_selection_request_with_two_cmdus() -> None:
    # type=0x8006 EM_CHANNEL_SELECTION_REQUEST
    out = _drive_agent_with("0000800601060080")
    assert len(out) == 2
    assert out[0].header.message_type == MessageType.EM_CHANNEL_SELECTION_RESPONSE.value
    assert out[0].header.message_id == 0x0106  # paired with request MID
    assert out[1].header.message_type == MessageType.EM_OPERATING_CHANNEL_REPORT.value
    assert out[1].header.message_id != 0x0106  # unsolicited follow-up gets fresh MID


def test_ap_capability_report_includes_ht_and_he_caps() -> None:
    # type=0x8001 EM_AP_CAPABILITY_QUERY
    out = _drive_agent_with("0000800101070080")
    assert len(out) == 1
    types = {t.tlv_type for t in out[0].tlvs}
    assert 0x86 in types  # ApHtCapabilities
    assert 0x88 in types  # ApHeCapabilities


def test_ap_metrics_response_includes_radio_metrics() -> None:
    # type=0x800B EM_AP_METRICS_QUERY
    out = _drive_agent_with("0000800b01080080")
    assert len(out) == 1
    assert out[0].header.message_type == MessageType.EM_AP_METRICS_RESPONSE.value
    types = {t.tlv_type for t in out[0].tlvs}
    assert 0x94 in types  # ApMetrics
    assert 0xC6 in types  # RadioMetrics


def test_unsolicited_ap_metrics_carries_metrics_tlvs() -> None:
    agent = _new_agent()
    captured: list[bytes] = []

    def fake_send(ctx, cmdu_bytes, *, dst=None):  # type: ignore[no-untyped-def]
        frame = EthernetFrame(
            dst=dst or b"\x01\x80\xc2\x00\x00\x13",
            src=ctx.al_mac,
            ethertype=0x893A,
            payload=cmdu_bytes,
        ).to_bytes()
        captured.append(frame)

    with patch("ieee1905.emulator.agent.send_frame", side_effect=fake_send):
        agent._send_ap_metrics_unsolicited()

    assert len(captured) == 1
    cmdu = _extract_cmdu_from_send(captured[0])
    assert cmdu.header.message_type == MessageType.EM_AP_METRICS_RESPONSE.value
    types = {t.tlv_type for t in cmdu.tlvs}
    assert 0x94 in types and 0xC6 in types  # ApMetrics + RadioMetrics


def test_agent_replies_client_capability_query_with_failure() -> None:
    # type=0x8009 EM_CLIENT_CAPABILITY_QUERY — no clients => result_code=1.
    out = _drive_agent_with("0000800901090080")
    assert len(out) == 1
    assert out[0].header.message_type == MessageType.EM_CLIENT_CAPABILITY_REPORT.value
    types = {t.tlv_type for t in out[0].tlvs}
    assert 0x91 in types  # ClientCapabilityReport
    # result_code byte == 0x01 (failure / no such client)
    crep = next(t for t in out[0].tlvs if t.tlv_type == 0x91)
    assert crep.payload[0] == 0x01


def test_agent_acks_ack_only_request_types() -> None:
    """Every type in ``_ACK_ONLY_REQUESTS`` should produce exactly one 1905 ACK."""
    cases = [
        ("00008014010a0080", "EM_CLIENT_STEERING_REQUEST"),
        ("00008016010b0080", "EM_CLIENT_ASSOCIATION_CONTROL_REQUEST"),
        ("0000801b010c0080", "EM_CHANNEL_SCAN_REQUEST"),
        ("00008020010d0080", "EM_CAC_REQUEST"),
        ("00008021010e0080", "EM_CAC_TERMINATION"),
        ("00008019010f0080", "EM_BACKHAUL_STEERING_REQUEST"),
    ]
    for hex_input, label in cases:
        out = _drive_agent_with(hex_input)
        assert len(out) == 1, f"{label}: expected 1 reply, got {len(out)}"
        assert out[0].header.message_type == MessageType.EM_ACK.value, (
            f"{label}: expected EM_ACK, got 0x{out[0].header.message_type:04x}"
        )


def test_full_wsc_onboarding_end_to_end() -> None:
    """Drive an Agent through the full Search -> M1 -> M2 -> onboarded path.

    The test reuses the fake-registrar fixture from test_wsc.py to build
    a spec-conformant M2 in response to whatever M1 the agent emits,
    then feeds it back as an AP-Autoconfig WSC CMDU. Success criteria:
    the agent's ``_onboarded`` flag flips and ``_bss_credentials`` is
    populated with the SSID/network-key the simulated registrar sent.
    """
    agent = _new_agent()
    captured: list[tuple[bytes, bytes]] = []  # (dst, cmdu_bytes)

    def fake_send(ctx, cmdu_bytes, *, dst=None):  # type: ignore[no-untyped-def]
        captured.append((dst or b"\xff" * 6, cmdu_bytes))

    with patch("ieee1905.emulator.agent.send_frame", side_effect=fake_send):
        # 1) Trigger M1 by injecting an AP-Autoconfig Response.
        agent._on_autoconfig_response(
            CONTROLLER_MAC,
            CMDU.from_bytes(bytes.fromhex("0000000801000080") + b"\x00\x00\x00"),
        )
        assert agent._wsc_session is not None
        assert len(captured) == 1
        # The CMDU the agent just sent should be AP-Autoconfig WSC (M1).
        m1_cmdu = CMDU.from_bytes(captured[0][1])
        assert m1_cmdu.header.message_type == MessageType.AP_AUTOCONFIGURATION_WSC.value
        # 2) Build an M2 against the live session and feed it back.
        m2_bytes, _, _ = _build_m2(
            agent._wsc_session, ssid=b"home-mesh", network_key=b"strong-password"
        )
        m2_cmdu = CMDU(
            header=CMDUHeader(
                message_type=MessageType.AP_AUTOCONFIGURATION_WSC.value,
                message_id=0x4321,
            ),
            tlvs=[
                encode_typed(WscFrame(wsc_payload=m2_bytes)),
                RawTLV(tlv_type=0x00, payload=b""),
            ],
        )
        agent._on_wsc(CONTROLLER_MAC, m2_cmdu)

    assert agent._onboarded is True
    assert len(agent._bss_credentials) == 1
    cred = agent._bss_credentials[0]
    assert cred.ssid == b"home-mesh"
    assert cred.network_key == b"strong-password"


def test_controller_topology_discovery_carries_supported_service() -> None:
    """The controller's periodic Topology Discovery must advertise
    SupportedService = Multi-AP Controller (0x00) so neighbors learn its
    role on the first beacon. Also asserts the MacAddress TLV echoes
    AL MAC (the phantom-ALE fix mirrored on the controller side)."""
    ctl = _new_controller()
    captured: list[bytes] = []

    def fake_send(ctx, cmdu_bytes, *, dst=None):  # type: ignore[no-untyped-def]
        captured.append(cmdu_bytes)

    with patch("ieee1905.emulator.controller.send_frame", side_effect=fake_send):
        ctl._send_topology_discovery()

    assert len(captured) == 1
    cmdu = CMDU.from_bytes(captured[0])
    assert cmdu.header.message_type == MessageType.TOPOLOGY_DISCOVERY.value
    types = {t.tlv_type for t in cmdu.tlvs}
    assert {0x01, 0x02, 0x80}.issubset(types)  # AL MAC + MAC Address + SupportedService
    # Both MAC TLVs must reflect the AL MAC, not a separate radio MAC.
    al_mac = next(t for t in cmdu.tlvs if t.tlv_type == 0x01).payload
    iface_mac = next(t for t in cmdu.tlvs if t.tlv_type == 0x02).payload
    assert al_mac == CONTROLLER_MAC and iface_mac == CONTROLLER_MAC


def test_controller_emits_wsc_m2_in_response_to_m1() -> None:
    """When an agent's M1 arrives, the controller emits an
    AP-Autoconfig WSC CMDU whose WSC TLV decrypts to a BssCredential the
    enrollee can consume."""
    ctl = _new_controller()
    captured: list[tuple[bytes, bytes]] = []

    def fake_send(ctx, cmdu_bytes, *, dst=None):  # type: ignore[no-untyped-def]
        captured.append((dst or b"\xff" * 6, cmdu_bytes))

    # A live enrollee session gives us a valid M1 payload + the
    # symmetric state needed to decrypt the M2 the controller emits.
    enrollee = wsc.WscEnrolleeSession(enrollee_mac=AGENT_MAC)
    m1 = enrollee.build_m1()
    m1_cmdu = CMDU(
        header=CMDUHeader(
            message_type=MessageType.AP_AUTOCONFIGURATION_WSC.value,
            message_id=0xBEEF,
        ),
        tlvs=[
            RawTLV(tlv_type=0x85, payload=RADIO_ID + bytes([0, 0])),
            encode_typed(WscFrame(wsc_payload=m1)),
            RawTLV(tlv_type=0x00, payload=b""),
        ],
    )

    with patch("ieee1905.emulator.controller.send_frame", side_effect=fake_send):
        ctl._on_cmdu(AGENT_MAC, m1_cmdu)

    # Two TX frames expected: WSC M2 first, then the post-onboarding
    # AP Capability Query the controller fires automatically.
    assert len(captured) == 2
    dst0, m2_frame = captured[0]
    dst1, q_frame = captured[1]
    assert dst0 == AGENT_MAC and dst1 == AGENT_MAC
    cmdu = CMDU.from_bytes(m2_frame)
    assert cmdu.header.message_type == MessageType.AP_AUTOCONFIGURATION_WSC.value
    assert CMDU.from_bytes(q_frame).header.message_type == (
        MessageType.EM_AP_CAPABILITY_QUERY.value
    )
    wsc_tlvs = [t for t in cmdu.tlvs if t.tlv_type == 0x11]
    assert len(wsc_tlvs) == 1

    # Drive the enrollee's M2 path on the captured payload and confirm
    # we recover the controller-supplied BSS credential.
    attrs = dict(wsc.parse_attributes(wsc_tlvs[0].payload))
    keys = wsc.derive_keys(
        enrollee, attrs[wsc.ATTR_PUBLIC_KEY], attrs[wsc.ATTR_REGISTRAR_NONCE]
    )
    assert wsc.verify_authenticator(keys, enrollee.m1_bytes, wsc_tlvs[0].payload)
    inner = wsc.decrypt_encrypted_settings(keys, attrs[wsc.ATTR_ENCRYPTED_SETTINGS])
    creds = wsc.parse_credentials(inner)
    assert len(creds) == 1
    assert creds[0].ssid == ctl.ssid
    assert creds[0].network_key == ctl.network_key
    assert creds[0].mac_address == ctl.bssid


def test_controller_promotes_agent_to_onboarded_on_capability_report() -> None:
    """Receiving an AP Capability Report flips the agent's ``onboarded``
    flag and triggers a Multi-AP Policy Config push + Channel Preference
    Query — both required follow-ups in the Multi-AP v1.0 §17.1 flow."""
    ctl = _new_controller()
    captured: list[bytes] = []

    def fake_send(ctx, cmdu_bytes, *, dst=None):  # type: ignore[no-untyped-def]
        captured.append(cmdu_bytes)

    with patch("ieee1905.emulator.controller.send_frame", side_effect=fake_send):
        report = CMDU.from_bytes(bytes.fromhex("0000800201230080") + b"\x00\x00\x00")
        ctl._on_cmdu(AGENT_MAC, report)

    agent = ctl._agents[AGENT_MAC]
    assert agent.onboarded is True
    msg_types = [CMDU.from_bytes(b).header.message_type for b in captured]
    # The trio: ACK for the report itself + Policy Config + Channel Preference Query.
    assert MessageType.EM_ACK.value in msg_types
    assert MessageType.EM_MULTI_AP_POLICY_CONFIG_REQUEST.value in msg_types
    assert MessageType.EM_CHANNEL_PREFERENCE_QUERY.value in msg_types


def test_controller_channel_preference_report_triggers_selection_request() -> None:
    ctl = _new_controller()
    # Pretend we already discovered the agent and its radio.
    state = ctl._touch_agent(AGENT_MAC)
    state.radio_id = RADIO_ID
    captured: list[bytes] = []

    def fake_send(ctx, cmdu_bytes, *, dst=None):  # type: ignore[no-untyped-def]
        captured.append(cmdu_bytes)

    with patch("ieee1905.emulator.controller.send_frame", side_effect=fake_send):
        report = CMDU.from_bytes(bytes.fromhex("0000800501240080") + b"\x00\x00\x00")
        ctl._on_cmdu(AGENT_MAC, report)

    msg_types = [CMDU.from_bytes(b).header.message_type for b in captured]
    assert MessageType.EM_ACK.value in msg_types
    assert MessageType.EM_CHANNEL_SELECTION_REQUEST.value in msg_types


def test_controller_full_handshake_drives_agent_to_onboarded() -> None:
    """End-to-end in-process Search -> Response -> M1 -> M2 -> onboarded.

    Mocks ``send_frame`` on both sides and shuttles every captured CMDU
    back to the peer's ``_on_cmdu``. The agent reaches ``_onboarded=True``
    with a BssCredential that mirrors the controller's configured SSID
    and BSSID — proving the in-house registrar and enrollee speak the
    same WSC dialect."""
    agent = _new_agent()
    ctl = _new_controller()
    ctl.ssid = b"e2e-mesh"
    ctl.network_key = b"e2e-test-key"
    ctl.bssid = b"\x06\x06\x06\x06\x06\x06"

    def shuttle(target, src_mac):  # type: ignore[no-untyped-def]
        """Build a send_frame side-effect that hands frames to ``target``."""
        def _send(ctx, cmdu_bytes, *, dst=None):  # type: ignore[no-untyped-def]
            try:
                cmdu = CMDU.from_bytes(cmdu_bytes)
            except CMDUParseError:
                return
            target._on_cmdu(src_mac, cmdu)
        return _send

    with patch("ieee1905.emulator.agent.send_frame",
               side_effect=shuttle(ctl, AGENT_MAC)), \
         patch("ieee1905.emulator.controller.send_frame",
               side_effect=shuttle(agent, CONTROLLER_MAC)):
        # Kick off the dance with the agent's autoconfig Search emission.
        agent._send_autoconfig_search()

    assert agent._onboarded is True
    assert len(agent._bss_credentials) == 1
    cred = agent._bss_credentials[0]
    assert cred.ssid == b"e2e-mesh"
    assert cred.network_key == b"e2e-test-key"
    assert cred.mac_address == ctl.bssid


def test_heartbeat_emits_metrics_only_after_onboarding() -> None:
    """Periodic metrics emission must be gated by the WSC-onboarded flag.

    Pre-onboarding the controller has no BSS context for our agent and
    drops unsolicited metric reports — emitting before onboarding just
    spams the wire.
    """
    agent = _new_agent()
    assert agent._onboarded is False
    # Simulate post-onboarding state.
    agent._onboarded = True
    captured: list[bytes] = []

    def fake_send(ctx, cmdu_bytes, *, dst=None):  # type: ignore[no-untyped-def]
        captured.append(cmdu_bytes)

    with patch("ieee1905.emulator.agent.send_frame", side_effect=fake_send):
        agent._send_ap_metrics_unsolicited()
    assert len(captured) == 1
    assert CMDU.from_bytes(captured[0]).header.message_type == (
        MessageType.EM_AP_METRICS_RESPONSE.value
    )
