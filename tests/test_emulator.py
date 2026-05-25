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
from ieee1905.core.cmdu import CMDU_HEADER_SIZE
from ieee1905.core.tlv import encode_typed
from ieee1905.core.tlvs import AlMacAddress, AutoconfigFreqBand, SearchedRole
from ieee1905.emulator._common import EmulatorContext
from ieee1905.emulator.agent import FakeAgent
from ieee1905.emulator.controller import FakeController
from ieee1905.io.ethernet import EthernetFrame

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
