# SPDX-License-Identifier: GPL-2.0-or-later
"""EasyMesh R1 TLV tests.

Covers per-TLV round-trip (typed → wire → typed) plus a regression
fixture lock (``easymesh_r1.pcap``).
"""

from __future__ import annotations

from pathlib import Path

from ieee1905.core import CMDU, RawTLV, TLVType
from ieee1905.core.tlv import decode_raw, encode_typed
from ieee1905.core.tlvs import ApCapability, ApHtCapabilities, SteeringBtmReport
from ieee1905.io import EthernetFrame
from ieee1905.io.backend import ETHERTYPE_IEEE1905, get_default_backend
from ieee1905.plugins import get_registry
from tests.fixtures.build_easymesh_r1_pcap import _r1_tlvs

FIXTURE = Path(__file__).parent / "fixtures" / "easymesh_r1.pcap"


def _rt(tlv: object) -> object:
    return decode_raw(encode_typed(tlv))  # type: ignore[arg-type]


# ---- Per-TLV round-trip (the fixture exercises the same set, but explicit
# tests give clearer failure attribution) ----------------------------------------


def test_every_r1_tlv_round_trips() -> None:
    for original in _r1_tlvs():
        decoded = _rt(original)
        assert type(decoded) is type(original), (
            f"{type(original).__name__}: decoded as {type(decoded).__name__}"
        )
        assert decoded == original, f"{type(original).__name__}: value mismatch"


# ---- Fixture regression --------------------------------------------------------


def _iter_payloads() -> list[bytes]:
    backend = get_default_backend()
    out: list[bytes] = []
    for raw_frame, _ts in backend.open_offline(str(FIXTURE)):
        eth = EthernetFrame.parse(raw_frame)
        if eth.ethertype == ETHERTYPE_IEEE1905:
            out.append(eth.payload)
    return out


def test_r1_fixture_exists() -> None:
    assert FIXTURE.exists(), (
        f"missing fixture: {FIXTURE} (regenerate with build_easymesh_r1_pcap)"
    )


def test_r1_fixture_frame_count() -> None:
    payloads = _iter_payloads()
    assert len(payloads) == len(_r1_tlvs())


def test_r1_fixture_wire_format_locked() -> None:
    payloads = _iter_payloads()
    for i, (payload, original) in enumerate(zip(payloads, _r1_tlvs(), strict=True)):
        cmdu = CMDU.from_bytes(payload)
        assert len(cmdu.tlvs) == 2, f"frame {i}: expected 2 TLVs, got {len(cmdu.tlvs)}"
        assert cmdu.tlvs[-1].tlv_type == TLVType.END_OF_MESSAGE.value
        assert cmdu.tlvs[0] == encode_typed(original), (  # type: ignore[arg-type]
            f"frame {i}: {type(original).__name__} wire bytes drifted"
        )


def test_r1_fixture_typed_decode_matches_original() -> None:
    payloads = _iter_payloads()
    for i, (payload, original) in enumerate(zip(payloads, _r1_tlvs(), strict=True)):
        cmdu = CMDU.from_bytes(payload)
        typed = list(cmdu.typed_tlvs())
        assert isinstance(typed[0], type(original)), (
            f"frame {i}: decoded as {type(typed[0]).__name__}, "
            f"expected {type(original).__name__}"
        )
        assert typed[0] == original, f"frame {i}: {type(original).__name__} mismatch"


# ---- Sanity: spot-check accessors on bit-packed capabilities -------------------


def test_ap_ht_capability_accessors() -> None:
    # flags=0xCE = 1100_1110:
    #  bits 7-6 = 11 -> max_tx = 4 SS
    #  bits 5-4 = 00 -> max_rx = 1 SS
    #  bit 3   = 1  -> SGI 20 MHz
    #  bit 2   = 1  -> SGI 40 MHz
    #  bit 1   = 1  -> HT 40 MHz
    cap = ApHtCapabilities(radio_id=b"\x00" * 6, flags=0xCE)
    assert cap.max_tx_streams == 4
    assert cap.max_rx_streams == 1
    assert cap.sgi_20mhz is True
    assert cap.sgi_40mhz is True
    assert cap.ht_40mhz is True


def test_ap_capability_accessors() -> None:
    cap = ApCapability(flags=0xE0)  # all three R1 bits set
    assert cap.unassoc_metrics_supported_channel is True
    assert cap.unassoc_metrics_nonoperating_channel is True
    assert cap.agent_initiated_rcpi_steering is True


def test_steering_btm_report_optional_target_field() -> None:
    """The optional target BSSID is only present when btm_status_code == 0."""
    bssid = b"\xaa\xbb\xcc\xdd\xee\xff"
    sta = b"\x00\x11\x22\x33\x44\x55"
    target = b"\x10\x20\x30\x40\x50\x60"

    full = SteeringBtmReport(bssid=bssid, sta_mac=sta, btm_status_code=0, target_bssid=target)
    short_ = SteeringBtmReport(bssid=bssid, sta_mac=sta, btm_status_code=1, target_bssid=None)

    assert _rt(full) == full
    assert _rt(short_) == short_
    assert len(encode_typed(full).payload) == 19  # type: ignore[arg-type]
    assert len(encode_typed(short_).payload) == 13  # type: ignore[arg-type]


# ---- Coverage: every R1 TLVType value has a registered handler -----------------


def test_every_r1_tlv_type_has_a_handler() -> None:
    registry = get_registry()
    missing = [
        t.name
        for t in TLVType
        if t.name.startswith("EM_") and registry.lookup(t.value) is None
    ]
    assert not missing, f"R1 TLV types missing a handler: {missing}"


# ---- Unknown TLV still surfaces as RawTLV in R1 message context ----------------


def test_unknown_tlv_in_em_message_falls_through_to_raw() -> None:
    payloads = _iter_payloads()
    cmdu = CMDU.from_bytes(payloads[0])
    cmdu.tlvs.insert(0, RawTLV(tlv_type=0xCC, payload=b"unknown-em"))
    rebuilt = CMDU.from_bytes(cmdu.to_bytes(append_end_of_message=False))
    typed = list(rebuilt.typed_tlvs())
    assert isinstance(typed[0], RawTLV)
    assert typed[0].payload == b"unknown-em"
