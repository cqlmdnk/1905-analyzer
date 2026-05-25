# SPDX-License-Identifier: GPL-2.0-or-later
"""Fragment reassembly tests."""

from __future__ import annotations

import time

from ieee1905.core import CMDU, CMDUHeader, FragmentReassembler, RawTLV
from ieee1905.core.cmdu import CMDU_HEADER_SIZE

SRC_A = b"\x00\x11\x22\x33\x44\x55"
SRC_B = b"\xaa\xbb\xcc\xdd\xee\xff"


def _make_fragment(
    *,
    message_id: int,
    fragment_id: int,
    last: bool,
    payload: bytes,
    message_type: int = 0x0003,
) -> bytes:
    header = CMDUHeader(
        message_type=message_type,
        message_id=message_id,
        fragment_id=fragment_id,
        last_fragment=last,
    )
    return header.to_bytes() + payload


def test_single_fragment_passes_through() -> None:
    rsm = FragmentReassembler()
    cmdu = CMDU(
        header=CMDUHeader(message_type=0x0001, message_id=0xCAFE),
        tlvs=[RawTLV(tlv_type=0x01, payload=b"\x00" * 6)],
    )
    result = rsm.push(SRC_A, cmdu.to_bytes())
    assert result is not None
    assert result.header.message_type == 0x0001
    assert rsm.pending_groups == 0


def test_two_fragment_reassembly_in_order() -> None:
    rsm = FragmentReassembler()
    # First fragment carries the first half of one TLV; second carries the
    # rest plus the end-of-message TLV. The reassembler glues bytes back
    # together before re-parsing TLVs.
    tlv = RawTLV(tlv_type=0x01, payload=b"\x00" * 6).to_bytes()
    eom = RawTLV(tlv_type=0x00, payload=b"").to_bytes()
    combined = tlv + eom

    half = len(combined) // 2
    frag0 = _make_fragment(message_id=1, fragment_id=0, last=False, payload=combined[:half])
    frag1 = _make_fragment(message_id=1, fragment_id=1, last=True, payload=combined[half:])

    assert rsm.push(SRC_A, frag0) is None
    assert rsm.pending_groups == 1

    result = rsm.push(SRC_A, frag1)
    assert result is not None
    assert result.header.message_id == 1
    assert result.header.fragment_id == 0
    assert result.header.last_fragment is True
    assert result.tlvs[0].tlv_type == 0x01
    assert result.tlvs[-1].tlv_type == 0x00
    assert rsm.pending_groups == 0


def test_two_fragment_reassembly_out_of_order() -> None:
    rsm = FragmentReassembler()
    tlv = RawTLV(tlv_type=0x01, payload=b"\x11" * 6).to_bytes()
    eom = RawTLV(tlv_type=0x00, payload=b"").to_bytes()
    combined = tlv + eom
    half = len(combined) // 2
    frag0 = _make_fragment(message_id=2, fragment_id=0, last=False, payload=combined[:half])
    frag1 = _make_fragment(message_id=2, fragment_id=1, last=True, payload=combined[half:])

    # Second fragment arrives first.
    assert rsm.push(SRC_A, frag1) is None
    assert rsm.push(SRC_A, frag0) is not None


def test_separate_sources_are_independent() -> None:
    rsm = FragmentReassembler()
    tlv = RawTLV(tlv_type=0x01, payload=b"\x22" * 6).to_bytes()
    eom = RawTLV(tlv_type=0x00, payload=b"").to_bytes()
    combined = tlv + eom
    half = len(combined) // 2

    rsm.push(SRC_A, _make_fragment(message_id=3, fragment_id=0, last=False, payload=combined[:half]))
    rsm.push(SRC_B, _make_fragment(message_id=3, fragment_id=0, last=False, payload=combined[:half]))
    assert rsm.pending_groups == 2

    rsm.push(SRC_A, _make_fragment(message_id=3, fragment_id=1, last=True, payload=combined[half:]))
    assert rsm.pending_groups == 1  # SRC_B's group still in flight


def test_stale_groups_are_evicted() -> None:
    rsm = FragmentReassembler(timeout_s=0.05)
    rsm.push(SRC_A, _make_fragment(message_id=4, fragment_id=0, last=False, payload=b"\xab" * 4))
    assert rsm.pending_groups == 1
    time.sleep(0.1)
    # Eviction runs at the start of every push(). Sending a non-final fragment
    # on a different MID keeps the call out of the single-fragment fast path,
    # so the only effect we care about is the eviction of MID 4.
    rsm.push(SRC_B, _make_fragment(message_id=5, fragment_id=0, last=False, payload=b"\x00"))
    assert (SRC_A, 4) not in rsm._groups
    # The brand-new SRC_B/MID=5 group is still pending (not stale yet).
    assert (SRC_B, 5) in rsm._groups


def test_pre_parse_with_real_cmdu_bytes() -> None:
    """End-to-end: a single full CMDU fed into the reassembler matches direct decode."""
    cmdu = CMDU(
        header=CMDUHeader(message_type=0x0003, message_id=0x4242),
        tlvs=[RawTLV(tlv_type=0x01, payload=b"\xaa\xbb\xcc\xdd\xee\xff")],
    )
    wire = cmdu.to_bytes()
    assert len(wire) > CMDU_HEADER_SIZE
    out = FragmentReassembler().push(SRC_A, wire)
    assert out is not None
    assert out.tlvs == CMDU.from_bytes(wire).tlvs
