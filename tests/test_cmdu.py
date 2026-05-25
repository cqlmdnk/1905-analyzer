# SPDX-License-Identifier: GPL-2.0-or-later
"""CMDU header + full-CMDU encode/decode tests."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ieee1905.core import CMDU, CMDUHeader, CMDUParseError, RawTLV


def test_header_round_trip_minimal() -> None:
    hdr = CMDUHeader(message_type=0x0001, message_id=0x1234)
    parsed = CMDUHeader.from_bytes(hdr.to_bytes())
    assert parsed == hdr


def test_header_round_trip_all_flags() -> None:
    hdr = CMDUHeader(
        message_type=0xABCD,
        message_id=0xFFFE,
        fragment_id=7,
        last_fragment=True,
        relay_indicator=True,
    )
    encoded = hdr.to_bytes()
    assert len(encoded) == 8
    assert encoded[7] & 0x80
    assert encoded[7] & 0x40
    assert CMDUHeader.from_bytes(encoded) == hdr


def test_header_truncated_raises() -> None:
    try:
        CMDUHeader.from_bytes(b"\x00" * 4)
    except CMDUParseError:
        return
    raise AssertionError("expected CMDUParseError")


def test_cmdu_appends_end_of_message_when_missing() -> None:
    cmdu = CMDU(header=CMDUHeader(message_type=0, message_id=0))
    wire = cmdu.to_bytes()
    # Header (8) + EoM TLV (3) = 11 bytes.
    assert len(wire) == 11
    assert wire[-3:] == b"\x00\x00\x00"


def test_cmdu_round_trip_with_tlvs() -> None:
    cmdu = CMDU(
        header=CMDUHeader(message_type=0x0003, message_id=0x4242),
        tlvs=[
            RawTLV(tlv_type=0x01, payload=b"\xaa\xbb\xcc\xdd\xee\xff"),
            RawTLV(tlv_type=0x0B, payload=b"\x00\x1a\x2b" + b"vendor data"),
        ],
    )
    parsed = CMDU.from_bytes(cmdu.to_bytes())
    assert parsed.header == cmdu.header
    # +1 for the auto-appended end-of-message TLV.
    assert len(parsed.tlvs) == len(cmdu.tlvs) + 1
    assert parsed.tlvs[:-1] == cmdu.tlvs
    assert parsed.tlvs[-1].tlv_type == 0x00


def test_cmdu_without_end_of_message_rejected() -> None:
    cmdu = CMDU(header=CMDUHeader(message_type=0, message_id=0))
    wire = cmdu.to_bytes(append_end_of_message=False)
    try:
        CMDU.from_bytes(wire)
    except CMDUParseError:
        return
    raise AssertionError("expected CMDUParseError")


# Hypothesis: random valid headers always round-trip cleanly.

header_strategy = st.builds(
    CMDUHeader,
    message_type=st.integers(0, 0xFFFF),
    message_id=st.integers(0, 0xFFFF),
    fragment_id=st.integers(0, 0xFF),
    last_fragment=st.booleans(),
    relay_indicator=st.booleans(),
)


@given(hdr=header_strategy)
@settings(max_examples=200)
def test_header_property_round_trip(hdr: CMDUHeader) -> None:
    assert CMDUHeader.from_bytes(hdr.to_bytes()) == hdr


# Hypothesis: a CMDU built from random TLVs round-trips.

@st.composite
def _raw_tlv_strategy(draw: st.DrawFn) -> RawTLV:
    # Reserve 0x00 for the auto-appended end-of-message TLV.
    tlv_type = draw(st.integers(1, 0xFF))
    payload = draw(st.binary(max_size=64))
    return RawTLV(tlv_type=tlv_type, payload=payload)


@given(
    hdr=header_strategy,
    tlvs=st.lists(_raw_tlv_strategy(), max_size=8),
)
@settings(max_examples=100)
def test_cmdu_property_round_trip(hdr: CMDUHeader, tlvs: list[RawTLV]) -> None:
    cmdu = CMDU(header=hdr, tlvs=tlvs)
    parsed = CMDU.from_bytes(cmdu.to_bytes())
    assert parsed.header == hdr
    assert parsed.tlvs[:-1] == tlvs
    assert parsed.tlvs[-1].tlv_type == 0x00
