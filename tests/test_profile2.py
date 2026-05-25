# SPDX-License-Identifier: GPL-2.0-or-later
"""Profile-2 (4-byte TLV length) framing round-trip and cross-mode tests."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ieee1905.core import CMDU, CMDUHeader, RawTLV
from ieee1905.core.cmdu import CMDUParseError
from ieee1905.core.tlv import (
    TLV_HEADER_SIZE,
    TLV_HEADER_SIZE_EXTENDED,
    TLVParseError,
)

# ---- RawTLV: encoder size deltas ---------------------------------------------


def test_extended_tlv_header_is_5_bytes() -> None:
    tlv = RawTLV(tlv_type=0x01, payload=b"\xaa" * 6)
    standard = tlv.to_bytes(extended_length=False)
    extended = tlv.to_bytes(extended_length=True)
    assert len(standard) == TLV_HEADER_SIZE + 6
    assert len(extended) == TLV_HEADER_SIZE_EXTENDED + 6
    assert len(extended) - len(standard) == 2  # 4-byte length vs 2-byte length


def test_extended_tlv_round_trip() -> None:
    tlv = RawTLV(tlv_type=0x80, payload=b"profile-2 sample payload")
    wire = tlv.to_bytes(extended_length=True)
    decoded = RawTLV.from_bytes(wire, extended_length=True)
    assert decoded == tlv


def test_standard_decode_of_extended_wire_misreads() -> None:
    """Decoding a Profile-2 frame with the default (standard) parser is wrong."""
    payload = b"\x00" * 8  # length 8 in u32 = 0x00000008
    tlv = RawTLV(tlv_type=0x80, payload=payload)
    extended_wire = tlv.to_bytes(extended_length=True)  # 5-byte header + 8 bytes
    # The standard parser sees: type=0x80, length=0x0000 (first 2 bytes), then
    # treats the next 2 bytes as the payload start — i.e. it returns a wrong TLV
    # whose payload is the bytes that were really the rest of the length field.
    misread = RawTLV.from_bytes(extended_wire[: TLV_HEADER_SIZE], extended_length=False)
    assert misread.length == 0
    # And parsing the full extended wire with the standard parser succeeds but
    # produces trailing bytes, so from_bytes (which enforces full consumption)
    # raises.
    with pytest.raises(TLVParseError):
        RawTLV.from_bytes(extended_wire, extended_length=False)


def test_extended_decode_of_standard_wire_misreads() -> None:
    """Decoding a standard frame with the Profile-2 parser misreads the length."""
    tlv = RawTLV(tlv_type=0x80, payload=b"\x01\x02\x03\x04")
    standard_wire = tlv.to_bytes(extended_length=False)
    # Standard is only 7 bytes; the extended parser needs at least 5 for the
    # header, succeeds at unpacking, but the declared (mis-)length runs past
    # the buffer.
    with pytest.raises(TLVParseError):
        RawTLV.from_bytes(standard_wire, extended_length=True)


# ---- CMDU: round-trip in each mode -------------------------------------------


@pytest.mark.parametrize("profile_kwarg", [{"extended_length": True}, {"profile": 2}])
def test_cmdu_round_trip_profile2(profile_kwarg: dict[str, object]) -> None:
    cmdu = CMDU(
        header=CMDUHeader(message_type=0x8002, message_id=0x4242),
        tlvs=[
            RawTLV(tlv_type=0x80, payload=b"supported-service"),
            RawTLV(tlv_type=0x83, payload=b"operational-bss"),
        ],
    )
    wire = cmdu.to_bytes(**profile_kwarg)  # type: ignore[arg-type]
    parsed = CMDU.from_bytes(wire, **profile_kwarg)  # type: ignore[arg-type]
    assert parsed.header == cmdu.header
    # Original two TLVs + auto-appended end-of-message.
    assert parsed.tlvs[:-1] == cmdu.tlvs
    assert parsed.tlvs[-1].tlv_type == 0x00


def test_cmdu_profile2_wire_is_larger_than_standard() -> None:
    cmdu = CMDU(
        header=CMDUHeader(message_type=0x0000, message_id=1),
        tlvs=[RawTLV(tlv_type=0x01, payload=b"\xaa" * 6)],
    )
    std = cmdu.to_bytes()
    p2 = cmdu.to_bytes(profile=2)
    # Two TLVs (the explicit one + auto-appended EoM) x 2 extra bytes per header.
    assert len(p2) - len(std) == 4


def test_cmdu_standard_decode_of_profile2_frame_fails() -> None:
    cmdu = CMDU(
        header=CMDUHeader(message_type=0x8002, message_id=1),
        tlvs=[RawTLV(tlv_type=0x80, payload=b"\xab" * 16)],
    )
    p2_wire = cmdu.to_bytes(profile=2)
    with pytest.raises(CMDUParseError):
        CMDU.from_bytes(p2_wire)


# ---- Property: random CMDUs round-trip in both modes -------------------------


@st.composite
def _raw_tlv_strategy(draw: st.DrawFn) -> RawTLV:
    return RawTLV(
        tlv_type=draw(st.integers(1, 0xFF)),
        payload=draw(st.binary(max_size=64)),
    )


header_strategy = st.builds(
    CMDUHeader,
    message_type=st.integers(0, 0xFFFF),
    message_id=st.integers(0, 0xFFFF),
)


@given(hdr=header_strategy, tlvs=st.lists(_raw_tlv_strategy(), max_size=6))
@settings(max_examples=50)
def test_cmdu_property_round_trip_standard(
    hdr: CMDUHeader, tlvs: list[RawTLV]
) -> None:
    cmdu = CMDU(header=hdr, tlvs=tlvs)
    parsed = CMDU.from_bytes(cmdu.to_bytes())
    assert parsed.header == hdr
    assert parsed.tlvs[:-1] == tlvs


@given(hdr=header_strategy, tlvs=st.lists(_raw_tlv_strategy(), max_size=6))
@settings(max_examples=50)
def test_cmdu_property_round_trip_profile2(
    hdr: CMDUHeader, tlvs: list[RawTLV]
) -> None:
    cmdu = CMDU(header=hdr, tlvs=tlvs)
    parsed = CMDU.from_bytes(cmdu.to_bytes(profile=2), profile=2)
    assert parsed.header == hdr
    assert parsed.tlvs[:-1] == tlvs
