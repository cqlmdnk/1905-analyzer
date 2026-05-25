# SPDX-License-Identifier: GPL-2.0-or-later
"""TLV codec + builtin TLV implementations."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ieee1905.core import RawTLV, TLVParseError
from ieee1905.core.tlv import decode_raw, encode_typed
from ieee1905.core.tlvs import (
    AlMacAddress,
    AutoconfigFreqBand,
    DeviceInformation,
    EndOfMessage,
    LinkMetricResultCode,
    LocalInterface,
    MacAddress,
    NeighborDevice,
    NeighborEntry,
    ProfileVersion,
    SearchedRole,
    SupportedFreqBand,
    SupportedRole,
    VendorSpecific,
)

MAC_A = b"\x00\x11\x22\x33\x44\x55"
MAC_B = b"\xaa\xbb\xcc\xdd\xee\xff"
OUI_TEST = b"\x00\x1a\x2b"


def test_raw_tlv_round_trip() -> None:
    raw = RawTLV(tlv_type=0x42, payload=b"hello world")
    parsed = RawTLV.from_bytes(raw.to_bytes())
    assert parsed == raw


def test_raw_tlv_truncated_header() -> None:
    try:
        RawTLV.from_bytes(b"\x42\x00")  # only 2 bytes, need 3
    except TLVParseError:
        return
    raise AssertionError("expected TLVParseError")


def test_raw_tlv_truncated_payload() -> None:
    # declares 10 bytes, supplies 3
    try:
        RawTLV.from_bytes(b"\x42\x00\x0a\xde\xad\xbe")
    except TLVParseError:
        return
    raise AssertionError("expected TLVParseError")


def test_end_of_message_round_trip() -> None:
    raw = encode_typed(EndOfMessage())
    assert raw.tlv_type == 0x00
    assert raw.payload == b""
    assert isinstance(decode_raw(raw), EndOfMessage)


def test_al_mac_address_round_trip() -> None:
    tlv = AlMacAddress(al_mac=MAC_A)
    raw = encode_typed(tlv)
    assert raw.tlv_type == 0x01
    assert raw.payload == MAC_A
    decoded = decode_raw(raw)
    assert isinstance(decoded, AlMacAddress)
    assert decoded.al_mac == MAC_A


def test_mac_address_round_trip() -> None:
    tlv = MacAddress(mac=MAC_B)
    raw = encode_typed(tlv)
    decoded = decode_raw(raw)
    assert isinstance(decoded, MacAddress)
    assert decoded.mac == MAC_B


def test_device_information_round_trip() -> None:
    tlv = DeviceInformation(
        al_mac=MAC_A,
        interfaces=[
            LocalInterface(mac=MAC_A, media_type=0x0100),
            LocalInterface(mac=MAC_B, media_type=0x0102, media_specific=b"\x01\x02\x03"),
        ],
    )
    raw = encode_typed(tlv)
    decoded = decode_raw(raw)
    assert isinstance(decoded, DeviceInformation)
    assert decoded == tlv


def test_neighbor_device_round_trip() -> None:
    tlv = NeighborDevice(
        local_interface_mac=MAC_A,
        neighbors=[
            NeighborEntry(neighbor_al_mac=MAC_B, has_bridge=True),
            NeighborEntry(neighbor_al_mac=MAC_A, has_bridge=False),
        ],
    )
    decoded = decode_raw(encode_typed(tlv))
    assert isinstance(decoded, NeighborDevice)
    assert decoded == tlv


def test_neighbor_device_misaligned_rejected() -> None:
    # local_mac (6) + 3 extra bytes — not a multiple of (MAC_LEN + 1).
    raw = RawTLV(tlv_type=0x07, payload=MAC_A + b"\x01\x02\x03")
    try:
        decode_raw(raw)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_vendor_specific_round_trip() -> None:
    tlv = VendorSpecific(oui=OUI_TEST, data=b"\xde\xad\xbe\xef")
    decoded = decode_raw(encode_typed(tlv))
    assert isinstance(decoded, VendorSpecific)
    assert decoded == tlv


def test_unknown_tlv_falls_through_to_raw() -> None:
    raw = RawTLV(tlv_type=0xEE, payload=b"unknown")  # type not registered
    decoded = decode_raw(raw)
    assert isinstance(decoded, RawTLV)
    assert decoded.payload == b"unknown"


# --- single-byte TLVs share a shape; parametrize them. -------------------------


def test_single_byte_tlvs_round_trip() -> None:
    cases = [
        (LinkMetricResultCode, 0x0C, 0),
        (SearchedRole, 0x0D, 0),
        (AutoconfigFreqBand, 0x0E, 1),
        (SupportedRole, 0x0F, 0),
        (SupportedFreqBand, 0x10, 2),
        (ProfileVersion, 0x1A, 1),
    ]
    for cls, expected_type, value in cases:
        tlv = cls(value)  # type: ignore[call-arg]
        raw = encode_typed(tlv)
        assert raw.tlv_type == expected_type
        assert len(raw.payload) == 1
        decoded = decode_raw(raw)
        assert isinstance(decoded, cls)
        assert decoded == tlv


# --- Hypothesis: random valid inputs round-trip. ------------------------------


mac_strategy = st.binary(min_size=6, max_size=6)
oui_strategy = st.binary(min_size=3, max_size=3)


@given(mac=mac_strategy)
@settings(max_examples=100)
def test_al_mac_property(mac: bytes) -> None:
    tlv = AlMacAddress(al_mac=mac)
    decoded = decode_raw(encode_typed(tlv))
    assert isinstance(decoded, AlMacAddress)
    assert decoded.al_mac == mac


@given(
    oui=oui_strategy,
    data=st.binary(max_size=128),
)
@settings(max_examples=100)
def test_vendor_specific_property(oui: bytes, data: bytes) -> None:
    tlv = VendorSpecific(oui=oui, data=data)
    decoded = decode_raw(encode_typed(tlv))
    assert isinstance(decoded, VendorSpecific)
    assert decoded.oui == oui
    assert decoded.data == data


@st.composite
def _interface_strategy(draw: st.DrawFn) -> LocalInterface:
    return LocalInterface(
        mac=draw(mac_strategy),
        media_type=draw(st.integers(0, 0xFFFF)),
        media_specific=draw(st.binary(max_size=64)),
    )


@given(
    al_mac=mac_strategy,
    ifaces=st.lists(_interface_strategy(), max_size=8),
)
@settings(max_examples=50)
def test_device_information_property(al_mac: bytes, ifaces: list[LocalInterface]) -> None:
    tlv = DeviceInformation(al_mac=al_mac, interfaces=ifaces)
    decoded = decode_raw(encode_typed(tlv))
    assert isinstance(decoded, DeviceInformation)
    assert decoded == tlv
