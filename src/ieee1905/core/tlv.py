# SPDX-License-Identifier: GPL-2.0-or-later
"""TLV (Type-Length-Value) codec.

IEEE 1905.1 TLV header is three bytes::

    +------+------+------+
    | Type |     Length  |
    | u8   |   u16 BE    |
    +------+------+------+

EasyMesh Profile-2 (Multi-AP Spec v2.0 §17.2) introduces an extended
encoding where the length field is 32 bits, giving a 5-byte header::

    +------+------+------+------+------+
    | Type |          Length          |
    | u8   |        u32 BE            |
    +------+------+------+------+------+

The mode is selected by the sender at CMDU level (a Profile-2 device
emits all TLVs in extended form; pre-Profile-2 devices always use the
3-byte header). The receiver knows which encoding to expect from
out-of-band capability exchange (Profile-2 AP Capability TLV).

In code, both :class:`RawTLV` and :class:`CMDU <ieee1905.core.cmdu.CMDU>`
accept ``extended_length`` (and the CMDU-level ``profile=`` alias) as
opt-in keyword arguments — the default remains standard 16-bit length
so existing call sites keep working unchanged.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, ClassVar, Protocol

from ieee1905.plugins.registry import get_registry

#: Size of the standard IEEE 1905.1 TLV header (type + length).
TLV_HEADER_SIZE = 3
#: Size of the Profile-2 extended TLV header (type + 32-bit length).
TLV_HEADER_SIZE_EXTENDED = 5

#: Maximum payload length addressable by the 16-bit length field.
TLV_MAX_PAYLOAD = 0xFFFF
#: Maximum payload length addressable by the Profile-2 32-bit length field.
TLV_MAX_PAYLOAD_EXTENDED = 0xFFFFFFFF


class TLVParseError(ValueError):
    """Raised when a byte stream cannot be parsed as a TLV."""


class TypedTLV(Protocol):
    """Interface every concrete TLV implementation satisfies."""

    TLV_TYPE: ClassVar[int]
    TLV_NAME: ClassVar[str]

    def to_payload(self) -> bytes:
        ...

    @classmethod
    def from_payload(cls, payload: bytes) -> TypedTLV:
        ...


# Alias used externally; "TLV" is the friendlier name.
TLV = TypedTLV


@dataclass(slots=True)
class RawTLV:
    """A TLV whose payload is kept as-is, without semantic decoding.

    ``RawTLV`` is the canonical wire-level representation used by the
    CMDU parser. Higher layers convert these into typed TLV objects via
    the registry.
    """

    tlv_type: int
    payload: bytes

    _HEADER: ClassVar[struct.Struct] = struct.Struct(">BH")
    _HEADER_EXTENDED: ClassVar[struct.Struct] = struct.Struct(">BI")

    def __post_init__(self) -> None:
        if not 0 <= self.tlv_type <= 0xFF:
            raise ValueError(f"TLV type out of range: 0x{self.tlv_type:x}")
        if len(self.payload) > TLV_MAX_PAYLOAD_EXTENDED:
            raise ValueError(
                f"TLV payload exceeds 32-bit length field: {len(self.payload)} bytes"
            )

    @property
    def length(self) -> int:
        return len(self.payload)

    def to_bytes(self, *, extended_length: bool = False) -> bytes:
        """Serialize as TLV. Set ``extended_length=True`` for Profile-2 (4-byte length)."""
        if extended_length:
            return self._HEADER_EXTENDED.pack(self.tlv_type, len(self.payload)) + self.payload
        if len(self.payload) > TLV_MAX_PAYLOAD:
            raise ValueError(
                f"TLV payload exceeds 16-bit length field; pass extended_length=True "
                f"({len(self.payload)} bytes)"
            )
        return self._HEADER.pack(self.tlv_type, len(self.payload)) + self.payload

    @classmethod
    def from_bytes(cls, data: bytes, *, extended_length: bool = False) -> RawTLV:
        tlv, consumed = cls.parse_one(data, 0, extended_length=extended_length)
        if consumed != len(data):
            raise TLVParseError(
                f"trailing bytes after TLV ({len(data) - consumed} extra)"
            )
        return tlv

    @classmethod
    def parse_one(
        cls,
        data: bytes,
        offset: int = 0,
        *,
        extended_length: bool = False,
    ) -> tuple[RawTLV, int]:
        """Parse one TLV starting at ``offset``; return (tlv, bytes consumed).

        ``extended_length=True`` selects the Profile-2 5-byte header.
        """
        header_struct = cls._HEADER_EXTENDED if extended_length else cls._HEADER
        header_size = header_struct.size
        if len(data) - offset < header_size:
            raise TLVParseError(
                "truncated TLV header: "
                f"need {header_size} bytes, have {len(data) - offset}"
            )
        tlv_type, payload_len = header_struct.unpack_from(data, offset)
        end = offset + header_size + payload_len
        if end > len(data):
            raise TLVParseError(
                f"truncated TLV payload: declared {payload_len} bytes, "
                f"only {len(data) - offset - header_size} available"
            )
        payload = bytes(data[offset + header_size : end])
        return cls(tlv_type=tlv_type, payload=payload), end - offset


def encode_typed(tlv: TypedTLV) -> RawTLV:
    """Wrap a typed TLV into its on-wire :class:`RawTLV` form."""
    return RawTLV(tlv_type=tlv.TLV_TYPE, payload=tlv.to_payload())


def decode_raw(raw: RawTLV) -> TypedTLV | RawTLV:
    """Try to decode ``raw`` via the registry; return the original on miss."""
    descriptor = get_registry().lookup(raw.tlv_type)
    if descriptor is None:
        return raw
    handler: Any = descriptor.handler
    from_payload = getattr(handler, "from_payload", None)
    if from_payload is None:
        return raw
    return from_payload(raw.payload)  # type: ignore[no-any-return]
