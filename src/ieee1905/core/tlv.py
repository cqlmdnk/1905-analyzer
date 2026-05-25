# SPDX-License-Identifier: GPL-2.0-or-later
"""TLV (Type-Length-Value) codec.

IEEE 1905.1 TLV header is three bytes::

    +------+------+------+
    | Type |     Length  |
    | u8   |   u16 BE    |
    +------+------+------+

The length field gives the size of the payload that follows, in bytes,
excluding the header itself. EasyMesh Profile-2 introduces a 32-bit
length variant; that one will be added in Phase 2 alongside the R2 TLVs.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, ClassVar, Protocol

from ieee1905.plugins.registry import get_registry

#: Size of the standard IEEE 1905.1 TLV header (type + length).
TLV_HEADER_SIZE = 3

#: Maximum payload length addressable by the 16-bit length field.
TLV_MAX_PAYLOAD = 0xFFFF


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

    def __post_init__(self) -> None:
        if not 0 <= self.tlv_type <= 0xFF:
            raise ValueError(f"TLV type out of range: 0x{self.tlv_type:x}")
        if len(self.payload) > TLV_MAX_PAYLOAD:
            raise ValueError(
                f"TLV payload exceeds 16-bit length field: {len(self.payload)} bytes"
            )

    @property
    def length(self) -> int:
        return len(self.payload)

    def to_bytes(self) -> bytes:
        return self._HEADER.pack(self.tlv_type, len(self.payload)) + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> RawTLV:
        tlv, consumed = cls.parse_one(data, 0)
        if consumed != len(data):
            raise TLVParseError(
                f"trailing bytes after TLV ({len(data) - consumed} extra)"
            )
        return tlv

    @classmethod
    def parse_one(cls, data: bytes, offset: int = 0) -> tuple[RawTLV, int]:
        """Parse one TLV starting at ``offset``; return (tlv, bytes consumed)."""
        if len(data) - offset < TLV_HEADER_SIZE:
            raise TLVParseError(
                "truncated TLV header: "
                f"need {TLV_HEADER_SIZE} bytes, have {len(data) - offset}"
            )
        tlv_type, payload_len = cls._HEADER.unpack_from(data, offset)
        end = offset + TLV_HEADER_SIZE + payload_len
        if end > len(data):
            raise TLVParseError(
                f"truncated TLV payload: declared {payload_len} bytes, "
                f"only {len(data) - offset - TLV_HEADER_SIZE} available"
            )
        payload = bytes(data[offset + TLV_HEADER_SIZE : end])
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
