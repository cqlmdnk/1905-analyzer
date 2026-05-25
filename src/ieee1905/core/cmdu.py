# SPDX-License-Identifier: GPL-2.0-or-later
"""CMDU header codec.

CMDU (Control Message Data Unit) wire format per IEEE 1905.1-2013 §6.1:

::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Message version (0x00) |  Reserved   |    Message type (BE)   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |       Message identifier (MID, BE)    | Fragment ID |F R . . .|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

F = last_fragment_indicator (bit 7 of flags byte)
R = relay_indicator        (bit 6 of flags byte)

The 8-byte header is followed by zero or more TLVs and is terminated by
an end-of-message TLV (type 0x00, length 0).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import ClassVar

from ieee1905.core.tlv import RawTLV, TLVParseError

#: EtherType reserved for IEEE 1905.1 frames.
ETHERTYPE_IEEE1905 = 0x893A

#: Wire size of the CMDU header in bytes.
CMDU_HEADER_SIZE = 8

#: Message version field; the only legal value in IEEE 1905.1-2013.
CMDU_MESSAGE_VERSION = 0x00


class CMDUParseError(ValueError):
    """Raised when the byte stream cannot be parsed as a CMDU."""


@dataclass(slots=True)
class CMDUHeader:
    """Decoded CMDU header (8 bytes on the wire)."""

    message_type: int
    message_id: int
    fragment_id: int = 0
    last_fragment: bool = True
    relay_indicator: bool = False
    message_version: int = CMDU_MESSAGE_VERSION
    reserved: int = 0

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(">BBHHBB")

    def to_bytes(self) -> bytes:
        flags = 0
        if self.last_fragment:
            flags |= 0x80
        if self.relay_indicator:
            flags |= 0x40
        return self._STRUCT.pack(
            self.message_version & 0xFF,
            self.reserved & 0xFF,
            self.message_type & 0xFFFF,
            self.message_id & 0xFFFF,
            self.fragment_id & 0xFF,
            flags,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> CMDUHeader:
        if len(data) < CMDU_HEADER_SIZE:
            raise CMDUParseError(
                f"CMDU header needs {CMDU_HEADER_SIZE} bytes, got {len(data)}"
            )
        version, reserved, msg_type, mid, frag_id, flags = cls._STRUCT.unpack_from(data)
        return cls(
            message_type=msg_type,
            message_id=mid,
            fragment_id=frag_id,
            last_fragment=bool(flags & 0x80),
            relay_indicator=bool(flags & 0x40),
            message_version=version,
            reserved=reserved,
        )


@dataclass(slots=True)
class CMDU:
    """A full CMDU: header + ordered TLV list.

    The terminating end-of-message TLV (type 0x00, length 0) is treated
    as a normal TLV in the ``tlvs`` list; :meth:`from_bytes` will reject
    a stream that is missing it.
    """

    header: CMDUHeader
    tlvs: list[RawTLV] = field(default_factory=list)

    #: End-of-message TLV type per IEEE 1905.1 §17.2.1.
    END_OF_MESSAGE_TYPE: ClassVar[int] = 0x00

    def to_bytes(self, *, append_end_of_message: bool = True) -> bytes:
        parts: list[bytes] = [self.header.to_bytes()]
        seen_eom = False
        for tlv in self.tlvs:
            parts.append(tlv.to_bytes())
            if tlv.tlv_type == self.END_OF_MESSAGE_TYPE:
                seen_eom = True
        if append_end_of_message and not seen_eom:
            parts.append(RawTLV(self.END_OF_MESSAGE_TYPE, b"").to_bytes())
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes, *, require_end_of_message: bool = True) -> CMDU:
        if len(data) < CMDU_HEADER_SIZE:
            raise CMDUParseError(
                f"CMDU needs at least {CMDU_HEADER_SIZE} bytes, got {len(data)}"
            )
        header = CMDUHeader.from_bytes(data)

        tlvs: list[RawTLV] = []
        offset = CMDU_HEADER_SIZE
        seen_eom = False
        while offset < len(data):
            try:
                tlv, consumed = RawTLV.parse_one(data, offset)
            except TLVParseError as exc:
                raise CMDUParseError(f"TLV at offset {offset}: {exc}") from exc
            tlvs.append(tlv)
            offset += consumed
            if tlv.tlv_type == cls.END_OF_MESSAGE_TYPE:
                seen_eom = True
                break

        if require_end_of_message and not seen_eom:
            raise CMDUParseError("CMDU does not terminate with end-of-message TLV")

        return cls(header=header, tlvs=tlvs)
