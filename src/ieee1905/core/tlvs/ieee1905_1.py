# SPDX-License-Identifier: GPL-2.0-or-later
"""Concrete IEEE 1905.1 TLV implementations (subset).

Each class follows the same shape:

* ``TLV_TYPE`` — the wire type byte
* ``TLV_NAME`` — short human-readable name
* ``to_payload()`` — encode the dataclass fields into the TLV payload
* ``from_payload(payload)`` — classmethod, inverse of ``to_payload``

Classes register themselves at import time via :func:`register_typed`.
Coverage in this file is the subset needed for v0.1 analyzer + plugin
work; remaining 1905.1 TLVs land later in Phase 1.

Spec references point to IEEE Std 1905.1-2013.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import ClassVar

from ieee1905.core.tlvs._helpers import MAC_LEN, OUI_LEN, parse_mac, register_typed

# ---------------------------------------------------------------------------
# 0x00 End of message — §17.2.1
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class EndOfMessage:
    TLV_TYPE: ClassVar[int] = 0x00
    TLV_NAME: ClassVar[str] = "End of message"

    def to_payload(self) -> bytes:
        return b""

    @classmethod
    def from_payload(cls, payload: bytes) -> EndOfMessage:
        if payload:
            raise ValueError(
                f"End-of-message TLV must have empty payload, got {len(payload)} bytes"
            )
        return cls()


register_typed(EndOfMessage, spec_ref="IEEE 1905.1-2013 §17.2.1")


# ---------------------------------------------------------------------------
# 0x01 AL MAC address — §17.2.2
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class AlMacAddress:
    TLV_TYPE: ClassVar[int] = 0x01
    TLV_NAME: ClassVar[str] = "AL MAC address"

    al_mac: bytes

    def __post_init__(self) -> None:
        if len(self.al_mac) != MAC_LEN:
            raise ValueError(f"AL MAC must be {MAC_LEN} bytes")

    def to_payload(self) -> bytes:
        return bytes(self.al_mac)

    @classmethod
    def from_payload(cls, payload: bytes) -> AlMacAddress:
        return cls(al_mac=parse_mac(payload))


register_typed(AlMacAddress, spec_ref="IEEE 1905.1-2013 §17.2.2")


# ---------------------------------------------------------------------------
# 0x02 MAC address — §17.2.3 (used to identify a single interface MAC)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class MacAddress:
    TLV_TYPE: ClassVar[int] = 0x02
    TLV_NAME: ClassVar[str] = "MAC address"

    mac: bytes

    def __post_init__(self) -> None:
        if len(self.mac) != MAC_LEN:
            raise ValueError(f"MAC must be {MAC_LEN} bytes")

    def to_payload(self) -> bytes:
        return bytes(self.mac)

    @classmethod
    def from_payload(cls, payload: bytes) -> MacAddress:
        return cls(mac=parse_mac(payload))


register_typed(MacAddress, spec_ref="IEEE 1905.1-2013 §17.2.3")


# ---------------------------------------------------------------------------
# 0x03 Device information — §17.2.4
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class LocalInterface:
    """One entry in a Device Information TLV's interface list."""

    mac: bytes
    media_type: int
    media_specific: bytes = b""

    _IFACE_HEADER: ClassVar[struct.Struct] = struct.Struct(">HB")  # media_type, len

    def __post_init__(self) -> None:
        if len(self.mac) != MAC_LEN:
            raise ValueError(f"interface MAC must be {MAC_LEN} bytes")
        if not 0 <= self.media_type <= 0xFFFF:
            raise ValueError("media_type out of range")
        if len(self.media_specific) > 0xFF:
            raise ValueError("media_specific too long for 8-bit length field")

    def to_payload(self) -> bytes:
        return (
            bytes(self.mac)
            + self._IFACE_HEADER.pack(self.media_type, len(self.media_specific))
            + bytes(self.media_specific)
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[LocalInterface, int]:
        mac = parse_mac(payload, offset)
        media_type, ms_len = cls._IFACE_HEADER.unpack_from(payload, offset + MAC_LEN)
        ms_start = offset + MAC_LEN + cls._IFACE_HEADER.size
        ms_end = ms_start + ms_len
        if ms_end > len(payload):
            raise ValueError(
                f"truncated media-specific info: need {ms_len} bytes, "
                f"have {len(payload) - ms_start}"
            )
        return (
            cls(mac=mac, media_type=media_type, media_specific=bytes(payload[ms_start:ms_end])),
            ms_end - offset,
        )


@dataclass(slots=True)
class DeviceInformation:
    TLV_TYPE: ClassVar[int] = 0x03
    TLV_NAME: ClassVar[str] = "Device information"

    al_mac: bytes
    interfaces: list[LocalInterface] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.al_mac) != MAC_LEN:
            raise ValueError(f"AL MAC must be {MAC_LEN} bytes")
        if len(self.interfaces) > 0xFF:
            raise ValueError("too many interfaces for 8-bit count field")

    def to_payload(self) -> bytes:
        parts = [bytes(self.al_mac), bytes([len(self.interfaces)])]
        parts.extend(iface.to_payload() for iface in self.interfaces)
        return b"".join(parts)

    @classmethod
    def from_payload(cls, payload: bytes) -> DeviceInformation:
        if len(payload) < MAC_LEN + 1:
            raise ValueError("Device Information TLV too short")
        al_mac = parse_mac(payload)
        count = payload[MAC_LEN]
        ifaces: list[LocalInterface] = []
        offset = MAC_LEN + 1
        for _ in range(count):
            iface, consumed = LocalInterface.parse(payload, offset)
            ifaces.append(iface)
            offset += consumed
        if offset != len(payload):
            raise ValueError(
                f"Device Information TLV has {len(payload) - offset} trailing bytes"
            )
        return cls(al_mac=al_mac, interfaces=ifaces)


register_typed(DeviceInformation, spec_ref="IEEE 1905.1-2013 §17.2.4")


# ---------------------------------------------------------------------------
# 0x07 1905 Neighbor device — §17.2.5
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class NeighborEntry:
    """One neighbor in a 1905 Neighbor device TLV."""

    neighbor_al_mac: bytes
    has_bridge: bool

    def __post_init__(self) -> None:
        if len(self.neighbor_al_mac) != MAC_LEN:
            raise ValueError(f"neighbor AL MAC must be {MAC_LEN} bytes")

    def to_bytes(self) -> bytes:
        return bytes(self.neighbor_al_mac) + bytes([1 if self.has_bridge else 0])

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> NeighborEntry:
        if offset + MAC_LEN + 1 > len(payload):
            raise ValueError("truncated neighbor entry")
        return cls(
            neighbor_al_mac=parse_mac(payload, offset),
            has_bridge=bool(payload[offset + MAC_LEN] & 0x01),
        )


@dataclass(slots=True)
class NeighborDevice:
    TLV_TYPE: ClassVar[int] = 0x07
    TLV_NAME: ClassVar[str] = "1905 Neighbor device"

    local_interface_mac: bytes
    neighbors: list[NeighborEntry] = field(default_factory=list)

    _ENTRY_SIZE: ClassVar[int] = MAC_LEN + 1

    def __post_init__(self) -> None:
        if len(self.local_interface_mac) != MAC_LEN:
            raise ValueError(f"local interface MAC must be {MAC_LEN} bytes")

    def to_payload(self) -> bytes:
        return bytes(self.local_interface_mac) + b"".join(n.to_bytes() for n in self.neighbors)

    @classmethod
    def from_payload(cls, payload: bytes) -> NeighborDevice:
        if len(payload) < MAC_LEN:
            raise ValueError("1905 Neighbor TLV too short")
        local_mac = parse_mac(payload)
        rest = len(payload) - MAC_LEN
        if rest % cls._ENTRY_SIZE != 0:
            raise ValueError(
                f"1905 Neighbor TLV trailing bytes don't align: {rest} % {cls._ENTRY_SIZE} != 0"
            )
        neighbors = [
            NeighborEntry.parse(payload, MAC_LEN + i * cls._ENTRY_SIZE)
            for i in range(rest // cls._ENTRY_SIZE)
        ]
        return cls(local_interface_mac=local_mac, neighbors=neighbors)


register_typed(NeighborDevice, spec_ref="IEEE 1905.1-2013 §17.2.5")


# ---------------------------------------------------------------------------
# 0x0B Vendor specific — §17.2.11
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class VendorSpecific:
    TLV_TYPE: ClassVar[int] = 0x0B
    TLV_NAME: ClassVar[str] = "Vendor specific"

    oui: bytes
    data: bytes

    def __post_init__(self) -> None:
        if len(self.oui) != OUI_LEN:
            raise ValueError(f"OUI must be {OUI_LEN} bytes")

    def to_payload(self) -> bytes:
        return bytes(self.oui) + bytes(self.data)

    @classmethod
    def from_payload(cls, payload: bytes) -> VendorSpecific:
        if len(payload) < OUI_LEN:
            raise ValueError("Vendor Specific TLV missing OUI")
        return cls(oui=bytes(payload[:OUI_LEN]), data=bytes(payload[OUI_LEN:]))


register_typed(VendorSpecific, spec_ref="IEEE 1905.1-2013 §17.2.11")


# ---------------------------------------------------------------------------
# 0x0C Link metric result code — §17.2.12
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class LinkMetricResultCode:
    TLV_TYPE: ClassVar[int] = 0x0C
    TLV_NAME: ClassVar[str] = "Link metric result code"

    #: 0x00 = invalid neighbor (the only currently defined value).
    result_code: int

    def to_payload(self) -> bytes:
        return bytes([self.result_code & 0xFF])

    @classmethod
    def from_payload(cls, payload: bytes) -> LinkMetricResultCode:
        if len(payload) != 1:
            raise ValueError(
                f"Link metric result code TLV must be 1 byte, got {len(payload)}"
            )
        return cls(result_code=payload[0])


register_typed(LinkMetricResultCode, spec_ref="IEEE 1905.1-2013 §17.2.12")


# ---------------------------------------------------------------------------
# 0x0D SearchedRole — §17.2.13
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SearchedRole:
    TLV_TYPE: ClassVar[int] = 0x0D
    TLV_NAME: ClassVar[str] = "SearchedRole"

    #: 0x00 = Registrar (only defined value in 1905.1).
    role: int

    def to_payload(self) -> bytes:
        return bytes([self.role & 0xFF])

    @classmethod
    def from_payload(cls, payload: bytes) -> SearchedRole:
        if len(payload) != 1:
            raise ValueError(f"SearchedRole TLV must be 1 byte, got {len(payload)}")
        return cls(role=payload[0])


register_typed(SearchedRole, spec_ref="IEEE 1905.1-2013 §17.2.13")


# ---------------------------------------------------------------------------
# 0x0E AutoconfigFreqBand — §17.2.14
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class AutoconfigFreqBand:
    TLV_TYPE: ClassVar[int] = 0x0E
    TLV_NAME: ClassVar[str] = "AutoconfigFreqBand"

    #: 0x00 = 2.4 GHz, 0x01 = 5 GHz, 0x02 = 60 GHz.
    band: int

    def to_payload(self) -> bytes:
        return bytes([self.band & 0xFF])

    @classmethod
    def from_payload(cls, payload: bytes) -> AutoconfigFreqBand:
        if len(payload) != 1:
            raise ValueError(
                f"AutoconfigFreqBand TLV must be 1 byte, got {len(payload)}"
            )
        return cls(band=payload[0])


register_typed(AutoconfigFreqBand, spec_ref="IEEE 1905.1-2013 §17.2.14")


# ---------------------------------------------------------------------------
# 0x0F SupportedRole — §17.2.15
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SupportedRole:
    TLV_TYPE: ClassVar[int] = 0x0F
    TLV_NAME: ClassVar[str] = "SupportedRole"

    role: int

    def to_payload(self) -> bytes:
        return bytes([self.role & 0xFF])

    @classmethod
    def from_payload(cls, payload: bytes) -> SupportedRole:
        if len(payload) != 1:
            raise ValueError(f"SupportedRole TLV must be 1 byte, got {len(payload)}")
        return cls(role=payload[0])


register_typed(SupportedRole, spec_ref="IEEE 1905.1-2013 §17.2.15")


# ---------------------------------------------------------------------------
# 0x10 SupportedFreqBand — §17.2.16
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SupportedFreqBand:
    TLV_TYPE: ClassVar[int] = 0x10
    TLV_NAME: ClassVar[str] = "SupportedFreqBand"

    band: int

    def to_payload(self) -> bytes:
        return bytes([self.band & 0xFF])

    @classmethod
    def from_payload(cls, payload: bytes) -> SupportedFreqBand:
        if len(payload) != 1:
            raise ValueError(
                f"SupportedFreqBand TLV must be 1 byte, got {len(payload)}"
            )
        return cls(band=payload[0])


register_typed(SupportedFreqBand, spec_ref="IEEE 1905.1-2013 §17.2.16")


# ---------------------------------------------------------------------------
# 0x1A 1905 Profile version — §17.2.26
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ProfileVersion:
    TLV_TYPE: ClassVar[int] = 0x1A
    TLV_NAME: ClassVar[str] = "1905 profile version"

    #: 0x00 = 1905.1-2013, 0x01 = 1905.1a-2014.
    version: int

    def to_payload(self) -> bytes:
        return bytes([self.version & 0xFF])

    @classmethod
    def from_payload(cls, payload: bytes) -> ProfileVersion:
        if len(payload) != 1:
            raise ValueError(
                f"1905 profile version TLV must be 1 byte, got {len(payload)}"
            )
        return cls(version=payload[0])


register_typed(ProfileVersion, spec_ref="IEEE 1905.1-2013 §17.2.26")
