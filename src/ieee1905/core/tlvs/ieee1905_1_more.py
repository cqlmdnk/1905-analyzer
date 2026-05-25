# SPDX-License-Identifier: GPL-2.0-or-later
"""Remaining IEEE 1905.1 TLV implementations.

These complete the 1905.1 baseline coverage beyond the subset already
implemented in :mod:`ieee1905.core.tlvs.ieee1905_1`. EasyMesh additions
(>= 0x80) land in Phase 2.

Spec references: IEEE Std 1905.1-2013 §17.2 (and 1905.1a-2014
amendments where applicable).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import ClassVar

from ieee1905.core.tlvs._helpers import (
    IPV4_LEN,
    IPV6_LEN,
    MAC_LEN,
    encode_ipv4,
    encode_ipv6,
    encode_padded_ascii,
    parse_ipv4,
    parse_ipv6,
    parse_mac,
    parse_padded_ascii,
    register_typed,
)

# ---------------------------------------------------------------------------
# 0x04 Device bridging capability — §17.2.4 (renumbered in some prints to
# §17.2.4 "Device Bridging Capability TLV"). Lists which local interfaces
# are bridged together.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class BridgingTuple:
    """One bridging tuple: the MACs in this tuple are bridged together."""

    macs: list[bytes] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.macs) > 0xFF:
            raise ValueError("too many MACs in bridging tuple (8-bit count)")
        for m in self.macs:
            if len(m) != MAC_LEN:
                raise ValueError(f"bridging-tuple MAC must be {MAC_LEN} bytes")

    def to_bytes(self) -> bytes:
        return bytes([len(self.macs)]) + b"".join(bytes(m) for m in self.macs)

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[BridgingTuple, int]:
        if offset + 1 > len(payload):
            raise ValueError("truncated bridging tuple count")
        count = payload[offset]
        start = offset + 1
        end = start + count * MAC_LEN
        if end > len(payload):
            raise ValueError(
                f"truncated bridging tuple: need {count * MAC_LEN} bytes, "
                f"have {len(payload) - start}"
            )
        macs = [bytes(payload[start + i * MAC_LEN : start + (i + 1) * MAC_LEN]) for i in range(count)]
        return cls(macs=macs), end - offset


@dataclass(slots=True)
class DeviceBridgingCapability:
    TLV_TYPE: ClassVar[int] = 0x04
    TLV_NAME: ClassVar[str] = "Device bridging capability"

    tuples: list[BridgingTuple] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.tuples) > 0xFF:
            raise ValueError("too many bridging tuples (8-bit count)")

    def to_payload(self) -> bytes:
        return bytes([len(self.tuples)]) + b"".join(t.to_bytes() for t in self.tuples)

    @classmethod
    def from_payload(cls, payload: bytes) -> DeviceBridgingCapability:
        if not payload:
            raise ValueError("Device bridging capability TLV needs at least a count byte")
        count = payload[0]
        offset = 1
        tuples: list[BridgingTuple] = []
        for _ in range(count):
            t, consumed = BridgingTuple.parse(payload, offset)
            tuples.append(t)
            offset += consumed
        if offset != len(payload):
            raise ValueError(
                f"Device bridging capability has {len(payload) - offset} trailing bytes"
            )
        return cls(tuples=tuples)


register_typed(DeviceBridgingCapability, spec_ref="IEEE 1905.1-2013 §17.2.4")


# ---------------------------------------------------------------------------
# 0x06 Non-1905 neighbor device list — §17.2.6
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Non1905NeighborDeviceList:
    TLV_TYPE: ClassVar[int] = 0x06
    TLV_NAME: ClassVar[str] = "Non-1905 neighbor device list"

    local_interface_mac: bytes
    neighbor_macs: list[bytes] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.local_interface_mac) != MAC_LEN:
            raise ValueError("local interface MAC must be 6 bytes")
        for m in self.neighbor_macs:
            if len(m) != MAC_LEN:
                raise ValueError("neighbor MAC must be 6 bytes")

    def to_payload(self) -> bytes:
        return bytes(self.local_interface_mac) + b"".join(bytes(m) for m in self.neighbor_macs)

    @classmethod
    def from_payload(cls, payload: bytes) -> Non1905NeighborDeviceList:
        if len(payload) < MAC_LEN:
            raise ValueError("Non-1905 neighbor TLV missing local interface MAC")
        rest = len(payload) - MAC_LEN
        if rest % MAC_LEN != 0:
            raise ValueError(
                f"Non-1905 neighbor TLV trailing bytes don't align: {rest} % {MAC_LEN} != 0"
            )
        neighbors = [
            bytes(payload[MAC_LEN + i * MAC_LEN : MAC_LEN + (i + 1) * MAC_LEN])
            for i in range(rest // MAC_LEN)
        ]
        return cls(local_interface_mac=parse_mac(payload), neighbor_macs=neighbors)


register_typed(Non1905NeighborDeviceList, spec_ref="IEEE 1905.1-2013 §17.2.6")


# ---------------------------------------------------------------------------
# 0x08 Link metric query — §17.2.8
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class LinkMetricQuery:
    TLV_TYPE: ClassVar[int] = 0x08
    TLV_NAME: ClassVar[str] = "Link metric query"

    #: 0x00 = all neighbors; 0x01 = specific neighbor (carry neighbor_al_mac).
    neighbor_type: int
    #: Only meaningful when ``neighbor_type == 0x01``. Six bytes either way.
    neighbor_al_mac: bytes = b"\x00\x00\x00\x00\x00\x00"
    #: 0x00 = TX only, 0x01 = RX only, 0x02 = both.
    link_metrics: int = 0x02

    def __post_init__(self) -> None:
        if len(self.neighbor_al_mac) != MAC_LEN:
            raise ValueError("neighbor AL MAC must be 6 bytes (use zeros for 'all')")

    def to_payload(self) -> bytes:
        return (
            bytes([self.neighbor_type & 0xFF])
            + bytes(self.neighbor_al_mac)
            + bytes([self.link_metrics & 0xFF])
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> LinkMetricQuery:
        expected = 1 + MAC_LEN + 1
        if len(payload) != expected:
            raise ValueError(
                f"Link metric query TLV must be {expected} bytes, got {len(payload)}"
            )
        return cls(
            neighbor_type=payload[0],
            neighbor_al_mac=parse_mac(payload, 1),
            link_metrics=payload[1 + MAC_LEN],
        )


register_typed(LinkMetricQuery, spec_ref="IEEE 1905.1-2013 §17.2.8")


# ---------------------------------------------------------------------------
# 0x09 Transmitter link metric — §17.2.9
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class TransmitterLinkEntry:
    """One per-link metric set in a Transmitter link metric TLV (29 bytes)."""

    local_interface_mac: bytes
    neighbor_interface_mac: bytes
    intf_type: int
    has_bridge: bool
    packet_errors: int
    transmitted_packets: int
    mac_throughput_mbps: int
    link_availability_pct_x100: int
    phy_rate_mbps: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(">HBIIHHH")
    SIZE: ClassVar[int] = 2 * MAC_LEN + _STRUCT.size

    def to_bytes(self) -> bytes:
        return (
            bytes(self.local_interface_mac)
            + bytes(self.neighbor_interface_mac)
            + self._STRUCT.pack(
                self.intf_type & 0xFFFF,
                1 if self.has_bridge else 0,
                self.packet_errors & 0xFFFFFFFF,
                self.transmitted_packets & 0xFFFFFFFF,
                self.mac_throughput_mbps & 0xFFFF,
                self.link_availability_pct_x100 & 0xFFFF,
                self.phy_rate_mbps & 0xFFFF,
            )
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> TransmitterLinkEntry:
        if offset + cls.SIZE > len(payload):
            raise ValueError(
                f"truncated transmitter link entry: need {cls.SIZE}, "
                f"have {len(payload) - offset}"
            )
        local = parse_mac(payload, offset)
        neighbor = parse_mac(payload, offset + MAC_LEN)
        (
            intf_type,
            bridge_flag,
            pkt_err,
            tx_pkt,
            mac_tput,
            link_avail,
            phy_rate,
        ) = cls._STRUCT.unpack_from(payload, offset + 2 * MAC_LEN)
        return cls(
            local_interface_mac=local,
            neighbor_interface_mac=neighbor,
            intf_type=intf_type,
            has_bridge=bool(bridge_flag & 0x01),
            packet_errors=pkt_err,
            transmitted_packets=tx_pkt,
            mac_throughput_mbps=mac_tput,
            link_availability_pct_x100=link_avail,
            phy_rate_mbps=phy_rate,
        )


@dataclass(slots=True)
class TransmitterLinkMetric:
    TLV_TYPE: ClassVar[int] = 0x09
    TLV_NAME: ClassVar[str] = "Transmitter link metric"

    responder_al_mac: bytes
    neighbor_al_mac: bytes
    links: list[TransmitterLinkEntry] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.responder_al_mac) != MAC_LEN:
            raise ValueError("responder AL MAC must be 6 bytes")
        if len(self.neighbor_al_mac) != MAC_LEN:
            raise ValueError("neighbor AL MAC must be 6 bytes")

    def to_payload(self) -> bytes:
        return (
            bytes(self.responder_al_mac)
            + bytes(self.neighbor_al_mac)
            + b"".join(link.to_bytes() for link in self.links)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> TransmitterLinkMetric:
        if len(payload) < 2 * MAC_LEN:
            raise ValueError("Transmitter link metric TLV missing AL MAC fields")
        rest = len(payload) - 2 * MAC_LEN
        if rest % TransmitterLinkEntry.SIZE != 0:
            raise ValueError(
                f"Transmitter link metric trailing bytes don't align: "
                f"{rest} % {TransmitterLinkEntry.SIZE} != 0"
            )
        links = [
            TransmitterLinkEntry.parse(payload, 2 * MAC_LEN + i * TransmitterLinkEntry.SIZE)
            for i in range(rest // TransmitterLinkEntry.SIZE)
        ]
        return cls(
            responder_al_mac=parse_mac(payload),
            neighbor_al_mac=parse_mac(payload, MAC_LEN),
            links=links,
        )


register_typed(TransmitterLinkMetric, spec_ref="IEEE 1905.1-2013 §17.2.9")


# ---------------------------------------------------------------------------
# 0x0A Receiver link metric — §17.2.10
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ReceiverLinkEntry:
    """One per-link metric set in a Receiver link metric TLV (23 bytes)."""

    local_interface_mac: bytes
    neighbor_interface_mac: bytes
    intf_type: int
    packet_errors: int
    packets_received: int
    rssi_db: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(">HIIB")
    SIZE: ClassVar[int] = 2 * MAC_LEN + _STRUCT.size

    def to_bytes(self) -> bytes:
        return (
            bytes(self.local_interface_mac)
            + bytes(self.neighbor_interface_mac)
            + self._STRUCT.pack(
                self.intf_type & 0xFFFF,
                self.packet_errors & 0xFFFFFFFF,
                self.packets_received & 0xFFFFFFFF,
                self.rssi_db & 0xFF,
            )
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> ReceiverLinkEntry:
        if offset + cls.SIZE > len(payload):
            raise ValueError(
                f"truncated receiver link entry: need {cls.SIZE}, "
                f"have {len(payload) - offset}"
            )
        local = parse_mac(payload, offset)
        neighbor = parse_mac(payload, offset + MAC_LEN)
        intf_type, pkt_err, rx_pkt, rssi = cls._STRUCT.unpack_from(
            payload, offset + 2 * MAC_LEN
        )
        return cls(
            local_interface_mac=local,
            neighbor_interface_mac=neighbor,
            intf_type=intf_type,
            packet_errors=pkt_err,
            packets_received=rx_pkt,
            rssi_db=rssi,
        )


@dataclass(slots=True)
class ReceiverLinkMetric:
    TLV_TYPE: ClassVar[int] = 0x0A
    TLV_NAME: ClassVar[str] = "Receiver link metric"

    responder_al_mac: bytes
    neighbor_al_mac: bytes
    links: list[ReceiverLinkEntry] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.responder_al_mac) != MAC_LEN:
            raise ValueError("responder AL MAC must be 6 bytes")
        if len(self.neighbor_al_mac) != MAC_LEN:
            raise ValueError("neighbor AL MAC must be 6 bytes")

    def to_payload(self) -> bytes:
        return (
            bytes(self.responder_al_mac)
            + bytes(self.neighbor_al_mac)
            + b"".join(link.to_bytes() for link in self.links)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> ReceiverLinkMetric:
        if len(payload) < 2 * MAC_LEN:
            raise ValueError("Receiver link metric TLV missing AL MAC fields")
        rest = len(payload) - 2 * MAC_LEN
        if rest % ReceiverLinkEntry.SIZE != 0:
            raise ValueError(
                f"Receiver link metric trailing bytes don't align: "
                f"{rest} % {ReceiverLinkEntry.SIZE} != 0"
            )
        links = [
            ReceiverLinkEntry.parse(payload, 2 * MAC_LEN + i * ReceiverLinkEntry.SIZE)
            for i in range(rest // ReceiverLinkEntry.SIZE)
        ]
        return cls(
            responder_al_mac=parse_mac(payload),
            neighbor_al_mac=parse_mac(payload, MAC_LEN),
            links=links,
        )


register_typed(ReceiverLinkMetric, spec_ref="IEEE 1905.1-2013 §17.2.10")


# ---------------------------------------------------------------------------
# 0x11 WSC — §17.2.17 (opaque Wi-Fi Simple Config M1/M2 frame).
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class WscFrame:
    TLV_TYPE: ClassVar[int] = 0x11
    TLV_NAME: ClassVar[str] = "WSC frame"

    #: Raw WSC attributes (M1 or M2) — opaque to the 1905 layer.
    wsc_payload: bytes

    def to_payload(self) -> bytes:
        return bytes(self.wsc_payload)

    @classmethod
    def from_payload(cls, payload: bytes) -> WscFrame:
        return cls(wsc_payload=bytes(payload))


register_typed(WscFrame, spec_ref="IEEE 1905.1-2013 §17.2.17")


# ---------------------------------------------------------------------------
# 0x12 Push button event notification — §17.2.18
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class PbeMediaType:
    """One (media type, media-specific info) pair in a PBE notification."""

    media_type: int
    media_specific: bytes = b""

    _HEADER: ClassVar[struct.Struct] = struct.Struct(">HB")

    def __post_init__(self) -> None:
        if not 0 <= self.media_type <= 0xFFFF:
            raise ValueError("media_type out of range")
        if len(self.media_specific) > 0xFF:
            raise ValueError("media_specific exceeds 8-bit length field")

    def to_bytes(self) -> bytes:
        return self._HEADER.pack(self.media_type, len(self.media_specific)) + bytes(
            self.media_specific
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[PbeMediaType, int]:
        if offset + cls._HEADER.size > len(payload):
            raise ValueError("truncated PBE media-type header")
        media_type, ms_len = cls._HEADER.unpack_from(payload, offset)
        start = offset + cls._HEADER.size
        end = start + ms_len
        if end > len(payload):
            raise ValueError("truncated PBE media-specific bytes")
        return cls(media_type=media_type, media_specific=bytes(payload[start:end])), end - offset


@dataclass(slots=True)
class PushButtonEventNotification:
    TLV_TYPE: ClassVar[int] = 0x12
    TLV_NAME: ClassVar[str] = "Push button event notification"

    media_types: list[PbeMediaType] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.media_types) > 0xFF:
            raise ValueError("too many media types (8-bit count)")

    def to_payload(self) -> bytes:
        return bytes([len(self.media_types)]) + b"".join(m.to_bytes() for m in self.media_types)

    @classmethod
    def from_payload(cls, payload: bytes) -> PushButtonEventNotification:
        if not payload:
            raise ValueError("Push button event notification needs at least a count byte")
        count = payload[0]
        offset = 1
        items: list[PbeMediaType] = []
        for _ in range(count):
            item, consumed = PbeMediaType.parse(payload, offset)
            items.append(item)
            offset += consumed
        if offset != len(payload):
            raise ValueError(
                f"Push button event notification has {len(payload) - offset} trailing bytes"
            )
        return cls(media_types=items)


register_typed(PushButtonEventNotification, spec_ref="IEEE 1905.1-2013 §17.2.18")


# ---------------------------------------------------------------------------
# 0x13 Push button join notification — §17.2.19
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class PushButtonJoinNotification:
    TLV_TYPE: ClassVar[int] = 0x13
    TLV_NAME: ClassVar[str] = "Push button join notification"

    notifier_al_mac: bytes
    notifier_mid: int
    transmitter_mac: bytes
    joining_interface_mac: bytes

    _MID: ClassVar[struct.Struct] = struct.Struct(">H")
    SIZE: ClassVar[int] = 3 * MAC_LEN + _MID.size

    def __post_init__(self) -> None:
        for label, m in (
            ("notifier_al_mac", self.notifier_al_mac),
            ("transmitter_mac", self.transmitter_mac),
            ("joining_interface_mac", self.joining_interface_mac),
        ):
            if len(m) != MAC_LEN:
                raise ValueError(f"{label} must be {MAC_LEN} bytes")

    def to_payload(self) -> bytes:
        return (
            bytes(self.notifier_al_mac)
            + self._MID.pack(self.notifier_mid & 0xFFFF)
            + bytes(self.transmitter_mac)
            + bytes(self.joining_interface_mac)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> PushButtonJoinNotification:
        if len(payload) != cls.SIZE:
            raise ValueError(
                f"Push button join notification TLV must be {cls.SIZE} bytes, got {len(payload)}"
            )
        notifier = parse_mac(payload, 0)
        (mid,) = cls._MID.unpack_from(payload, MAC_LEN)
        transmitter = parse_mac(payload, MAC_LEN + cls._MID.size)
        joining = parse_mac(payload, 2 * MAC_LEN + cls._MID.size)
        return cls(
            notifier_al_mac=notifier,
            notifier_mid=mid,
            transmitter_mac=transmitter,
            joining_interface_mac=joining,
        )


register_typed(PushButtonJoinNotification, spec_ref="IEEE 1905.1-2013 §17.2.19")


# ---------------------------------------------------------------------------
# 0x14 Generic PHY device information — §17.2.20
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class GenericPhyInterface:
    interface_mac: bytes
    phy_oui: bytes  # 3 bytes
    phy_variant_index: int
    phy_variant_name: str  # 32 chars, NUL-padded ASCII
    description_url: bytes = b""
    media_specific: bytes = b""

    _VARIANT_NAME_LEN: ClassVar[int] = 32

    def __post_init__(self) -> None:
        if len(self.interface_mac) != MAC_LEN:
            raise ValueError("interface MAC must be 6 bytes")
        if len(self.phy_oui) != 3:
            raise ValueError("PHY OUI must be 3 bytes")
        if not 0 <= self.phy_variant_index <= 0xFF:
            raise ValueError("phy_variant_index out of range")
        if len(self.description_url) > 0xFF:
            raise ValueError("description_url too long (8-bit length field)")
        if len(self.media_specific) > 0xFF:
            raise ValueError("media_specific too long (8-bit length field)")

    def to_bytes(self) -> bytes:
        return (
            bytes(self.interface_mac)
            + bytes(self.phy_oui)
            + bytes([self.phy_variant_index & 0xFF])
            + encode_padded_ascii(self.phy_variant_name, self._VARIANT_NAME_LEN)
            + bytes([len(self.description_url)])
            + bytes(self.description_url)
            + bytes([len(self.media_specific)])
            + bytes(self.media_specific)
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[GenericPhyInterface, int]:
        start = offset
        mac = parse_mac(payload, offset)
        offset += MAC_LEN
        if offset + 3 + 1 + cls._VARIANT_NAME_LEN + 1 + 1 > len(payload):
            raise ValueError("truncated Generic PHY interface entry")
        oui = bytes(payload[offset : offset + 3])
        offset += 3
        variant_index = payload[offset]
        offset += 1
        variant_name = parse_padded_ascii(payload, offset, cls._VARIANT_NAME_LEN)
        offset += cls._VARIANT_NAME_LEN
        url_len = payload[offset]
        offset += 1
        if offset + url_len > len(payload):
            raise ValueError("truncated Generic PHY description URL")
        url = bytes(payload[offset : offset + url_len])
        offset += url_len
        if offset + 1 > len(payload):
            raise ValueError("truncated Generic PHY media-specific length")
        ms_len = payload[offset]
        offset += 1
        if offset + ms_len > len(payload):
            raise ValueError("truncated Generic PHY media-specific info")
        ms = bytes(payload[offset : offset + ms_len])
        offset += ms_len
        return (
            cls(
                interface_mac=mac,
                phy_oui=oui,
                phy_variant_index=variant_index,
                phy_variant_name=variant_name,
                description_url=url,
                media_specific=ms,
            ),
            offset - start,
        )


@dataclass(slots=True)
class GenericPhyDeviceInformation:
    TLV_TYPE: ClassVar[int] = 0x14
    TLV_NAME: ClassVar[str] = "Generic PHY device information"

    al_mac: bytes
    interfaces: list[GenericPhyInterface] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.al_mac) != MAC_LEN:
            raise ValueError("AL MAC must be 6 bytes")
        if len(self.interfaces) > 0xFF:
            raise ValueError("too many interfaces (8-bit count)")

    def to_payload(self) -> bytes:
        return (
            bytes(self.al_mac)
            + bytes([len(self.interfaces)])
            + b"".join(iface.to_bytes() for iface in self.interfaces)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> GenericPhyDeviceInformation:
        if len(payload) < MAC_LEN + 1:
            raise ValueError("Generic PHY device information TLV too short")
        al_mac = parse_mac(payload)
        count = payload[MAC_LEN]
        offset = MAC_LEN + 1
        ifaces: list[GenericPhyInterface] = []
        for _ in range(count):
            iface, consumed = GenericPhyInterface.parse(payload, offset)
            ifaces.append(iface)
            offset += consumed
        if offset != len(payload):
            raise ValueError(
                f"Generic PHY device information has {len(payload) - offset} trailing bytes"
            )
        return cls(al_mac=al_mac, interfaces=ifaces)


register_typed(GenericPhyDeviceInformation, spec_ref="IEEE 1905.1-2013 §17.2.20")


# ---------------------------------------------------------------------------
# 0x15 Device identification — §17.2.21
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class DeviceIdentification:
    TLV_TYPE: ClassVar[int] = 0x15
    TLV_NAME: ClassVar[str] = "Device identification"

    friendly_name: str
    manufacturer_name: str
    manufacturer_model: str

    _FIELD_LEN: ClassVar[int] = 64
    SIZE: ClassVar[int] = 3 * _FIELD_LEN

    def __post_init__(self) -> None:
        for label, value in (
            ("friendly_name", self.friendly_name),
            ("manufacturer_name", self.manufacturer_name),
            ("manufacturer_model", self.manufacturer_model),
        ):
            if len(value.encode("latin-1")) > self._FIELD_LEN:
                raise ValueError(
                    f"{label} exceeds {self._FIELD_LEN}-byte field"
                )

    def to_payload(self) -> bytes:
        return (
            encode_padded_ascii(self.friendly_name, self._FIELD_LEN)
            + encode_padded_ascii(self.manufacturer_name, self._FIELD_LEN)
            + encode_padded_ascii(self.manufacturer_model, self._FIELD_LEN)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> DeviceIdentification:
        if len(payload) != cls.SIZE:
            raise ValueError(
                f"Device identification TLV must be {cls.SIZE} bytes, got {len(payload)}"
            )
        return cls(
            friendly_name=parse_padded_ascii(payload, 0, cls._FIELD_LEN),
            manufacturer_name=parse_padded_ascii(payload, cls._FIELD_LEN, cls._FIELD_LEN),
            manufacturer_model=parse_padded_ascii(payload, 2 * cls._FIELD_LEN, cls._FIELD_LEN),
        )


register_typed(DeviceIdentification, spec_ref="IEEE 1905.1-2013 §17.2.21")


# ---------------------------------------------------------------------------
# 0x16 Control URL — §17.2.22
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ControlUrl:
    TLV_TYPE: ClassVar[int] = 0x16
    TLV_NAME: ClassVar[str] = "Control URL"

    url: str

    def to_payload(self) -> bytes:
        return self.url.encode("ascii")

    @classmethod
    def from_payload(cls, payload: bytes) -> ControlUrl:
        return cls(url=bytes(payload).decode("ascii"))


register_typed(ControlUrl, spec_ref="IEEE 1905.1-2013 §17.2.22")


# ---------------------------------------------------------------------------
# 0x17 IPv4 — §17.2.23
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Ipv4Address:
    #: 0=unknown, 1=DHCP, 2=static, 3=auto-IP.
    address_type: int
    address: str  # dotted-quad
    dhcp_server: str  # dotted-quad (may be 0.0.0.0)

    SIZE: ClassVar[int] = 1 + IPV4_LEN + IPV4_LEN

    def to_bytes(self) -> bytes:
        return bytes([self.address_type & 0xFF]) + encode_ipv4(self.address) + encode_ipv4(
            self.dhcp_server
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> Ipv4Address:
        if offset + cls.SIZE > len(payload):
            raise ValueError("truncated IPv4 address entry")
        return cls(
            address_type=payload[offset],
            address=parse_ipv4(payload, offset + 1),
            dhcp_server=parse_ipv4(payload, offset + 1 + IPV4_LEN),
        )


@dataclass(slots=True)
class Ipv4Entry:
    interface_mac: bytes
    addresses: list[Ipv4Address] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.interface_mac) != MAC_LEN:
            raise ValueError("interface MAC must be 6 bytes")
        if len(self.addresses) > 0xFF:
            raise ValueError("too many IPv4 addresses (8-bit count)")

    def to_bytes(self) -> bytes:
        return (
            bytes(self.interface_mac)
            + bytes([len(self.addresses)])
            + b"".join(a.to_bytes() for a in self.addresses)
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[Ipv4Entry, int]:
        start = offset
        if offset + MAC_LEN + 1 > len(payload):
            raise ValueError("truncated IPv4 entry header")
        mac = parse_mac(payload, offset)
        offset += MAC_LEN
        count = payload[offset]
        offset += 1
        addrs = [Ipv4Address.parse(payload, offset + i * Ipv4Address.SIZE) for i in range(count)]
        offset += count * Ipv4Address.SIZE
        if offset > len(payload):
            raise ValueError("truncated IPv4 entry body")
        return cls(interface_mac=mac, addresses=addrs), offset - start


@dataclass(slots=True)
class IPv4:
    TLV_TYPE: ClassVar[int] = 0x17
    TLV_NAME: ClassVar[str] = "IPv4"

    entries: list[Ipv4Entry] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.entries) > 0xFF:
            raise ValueError("too many IPv4 entries (8-bit count)")

    def to_payload(self) -> bytes:
        return bytes([len(self.entries)]) + b"".join(e.to_bytes() for e in self.entries)

    @classmethod
    def from_payload(cls, payload: bytes) -> IPv4:
        if not payload:
            raise ValueError("IPv4 TLV needs at least a count byte")
        count = payload[0]
        offset = 1
        entries: list[Ipv4Entry] = []
        for _ in range(count):
            entry, consumed = Ipv4Entry.parse(payload, offset)
            entries.append(entry)
            offset += consumed
        if offset != len(payload):
            raise ValueError(f"IPv4 TLV has {len(payload) - offset} trailing bytes")
        return cls(entries=entries)


register_typed(IPv4, spec_ref="IEEE 1905.1-2013 §17.2.23")


# ---------------------------------------------------------------------------
# 0x18 IPv6 — §17.2.24
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Ipv6Address:
    #: 0=unknown, 1=DHCPv6, 2=static, 3=SLAAC.
    address_type: int
    address: str
    origin: str  # source of the address (e.g. DHCPv6 server)

    SIZE: ClassVar[int] = 1 + IPV6_LEN + IPV6_LEN

    def to_bytes(self) -> bytes:
        return (
            bytes([self.address_type & 0xFF])
            + encode_ipv6(self.address)
            + encode_ipv6(self.origin)
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> Ipv6Address:
        if offset + cls.SIZE > len(payload):
            raise ValueError("truncated IPv6 address entry")
        return cls(
            address_type=payload[offset],
            address=parse_ipv6(payload, offset + 1),
            origin=parse_ipv6(payload, offset + 1 + IPV6_LEN),
        )


@dataclass(slots=True)
class Ipv6Entry:
    interface_mac: bytes
    link_local: str
    addresses: list[Ipv6Address] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.interface_mac) != MAC_LEN:
            raise ValueError("interface MAC must be 6 bytes")
        if len(self.addresses) > 0xFF:
            raise ValueError("too many IPv6 addresses (8-bit count)")

    def to_bytes(self) -> bytes:
        return (
            bytes(self.interface_mac)
            + encode_ipv6(self.link_local)
            + bytes([len(self.addresses)])
            + b"".join(a.to_bytes() for a in self.addresses)
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[Ipv6Entry, int]:
        start = offset
        header = MAC_LEN + IPV6_LEN + 1
        if offset + header > len(payload):
            raise ValueError("truncated IPv6 entry header")
        mac = parse_mac(payload, offset)
        offset += MAC_LEN
        link_local = parse_ipv6(payload, offset)
        offset += IPV6_LEN
        count = payload[offset]
        offset += 1
        addrs = [Ipv6Address.parse(payload, offset + i * Ipv6Address.SIZE) for i in range(count)]
        offset += count * Ipv6Address.SIZE
        if offset > len(payload):
            raise ValueError("truncated IPv6 entry body")
        return (
            cls(interface_mac=mac, link_local=link_local, addresses=addrs),
            offset - start,
        )


@dataclass(slots=True)
class IPv6:
    TLV_TYPE: ClassVar[int] = 0x18
    TLV_NAME: ClassVar[str] = "IPv6"

    entries: list[Ipv6Entry] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.entries) > 0xFF:
            raise ValueError("too many IPv6 entries (8-bit count)")

    def to_payload(self) -> bytes:
        return bytes([len(self.entries)]) + b"".join(e.to_bytes() for e in self.entries)

    @classmethod
    def from_payload(cls, payload: bytes) -> IPv6:
        if not payload:
            raise ValueError("IPv6 TLV needs at least a count byte")
        count = payload[0]
        offset = 1
        entries: list[Ipv6Entry] = []
        for _ in range(count):
            entry, consumed = Ipv6Entry.parse(payload, offset)
            entries.append(entry)
            offset += consumed
        if offset != len(payload):
            raise ValueError(f"IPv6 TLV has {len(payload) - offset} trailing bytes")
        return cls(entries=entries)


register_typed(IPv6, spec_ref="IEEE 1905.1-2013 §17.2.24")


# ---------------------------------------------------------------------------
# 0x19 Generic PHY event notification — §17.2.25
# Interface-keyed opaque event blobs.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class GenericPhyEventEntry:
    interface_mac: bytes
    event_data: bytes

    def __post_init__(self) -> None:
        if len(self.interface_mac) != MAC_LEN:
            raise ValueError("interface MAC must be 6 bytes")
        if len(self.event_data) > 0xFF:
            raise ValueError("event_data exceeds 8-bit length field")

    def to_bytes(self) -> bytes:
        return (
            bytes(self.interface_mac)
            + bytes([len(self.event_data)])
            + bytes(self.event_data)
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[GenericPhyEventEntry, int]:
        if offset + MAC_LEN + 1 > len(payload):
            raise ValueError("truncated Generic PHY event entry header")
        mac = parse_mac(payload, offset)
        length = payload[offset + MAC_LEN]
        start = offset + MAC_LEN + 1
        end = start + length
        if end > len(payload):
            raise ValueError("truncated Generic PHY event data")
        return cls(interface_mac=mac, event_data=bytes(payload[start:end])), end - offset


@dataclass(slots=True)
class GenericPhyEventNotification:
    TLV_TYPE: ClassVar[int] = 0x19
    TLV_NAME: ClassVar[str] = "Generic PHY event notification"

    interfaces: list[GenericPhyEventEntry] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.interfaces) > 0xFF:
            raise ValueError("too many event entries (8-bit count)")

    def to_payload(self) -> bytes:
        return bytes([len(self.interfaces)]) + b"".join(i.to_bytes() for i in self.interfaces)

    @classmethod
    def from_payload(cls, payload: bytes) -> GenericPhyEventNotification:
        if not payload:
            raise ValueError("Generic PHY event notification TLV needs a count byte")
        count = payload[0]
        offset = 1
        items: list[GenericPhyEventEntry] = []
        for _ in range(count):
            item, consumed = GenericPhyEventEntry.parse(payload, offset)
            items.append(item)
            offset += consumed
        if offset != len(payload):
            raise ValueError(
                f"Generic PHY event notification has {len(payload) - offset} trailing bytes"
            )
        return cls(interfaces=items)


register_typed(GenericPhyEventNotification, spec_ref="IEEE 1905.1-2013 §17.2.25")


# ---------------------------------------------------------------------------
# 0x1B Power off interface — §17.2.27 (interface list).
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class PowerOffInterfaceEntry:
    interface_mac: bytes
    media_type: int
    phy_oui: bytes
    phy_variant_index: int
    media_specific: bytes = b""

    _STATIC: ClassVar[struct.Struct] = struct.Struct(">H3sBB")  # media_type, oui, variant, ms_len
    HEADER_SIZE: ClassVar[int] = MAC_LEN + _STATIC.size

    def __post_init__(self) -> None:
        if len(self.interface_mac) != MAC_LEN:
            raise ValueError("interface MAC must be 6 bytes")
        if len(self.phy_oui) != 3:
            raise ValueError("phy_oui must be 3 bytes (zeros if media isn't generic PHY)")
        if len(self.media_specific) > 0xFF:
            raise ValueError("media_specific too long (8-bit length field)")

    def to_bytes(self) -> bytes:
        header = self._STATIC.pack(
            self.media_type & 0xFFFF,
            bytes(self.phy_oui),
            self.phy_variant_index & 0xFF,
            len(self.media_specific),
        )
        return bytes(self.interface_mac) + header + bytes(self.media_specific)

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[PowerOffInterfaceEntry, int]:
        if offset + cls.HEADER_SIZE > len(payload):
            raise ValueError("truncated power-off interface entry header")
        mac = parse_mac(payload, offset)
        media_type, oui, variant, ms_len = cls._STATIC.unpack_from(payload, offset + MAC_LEN)
        start = offset + cls.HEADER_SIZE
        end = start + ms_len
        if end > len(payload):
            raise ValueError("truncated power-off interface media-specific bytes")
        return (
            cls(
                interface_mac=mac,
                media_type=media_type,
                phy_oui=oui,
                phy_variant_index=variant,
                media_specific=bytes(payload[start:end]),
            ),
            end - offset,
        )


@dataclass(slots=True)
class PowerOffInterface:
    TLV_TYPE: ClassVar[int] = 0x1B
    TLV_NAME: ClassVar[str] = "Power off interface"

    interfaces: list[PowerOffInterfaceEntry] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.interfaces) > 0xFF:
            raise ValueError("too many interfaces (8-bit count)")

    def to_payload(self) -> bytes:
        return bytes([len(self.interfaces)]) + b"".join(i.to_bytes() for i in self.interfaces)

    @classmethod
    def from_payload(cls, payload: bytes) -> PowerOffInterface:
        if not payload:
            raise ValueError("Power off interface TLV needs a count byte")
        count = payload[0]
        offset = 1
        items: list[PowerOffInterfaceEntry] = []
        for _ in range(count):
            item, consumed = PowerOffInterfaceEntry.parse(payload, offset)
            items.append(item)
            offset += consumed
        if offset != len(payload):
            raise ValueError(
                f"Power off interface TLV has {len(payload) - offset} trailing bytes"
            )
        return cls(interfaces=items)


register_typed(PowerOffInterface, spec_ref="IEEE 1905.1-2013 §17.2.27")


# ---------------------------------------------------------------------------
# 0x1C Interface power change information — §17.2.28
# 0x1D Interface power change status — §17.2.29
# Same shape; one carries requested state, the other the result code.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class InterfacePowerChangeEntry:
    interface_mac: bytes
    state: int  # request: 0=on / 1=power save / 2=off ; status: 0=ok / 1=no change / 2=alternate

    SIZE: ClassVar[int] = MAC_LEN + 1

    def __post_init__(self) -> None:
        if len(self.interface_mac) != MAC_LEN:
            raise ValueError("interface MAC must be 6 bytes")

    def to_bytes(self) -> bytes:
        return bytes(self.interface_mac) + bytes([self.state & 0xFF])

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> InterfacePowerChangeEntry:
        if offset + cls.SIZE > len(payload):
            raise ValueError("truncated interface power change entry")
        return cls(
            interface_mac=parse_mac(payload, offset),
            state=payload[offset + MAC_LEN],
        )


def _parse_power_change_list(payload: bytes) -> list[InterfacePowerChangeEntry]:
    if not payload:
        raise ValueError("interface power change TLV needs a count byte")
    count = payload[0]
    expected = 1 + count * InterfacePowerChangeEntry.SIZE
    if len(payload) != expected:
        raise ValueError(
            f"interface power change TLV length mismatch: expected {expected}, got {len(payload)}"
        )
    return [
        InterfacePowerChangeEntry.parse(payload, 1 + i * InterfacePowerChangeEntry.SIZE)
        for i in range(count)
    ]


def _encode_power_change_list(entries: list[InterfacePowerChangeEntry]) -> bytes:
    if len(entries) > 0xFF:
        raise ValueError("too many entries (8-bit count)")
    return bytes([len(entries)]) + b"".join(e.to_bytes() for e in entries)


@dataclass(slots=True)
class InterfacePowerChangeInformation:
    TLV_TYPE: ClassVar[int] = 0x1C
    TLV_NAME: ClassVar[str] = "Interface power change information"

    entries: list[InterfacePowerChangeEntry] = field(default_factory=list)

    def to_payload(self) -> bytes:
        return _encode_power_change_list(self.entries)

    @classmethod
    def from_payload(cls, payload: bytes) -> InterfacePowerChangeInformation:
        return cls(entries=_parse_power_change_list(payload))


register_typed(InterfacePowerChangeInformation, spec_ref="IEEE 1905.1-2013 §17.2.28")


@dataclass(slots=True)
class InterfacePowerChangeStatus:
    TLV_TYPE: ClassVar[int] = 0x1D
    TLV_NAME: ClassVar[str] = "Interface power change status"

    entries: list[InterfacePowerChangeEntry] = field(default_factory=list)

    def to_payload(self) -> bytes:
        return _encode_power_change_list(self.entries)

    @classmethod
    def from_payload(cls, payload: bytes) -> InterfacePowerChangeStatus:
        return cls(entries=_parse_power_change_list(payload))


register_typed(InterfacePowerChangeStatus, spec_ref="IEEE 1905.1-2013 §17.2.29")


# ---------------------------------------------------------------------------
# 0x1E L2 neighbor device — §17.2.30
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class L2Neighbor:
    """One L2 neighbor (with optional "behind" MACs)."""

    neighbor_mac: bytes
    behind_macs: list[bytes] = field(default_factory=list)

    _COUNT: ClassVar[struct.Struct] = struct.Struct(">H")

    def __post_init__(self) -> None:
        if len(self.neighbor_mac) != MAC_LEN:
            raise ValueError("neighbor MAC must be 6 bytes")
        for m in self.behind_macs:
            if len(m) != MAC_LEN:
                raise ValueError("behind MAC must be 6 bytes")

    def to_bytes(self) -> bytes:
        return (
            bytes(self.neighbor_mac)
            + self._COUNT.pack(len(self.behind_macs) & 0xFFFF)
            + b"".join(bytes(m) for m in self.behind_macs)
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[L2Neighbor, int]:
        if offset + MAC_LEN + cls._COUNT.size > len(payload):
            raise ValueError("truncated L2 neighbor header")
        mac = parse_mac(payload, offset)
        (count,) = cls._COUNT.unpack_from(payload, offset + MAC_LEN)
        start = offset + MAC_LEN + cls._COUNT.size
        end = start + count * MAC_LEN
        if end > len(payload):
            raise ValueError(
                f"truncated L2 behind-MAC list: need {count * MAC_LEN}, "
                f"have {len(payload) - start}"
            )
        behind = [
            bytes(payload[start + i * MAC_LEN : start + (i + 1) * MAC_LEN]) for i in range(count)
        ]
        return cls(neighbor_mac=mac, behind_macs=behind), end - offset


@dataclass(slots=True)
class L2LocalInterface:
    """One local interface with a list of L2 neighbors visible through it."""

    local_interface_mac: bytes
    neighbors: list[L2Neighbor] = field(default_factory=list)

    _COUNT: ClassVar[struct.Struct] = struct.Struct(">H")

    def __post_init__(self) -> None:
        if len(self.local_interface_mac) != MAC_LEN:
            raise ValueError("local interface MAC must be 6 bytes")

    def to_bytes(self) -> bytes:
        return (
            bytes(self.local_interface_mac)
            + self._COUNT.pack(len(self.neighbors) & 0xFFFF)
            + b"".join(n.to_bytes() for n in self.neighbors)
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[L2LocalInterface, int]:
        start = offset
        if offset + MAC_LEN + cls._COUNT.size > len(payload):
            raise ValueError("truncated L2 local interface header")
        mac = parse_mac(payload, offset)
        offset += MAC_LEN
        (count,) = cls._COUNT.unpack_from(payload, offset)
        offset += cls._COUNT.size
        neighbors: list[L2Neighbor] = []
        for _ in range(count):
            n, consumed = L2Neighbor.parse(payload, offset)
            neighbors.append(n)
            offset += consumed
        return (
            cls(local_interface_mac=mac, neighbors=neighbors),
            offset - start,
        )


@dataclass(slots=True)
class L2NeighborDevice:
    TLV_TYPE: ClassVar[int] = 0x1E
    TLV_NAME: ClassVar[str] = "L2 neighbor device"

    local_interfaces: list[L2LocalInterface] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.local_interfaces) > 0xFF:
            raise ValueError("too many local interfaces (8-bit count)")

    def to_payload(self) -> bytes:
        return bytes([len(self.local_interfaces)]) + b"".join(
            i.to_bytes() for i in self.local_interfaces
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> L2NeighborDevice:
        if not payload:
            raise ValueError("L2 neighbor device TLV needs a count byte")
        count = payload[0]
        offset = 1
        items: list[L2LocalInterface] = []
        for _ in range(count):
            item, consumed = L2LocalInterface.parse(payload, offset)
            items.append(item)
            offset += consumed
        if offset != len(payload):
            raise ValueError(
                f"L2 neighbor device TLV has {len(payload) - offset} trailing bytes"
            )
        return cls(local_interfaces=items)


register_typed(L2NeighborDevice, spec_ref="IEEE 1905.1-2013 §17.2.30")
