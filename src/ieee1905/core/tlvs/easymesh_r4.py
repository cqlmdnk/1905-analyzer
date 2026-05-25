# SPDX-License-Identifier: GPL-2.0-or-later
"""Wi-Fi EasyMesh R4 TLV implementations.

Spec: Wi-Fi Alliance *Multi-AP Specification* v4.0 §17.2.x.

R4 adds Wi-Fi 6 / 7 capability advertisement, EHT operations (the
PHY/MAC parameters for IEEE 802.11be), Multi-Link Device (MLD)
configuration on agents, backhaul STAs and associated STAs, plus
affiliated AP/STA metrics and a TID-to-link mapping policy.

The capability TLVs in this family carry deeply bit-packed feature
fields. We expose every byte/bit through named accessors and keep the
underlying raw bytes round-trippable. The fine-grained bit semantics
(e.g. which bit means "MLO emulation supported") come from the Wi-Fi
7 / 802.11be spec — interpretation can be refined later as vendors
ship the bits.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import ClassVar

from ieee1905.core.tlvs._helpers import MAC_LEN, parse_mac, register_typed

BSSID_LEN = 6


# ---------------------------------------------------------------------------
# 0xAB AP Wi-Fi 6 Capabilities — §17.2.45 (slotted into R4 alongside EHT
# because Multi-AP organises R3+R4 6E/7 capability TLVs together; R2 left
# 0xAB free).
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class HeRoleCapabilities:
    """Per-role HE/Wi-Fi 6 capability sub-record (AP, bSTA or fSTA)."""

    role: int  # 0=AP, 1=bSTA, 2=fSTA
    he_mcs_length: int  # u8
    he_mcs: bytes  # length = he_mcs_length
    he_flags_1: int  # bit-packed feature flags byte 1
    he_flags_2: int  # bit-packed feature flags byte 2

    def to_bytes(self) -> bytes:
        return (
            bytes([self.role & 0xFF, self.he_mcs_length & 0xFF])
            + bytes(self.he_mcs)
            + bytes([self.he_flags_1 & 0xFF, self.he_flags_2 & 0xFF])
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[HeRoleCapabilities, int]:
        start = offset
        if offset + 2 > len(payload):
            raise ValueError("truncated HE role-capabilities header")
        role = payload[offset]
        mcs_len = payload[offset + 1]
        offset += 2
        if offset + mcs_len + 2 > len(payload):
            raise ValueError("truncated HE role-capabilities body")
        mcs = bytes(payload[offset : offset + mcs_len])
        offset += mcs_len
        f1 = payload[offset]
        f2 = payload[offset + 1]
        offset += 2
        return (
            cls(role=role, he_mcs_length=mcs_len, he_mcs=mcs, he_flags_1=f1, he_flags_2=f2),
            offset - start,
        )


@dataclass(slots=True)
class ApWifi6Capabilities:
    TLV_TYPE: ClassVar[int] = 0xAB
    TLV_NAME: ClassVar[str] = "AP Wi-Fi 6 capabilities"

    radio_id: bytes
    roles: list[HeRoleCapabilities] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.radio_id) != MAC_LEN:
            raise ValueError("radio_id must be 6 bytes")
        if len(self.roles) > 0xFF:
            raise ValueError("too many roles (8-bit count)")

    def to_payload(self) -> bytes:
        return (
            bytes(self.radio_id)
            + bytes([len(self.roles)])
            + b"".join(r.to_bytes() for r in self.roles)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> ApWifi6Capabilities:
        if len(payload) < MAC_LEN + 1:
            raise ValueError("AP Wi-Fi 6 capabilities TLV too short")
        rid = parse_mac(payload)
        count = payload[MAC_LEN]
        offset = MAC_LEN + 1
        roles: list[HeRoleCapabilities] = []
        for _ in range(count):
            r, consumed = HeRoleCapabilities.parse(payload, offset)
            roles.append(r)
            offset += consumed
        if offset != len(payload):
            raise ValueError(
                f"AP Wi-Fi 6 capabilities has {len(payload) - offset} trailing bytes"
            )
        return cls(radio_id=rid, roles=roles)


register_typed(ApWifi6Capabilities, spec_ref="Multi-AP v4.0 §17.2.45")


# ---------------------------------------------------------------------------
# 0xE0 AP EHT Operations — §17.2.90 (per-radio Wi-Fi 7 EHT operating parameters)
# 0xE8 EHT Operations — §17.2.95 (network-wide EHT operations)
# Wire format mirrors IEEE 802.11be EHT operation IE. Stored mostly as
# named bit-packed bytes; field-level semantics are picked up by the UI.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class EhtOperationsBss:
    bssid: bytes
    eht_operation_information_length: int  # u8
    #: Opaque EHT Operation Info bytes (matches 802.11be IE body).
    eht_operation_information: bytes
    basic_eht_mcs_nss_set: bytes  # 4 bytes per spec
    disabled_subchannel_bitmap: bytes  # 2 bytes per spec

    def __post_init__(self) -> None:
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")
        if len(self.basic_eht_mcs_nss_set) != 4:
            raise ValueError("basic_eht_mcs_nss_set must be 4 bytes")
        if len(self.disabled_subchannel_bitmap) != 2:
            raise ValueError("disabled_subchannel_bitmap must be 2 bytes")
        if len(self.eht_operation_information) != self.eht_operation_information_length:
            raise ValueError("eht_operation_information length mismatch")

    def to_bytes(self) -> bytes:
        return (
            bytes(self.bssid)
            + bytes([self.eht_operation_information_length])
            + bytes(self.eht_operation_information)
            + bytes(self.basic_eht_mcs_nss_set)
            + bytes(self.disabled_subchannel_bitmap)
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[EhtOperationsBss, int]:
        start = offset
        if offset + BSSID_LEN + 1 > len(payload):
            raise ValueError("truncated EHT operations BSS header")
        bssid = parse_mac(payload, offset)
        offset += BSSID_LEN
        op_len = payload[offset]
        offset += 1
        if offset + op_len + 4 + 2 > len(payload):
            raise ValueError("truncated EHT operations body")
        op_info = bytes(payload[offset : offset + op_len])
        offset += op_len
        mcs = bytes(payload[offset : offset + 4])
        offset += 4
        disabled = bytes(payload[offset : offset + 2])
        offset += 2
        return (
            cls(
                bssid=bssid,
                eht_operation_information_length=op_len,
                eht_operation_information=op_info,
                basic_eht_mcs_nss_set=mcs,
                disabled_subchannel_bitmap=disabled,
            ),
            offset - start,
        )


@dataclass(slots=True)
class ApEhtOperations:
    TLV_TYPE: ClassVar[int] = 0xE0
    TLV_NAME: ClassVar[str] = "AP EHT operations"

    radio_id: bytes
    bsses: list[EhtOperationsBss] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.radio_id) != MAC_LEN:
            raise ValueError("radio_id must be 6 bytes")
        if len(self.bsses) > 0xFF:
            raise ValueError("too many BSSes (8-bit count)")

    def to_payload(self) -> bytes:
        return (
            bytes(self.radio_id)
            + bytes([len(self.bsses)])
            + b"".join(b.to_bytes() for b in self.bsses)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> ApEhtOperations:
        if len(payload) < MAC_LEN + 1:
            raise ValueError("AP EHT operations TLV too short")
        rid = parse_mac(payload)
        count = payload[MAC_LEN]
        offset = MAC_LEN + 1
        bsses: list[EhtOperationsBss] = []
        for _ in range(count):
            b, consumed = EhtOperationsBss.parse(payload, offset)
            bsses.append(b)
            offset += consumed
        if offset != len(payload):
            raise ValueError(
                f"AP EHT operations TLV has {len(payload) - offset} trailing bytes"
            )
        return cls(radio_id=rid, bsses=bsses)


register_typed(ApEhtOperations, spec_ref="Multi-AP v4.0 §17.2.90")


@dataclass(slots=True)
class EhtOperations:
    TLV_TYPE: ClassVar[int] = 0xE8
    TLV_NAME: ClassVar[str] = "EHT operations"

    #: Same shape as AP EHT Operations, but network-wide aggregation.
    radios: list[ApEhtOperations] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.radios) > 0xFF:
            raise ValueError("too many radios (8-bit count)")

    def to_payload(self) -> bytes:
        # Each radio's body is its full AP-EHT-Operations payload (without TLV header).
        return bytes([len(self.radios)]) + b"".join(r.to_payload() for r in self.radios)

    @classmethod
    def from_payload(cls, payload: bytes) -> EhtOperations:
        if not payload:
            raise ValueError("EHT operations TLV needs a count byte")
        count = payload[0]
        offset = 1
        radios: list[ApEhtOperations] = []
        for _ in range(count):
            # Parse one radio_id + count_bsses + bsses chunk.
            if offset + MAC_LEN + 1 > len(payload):
                raise ValueError("truncated EHT operations radio chunk header")
            radio_id = parse_mac(payload, offset)
            bss_count = payload[offset + MAC_LEN]
            inner_offset = offset + MAC_LEN + 1
            bsses: list[EhtOperationsBss] = []
            for _ in range(bss_count):
                b, consumed = EhtOperationsBss.parse(payload, inner_offset)
                bsses.append(b)
                inner_offset += consumed
            radios.append(ApEhtOperations(radio_id=radio_id, bsses=bsses))
            offset = inner_offset
        if offset != len(payload):
            raise ValueError(
                f"EHT operations TLV has {len(payload) - offset} trailing bytes"
            )
        return cls(radios=radios)


register_typed(EhtOperations, spec_ref="Multi-AP v4.0 §17.2.95")


# ---------------------------------------------------------------------------
# 0xE1 AP Wi-Fi 7 Agent Capabilities — §17.2.91
# Top-level agent-wide capability bitmap plus per-radio caps.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Wifi7RadioCapability:
    radio_id: bytes
    #: bit 7 EMLSR, bit 6 EMLMR, bit 5 NSTR, bit 4 STR, bits 3-0 reserved.
    flags: int

    SIZE: ClassVar[int] = MAC_LEN + 1

    def __post_init__(self) -> None:
        if len(self.radio_id) != MAC_LEN:
            raise ValueError("radio_id must be 6 bytes")

    def to_bytes(self) -> bytes:
        return bytes(self.radio_id) + bytes([self.flags & 0xFF])

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> Wifi7RadioCapability:
        if offset + cls.SIZE > len(payload):
            raise ValueError("truncated Wi-Fi 7 radio capability entry")
        return cls(radio_id=parse_mac(payload, offset), flags=payload[offset + MAC_LEN])


@dataclass(slots=True)
class ApWifi7AgentCapabilities:
    TLV_TYPE: ClassVar[int] = 0xE1
    TLV_NAME: ClassVar[str] = "AP Wi-Fi 7 agent capabilities"

    #: Agent-wide MLD capability flags (Multi-AP v4.0 Table 17-X).
    agent_flags: int
    radios: list[Wifi7RadioCapability] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.radios) > 0xFF:
            raise ValueError("too many radios (8-bit count)")

    def to_payload(self) -> bytes:
        return (
            bytes([self.agent_flags & 0xFF, len(self.radios) & 0xFF])
            + b"".join(r.to_bytes() for r in self.radios)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> ApWifi7AgentCapabilities:
        if len(payload) < 2:
            raise ValueError("AP Wi-Fi 7 agent capabilities TLV too short")
        agent_flags = payload[0]
        count = payload[1]
        expected = 2 + count * Wifi7RadioCapability.SIZE
        if len(payload) != expected:
            raise ValueError(
                f"AP Wi-Fi 7 agent capabilities length mismatch: expected {expected}, "
                f"got {len(payload)}"
            )
        radios = [
            Wifi7RadioCapability.parse(payload, 2 + i * Wifi7RadioCapability.SIZE)
            for i in range(count)
        ]
        return cls(agent_flags=agent_flags, radios=radios)


register_typed(ApWifi7AgentCapabilities, spec_ref="Multi-AP v4.0 §17.2.91")


# ---------------------------------------------------------------------------
# 0xE2 Agent AP MLD Configuration — §17.2.92
# 0xE3 Backhaul STA MLD Configuration — §17.2.93
# 0xE4 Associated STA MLD Configuration — §17.2.94
# MLD = Multi-Link Device. Each carries an MLD MAC + list of affiliated
# link MACs with per-link configuration bytes.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class AffiliatedLink:
    """One affiliated-link record within an MLD configuration TLV."""

    link_mac: bytes
    #: bit-packed per-link configuration (NSTR, EMLSR, STR mode, ...).
    flags: int

    SIZE: ClassVar[int] = MAC_LEN + 1

    def __post_init__(self) -> None:
        if len(self.link_mac) != MAC_LEN:
            raise ValueError("link_mac must be 6 bytes")

    def to_bytes(self) -> bytes:
        return bytes(self.link_mac) + bytes([self.flags & 0xFF])

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> AffiliatedLink:
        if offset + cls.SIZE > len(payload):
            raise ValueError("truncated affiliated-link entry")
        return cls(link_mac=parse_mac(payload, offset), flags=payload[offset + MAC_LEN])


@dataclass(slots=True)
class _MldConfigBase:
    mld_mac: bytes
    mld_flags: int  # MLD-wide config flags
    links: list[AffiliatedLink] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.mld_mac) != MAC_LEN:
            raise ValueError("mld_mac must be 6 bytes")
        if len(self.links) > 0xFF:
            raise ValueError("too many links (8-bit count)")

    def _to_payload(self) -> bytes:
        return (
            bytes(self.mld_mac)
            + bytes([self.mld_flags & 0xFF, len(self.links) & 0xFF])
            + b"".join(link.to_bytes() for link in self.links)
        )

    @classmethod
    def _parse(cls, payload: bytes) -> tuple[bytes, int, list[AffiliatedLink]]:
        if len(payload) < MAC_LEN + 2:
            raise ValueError("MLD configuration TLV too short")
        mac = parse_mac(payload, 0)
        flags = payload[MAC_LEN]
        count = payload[MAC_LEN + 1]
        expected = MAC_LEN + 2 + count * AffiliatedLink.SIZE
        if len(payload) != expected:
            raise ValueError(
                f"MLD configuration length mismatch: expected {expected}, got {len(payload)}"
            )
        links = [
            AffiliatedLink.parse(payload, MAC_LEN + 2 + i * AffiliatedLink.SIZE)
            for i in range(count)
        ]
        return mac, flags, links


@dataclass(slots=True)
class AgentApMldConfiguration(_MldConfigBase):
    TLV_TYPE: ClassVar[int] = 0xE2
    TLV_NAME: ClassVar[str] = "Agent AP MLD configuration"

    def to_payload(self) -> bytes:
        return self._to_payload()

    @classmethod
    def from_payload(cls, payload: bytes) -> AgentApMldConfiguration:
        mac, flags, links = cls._parse(payload)
        return cls(mld_mac=mac, mld_flags=flags, links=links)


register_typed(AgentApMldConfiguration, spec_ref="Multi-AP v4.0 §17.2.92")


@dataclass(slots=True)
class BackhaulStaMldConfiguration(_MldConfigBase):
    TLV_TYPE: ClassVar[int] = 0xE3
    TLV_NAME: ClassVar[str] = "Backhaul STA MLD configuration"

    def to_payload(self) -> bytes:
        return self._to_payload()

    @classmethod
    def from_payload(cls, payload: bytes) -> BackhaulStaMldConfiguration:
        mac, flags, links = cls._parse(payload)
        return cls(mld_mac=mac, mld_flags=flags, links=links)


register_typed(BackhaulStaMldConfiguration, spec_ref="Multi-AP v4.0 §17.2.93")


@dataclass(slots=True)
class AssociatedStaMldConfiguration(_MldConfigBase):
    TLV_TYPE: ClassVar[int] = 0xE4
    TLV_NAME: ClassVar[str] = "Associated STA MLD configuration"

    def to_payload(self) -> bytes:
        return self._to_payload()

    @classmethod
    def from_payload(cls, payload: bytes) -> AssociatedStaMldConfiguration:
        mac, flags, links = cls._parse(payload)
        return cls(mld_mac=mac, mld_flags=flags, links=links)


register_typed(AssociatedStaMldConfiguration, spec_ref="Multi-AP v4.0 §17.2.94")


# ---------------------------------------------------------------------------
# 0xE5 Affiliated STA Metrics — §17.2.96
# 0xE6 Affiliated AP Metrics — §17.2.97
# Per-link metrics for MLO-enabled STAs / APs.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class AffiliatedStaMetrics:
    TLV_TYPE: ClassVar[int] = 0xE5
    TLV_NAME: ClassVar[str] = "Affiliated STA metrics"

    sta_mac: bytes
    bssid: bytes
    #: u32 BE counters per link, mirroring R1 Associated STA Traffic Stats.
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    packets_sent_errors: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(">IIIII")
    SIZE: ClassVar[int] = MAC_LEN + BSSID_LEN + _STRUCT.size

    def __post_init__(self) -> None:
        if len(self.sta_mac) != MAC_LEN:
            raise ValueError("sta_mac must be 6 bytes")
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")

    def to_payload(self) -> bytes:
        return bytes(self.sta_mac) + bytes(self.bssid) + self._STRUCT.pack(
            self.bytes_sent & 0xFFFFFFFF,
            self.bytes_received & 0xFFFFFFFF,
            self.packets_sent & 0xFFFFFFFF,
            self.packets_received & 0xFFFFFFFF,
            self.packets_sent_errors & 0xFFFFFFFF,
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> AffiliatedStaMetrics:
        if len(payload) != cls.SIZE:
            raise ValueError(
                f"Affiliated STA metrics TLV must be {cls.SIZE} bytes, got {len(payload)}"
            )
        vals = cls._STRUCT.unpack_from(payload, MAC_LEN + BSSID_LEN)
        return cls(
            sta_mac=parse_mac(payload, 0),
            bssid=parse_mac(payload, MAC_LEN),
            bytes_sent=vals[0],
            bytes_received=vals[1],
            packets_sent=vals[2],
            packets_received=vals[3],
            packets_sent_errors=vals[4],
        )


register_typed(AffiliatedStaMetrics, spec_ref="Multi-AP v4.0 §17.2.96")


@dataclass(slots=True)
class AffiliatedApMetrics:
    TLV_TYPE: ClassVar[int] = 0xE6
    TLV_NAME: ClassVar[str] = "Affiliated AP metrics"

    bssid: bytes
    #: Channel utilization as a percentage (u8) plus matching extended
    #: counters; same shape as R2 AP Extended Metrics for symmetry across MLO.
    channel_utilization: int
    num_associated_stas: int
    unicast_bytes_sent: int
    unicast_bytes_received: int
    multicast_bytes_sent: int
    multicast_bytes_received: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(">BHIIII")
    SIZE: ClassVar[int] = BSSID_LEN + _STRUCT.size

    def __post_init__(self) -> None:
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")

    def to_payload(self) -> bytes:
        return bytes(self.bssid) + self._STRUCT.pack(
            self.channel_utilization & 0xFF,
            self.num_associated_stas & 0xFFFF,
            self.unicast_bytes_sent & 0xFFFFFFFF,
            self.unicast_bytes_received & 0xFFFFFFFF,
            self.multicast_bytes_sent & 0xFFFFFFFF,
            self.multicast_bytes_received & 0xFFFFFFFF,
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> AffiliatedApMetrics:
        if len(payload) != cls.SIZE:
            raise ValueError(
                f"Affiliated AP metrics TLV must be {cls.SIZE} bytes, got {len(payload)}"
            )
        ch_util, n_sta, u_sent, u_recv, m_sent, m_recv = cls._STRUCT.unpack_from(
            payload, BSSID_LEN
        )
        return cls(
            bssid=parse_mac(payload, 0),
            channel_utilization=ch_util,
            num_associated_stas=n_sta,
            unicast_bytes_sent=u_sent,
            unicast_bytes_received=u_recv,
            multicast_bytes_sent=m_sent,
            multicast_bytes_received=m_recv,
        )


register_typed(AffiliatedApMetrics, spec_ref="Multi-AP v4.0 §17.2.97")


# ---------------------------------------------------------------------------
# 0xE7 TID-to-Link Mapping Policy — §17.2.98
# Maps Traffic Identifiers (TIDs, 0-7) to specific links within an MLD.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class TidToLinkMappingPolicy:
    TLV_TYPE: ClassVar[int] = 0xE7
    TLV_NAME: ClassVar[str] = "TID-to-link mapping policy"

    mld_mac: bytes
    #: bit-packed direction (uplink/downlink/both) + default mapping flag.
    flags: int
    #: For each TID (0..7): a bitmap of link IDs (u8). Length 8 bytes.
    tid_to_link_bitmap: bytes

    SIZE: ClassVar[int] = MAC_LEN + 1 + 8

    def __post_init__(self) -> None:
        if len(self.mld_mac) != MAC_LEN:
            raise ValueError("mld_mac must be 6 bytes")
        if len(self.tid_to_link_bitmap) != 8:
            raise ValueError("tid_to_link_bitmap must be 8 bytes (one per TID)")

    def to_payload(self) -> bytes:
        return bytes(self.mld_mac) + bytes([self.flags & 0xFF]) + bytes(self.tid_to_link_bitmap)

    @classmethod
    def from_payload(cls, payload: bytes) -> TidToLinkMappingPolicy:
        if len(payload) != cls.SIZE:
            raise ValueError(
                f"TID-to-link mapping policy TLV must be {cls.SIZE} bytes, got {len(payload)}"
            )
        return cls(
            mld_mac=parse_mac(payload, 0),
            flags=payload[MAC_LEN],
            tid_to_link_bitmap=bytes(payload[MAC_LEN + 1 :]),
        )


register_typed(TidToLinkMappingPolicy, spec_ref="Multi-AP v4.0 §17.2.98")
