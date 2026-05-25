# SPDX-License-Identifier: GPL-2.0-or-later
"""Wi-Fi EasyMesh R1 TLV implementations.

Spec: Wi-Fi Alliance *Multi-AP Specification* v1.0 §17.2.x. Types
0x80-0xA3 cover service/identification, AP & radio capabilities,
channel management, client info, steering, metrics and a couple of
small misc TLVs.

A few design notes:

- Bit-packed capability fields (HT / VHT / HE flags, ESP info, …) are
  exposed via named integer fields plus accessors for the individual
  flags. The underlying wire bytes are reconstructable from those
  fields so we never need to round-trip "opaque" capability bytes.
- Variable-length sub-records (channel lists, target BSSIDs, …) use
  the same ``parse``/``to_bytes`` pair pattern as :mod:`ieee1905_1`.

EasyMesh introduces TLV types in the 0x80+ range but keeps the 1905.1
header format (1-byte type, 16-bit length). Profile-2 expands the
length field to 32 bits — that lands together with R2.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import ClassVar

from ieee1905.core.tlvs._helpers import MAC_LEN, parse_mac, register_typed

BSSID_LEN = 6


# ---------------------------------------------------------------------------
# 0x80 SupportedService — §17.2.1
# 0x81 SearchedService  — §17.2.2
# Service codes: 0x00 = Multi-AP Controller, 0x01 = Multi-AP Agent.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SupportedService:
    TLV_TYPE: ClassVar[int] = 0x80
    TLV_NAME: ClassVar[str] = "Supported service"

    services: list[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.services) > 0xFF:
            raise ValueError("too many services (8-bit count)")

    def to_payload(self) -> bytes:
        return bytes([len(self.services)]) + bytes(s & 0xFF for s in self.services)

    @classmethod
    def from_payload(cls, payload: bytes) -> SupportedService:
        if not payload:
            raise ValueError("Supported service TLV needs a count byte")
        count = payload[0]
        if len(payload) != 1 + count:
            raise ValueError(
                f"Supported service TLV length mismatch: expected {1 + count}, got {len(payload)}"
            )
        return cls(services=list(payload[1:]))


register_typed(SupportedService, spec_ref="Multi-AP v1.0 §17.2.1")


@dataclass(slots=True)
class SearchedService:
    TLV_TYPE: ClassVar[int] = 0x81
    TLV_NAME: ClassVar[str] = "Searched service"

    services: list[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.services) > 0xFF:
            raise ValueError("too many services (8-bit count)")

    def to_payload(self) -> bytes:
        return bytes([len(self.services)]) + bytes(s & 0xFF for s in self.services)

    @classmethod
    def from_payload(cls, payload: bytes) -> SearchedService:
        if not payload:
            raise ValueError("Searched service TLV needs a count byte")
        count = payload[0]
        if len(payload) != 1 + count:
            raise ValueError(
                f"Searched service TLV length mismatch: expected {1 + count}, got {len(payload)}"
            )
        return cls(services=list(payload[1:]))


register_typed(SearchedService, spec_ref="Multi-AP v1.0 §17.2.2")


# ---------------------------------------------------------------------------
# 0x82 AP Radio Identifier — §17.2.3
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ApRadioIdentifier:
    TLV_TYPE: ClassVar[int] = 0x82
    TLV_NAME: ClassVar[str] = "AP radio identifier"

    radio_id: bytes  # 6-byte radio unique identifier (typically a MAC)

    def __post_init__(self) -> None:
        if len(self.radio_id) != MAC_LEN:
            raise ValueError("radio_id must be 6 bytes")

    def to_payload(self) -> bytes:
        return bytes(self.radio_id)

    @classmethod
    def from_payload(cls, payload: bytes) -> ApRadioIdentifier:
        return cls(radio_id=parse_mac(payload))


register_typed(ApRadioIdentifier, spec_ref="Multi-AP v1.0 §17.2.3")


# ---------------------------------------------------------------------------
# 0x83 AP Operational BSS — §17.2.4
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class OperationalBss:
    """One BSS entry within a radio's operational BSS list."""

    bssid: bytes
    ssid: bytes  # raw SSID octets (may be non-UTF-8); empty for hidden

    def __post_init__(self) -> None:
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")
        if len(self.ssid) > 0xFF:
            raise ValueError("SSID exceeds 8-bit length field")

    def to_bytes(self) -> bytes:
        return bytes(self.bssid) + bytes([len(self.ssid)]) + bytes(self.ssid)

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[OperationalBss, int]:
        start = offset
        if offset + BSSID_LEN + 1 > len(payload):
            raise ValueError("truncated operational BSS header")
        bssid = parse_mac(payload, offset)
        offset += BSSID_LEN
        ssid_len = payload[offset]
        offset += 1
        if offset + ssid_len > len(payload):
            raise ValueError("truncated SSID")
        ssid = bytes(payload[offset : offset + ssid_len])
        offset += ssid_len
        return cls(bssid=bssid, ssid=ssid), offset - start


@dataclass(slots=True)
class OperationalBssRadio:
    """One radio in an AP Operational BSS TLV."""

    radio_id: bytes
    bsses: list[OperationalBss] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.radio_id) != MAC_LEN:
            raise ValueError("radio_id must be 6 bytes")
        if len(self.bsses) > 0xFF:
            raise ValueError("too many BSSes (8-bit count)")

    def to_bytes(self) -> bytes:
        return (
            bytes(self.radio_id)
            + bytes([len(self.bsses)])
            + b"".join(b.to_bytes() for b in self.bsses)
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[OperationalBssRadio, int]:
        start = offset
        if offset + MAC_LEN + 1 > len(payload):
            raise ValueError("truncated operational BSS radio header")
        rid = parse_mac(payload, offset)
        offset += MAC_LEN
        bss_count = payload[offset]
        offset += 1
        bsses: list[OperationalBss] = []
        for _ in range(bss_count):
            b, consumed = OperationalBss.parse(payload, offset)
            bsses.append(b)
            offset += consumed
        return cls(radio_id=rid, bsses=bsses), offset - start


@dataclass(slots=True)
class ApOperationalBss:
    TLV_TYPE: ClassVar[int] = 0x83
    TLV_NAME: ClassVar[str] = "AP operational BSS"

    radios: list[OperationalBssRadio] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.radios) > 0xFF:
            raise ValueError("too many radios (8-bit count)")

    def to_payload(self) -> bytes:
        return bytes([len(self.radios)]) + b"".join(r.to_bytes() for r in self.radios)

    @classmethod
    def from_payload(cls, payload: bytes) -> ApOperationalBss:
        if not payload:
            raise ValueError("AP operational BSS TLV needs a count byte")
        count = payload[0]
        offset = 1
        radios: list[OperationalBssRadio] = []
        for _ in range(count):
            r, consumed = OperationalBssRadio.parse(payload, offset)
            radios.append(r)
            offset += consumed
        if offset != len(payload):
            raise ValueError(
                f"AP operational BSS TLV has {len(payload) - offset} trailing bytes"
            )
        return cls(radios=radios)


register_typed(ApOperationalBss, spec_ref="Multi-AP v1.0 §17.2.4")


# ---------------------------------------------------------------------------
# 0x84 Associated Clients — §17.2.5
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class AssociatedClient:
    client_mac: bytes
    seconds_since_assoc: int  # uint16 BE

    SIZE: ClassVar[int] = MAC_LEN + 2

    def __post_init__(self) -> None:
        if len(self.client_mac) != MAC_LEN:
            raise ValueError("client_mac must be 6 bytes")

    def to_bytes(self) -> bytes:
        return bytes(self.client_mac) + struct.pack(">H", self.seconds_since_assoc & 0xFFFF)

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> AssociatedClient:
        if offset + cls.SIZE > len(payload):
            raise ValueError("truncated associated client entry")
        return cls(
            client_mac=parse_mac(payload, offset),
            seconds_since_assoc=struct.unpack_from(">H", payload, offset + MAC_LEN)[0],
        )


@dataclass(slots=True)
class AssociatedClientsBss:
    bssid: bytes
    clients: list[AssociatedClient] = field(default_factory=list)

    _COUNT: ClassVar[struct.Struct] = struct.Struct(">H")

    def __post_init__(self) -> None:
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")

    def to_bytes(self) -> bytes:
        return (
            bytes(self.bssid)
            + self._COUNT.pack(len(self.clients) & 0xFFFF)
            + b"".join(c.to_bytes() for c in self.clients)
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[AssociatedClientsBss, int]:
        start = offset
        if offset + BSSID_LEN + cls._COUNT.size > len(payload):
            raise ValueError("truncated associated-clients BSS header")
        bssid = parse_mac(payload, offset)
        (count,) = cls._COUNT.unpack_from(payload, offset + BSSID_LEN)
        offset += BSSID_LEN + cls._COUNT.size
        clients = [
            AssociatedClient.parse(payload, offset + i * AssociatedClient.SIZE)
            for i in range(count)
        ]
        offset += count * AssociatedClient.SIZE
        if offset > len(payload):
            raise ValueError("truncated associated-clients list")
        return cls(bssid=bssid, clients=clients), offset - start


@dataclass(slots=True)
class AssociatedClients:
    TLV_TYPE: ClassVar[int] = 0x84
    TLV_NAME: ClassVar[str] = "Associated clients"

    bsses: list[AssociatedClientsBss] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.bsses) > 0xFF:
            raise ValueError("too many BSSes (8-bit count)")

    def to_payload(self) -> bytes:
        return bytes([len(self.bsses)]) + b"".join(b.to_bytes() for b in self.bsses)

    @classmethod
    def from_payload(cls, payload: bytes) -> AssociatedClients:
        if not payload:
            raise ValueError("Associated clients TLV needs a count byte")
        count = payload[0]
        offset = 1
        bsses: list[AssociatedClientsBss] = []
        for _ in range(count):
            b, consumed = AssociatedClientsBss.parse(payload, offset)
            bsses.append(b)
            offset += consumed
        if offset != len(payload):
            raise ValueError(
                f"Associated clients TLV has {len(payload) - offset} trailing bytes"
            )
        return cls(bsses=bsses)


register_typed(AssociatedClients, spec_ref="Multi-AP v1.0 §17.2.5")


# ---------------------------------------------------------------------------
# 0x85 AP Radio Basic Capabilities — §17.2.6
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class OperatingClassCapability:
    op_class: int
    max_tx_eirp_dbm: int  # signed int8 per spec, but in practice 0-30 dBm
    non_operable_channels: list[int] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        return (
            bytes([self.op_class & 0xFF, self.max_tx_eirp_dbm & 0xFF, len(self.non_operable_channels) & 0xFF])
            + bytes(c & 0xFF for c in self.non_operable_channels)
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[OperatingClassCapability, int]:
        if offset + 3 > len(payload):
            raise ValueError("truncated operating-class header")
        op_class = payload[offset]
        eirp = payload[offset + 1]
        count = payload[offset + 2]
        start = offset + 3
        end = start + count
        if end > len(payload):
            raise ValueError("truncated non-operable channel list")
        return (
            cls(
                op_class=op_class,
                max_tx_eirp_dbm=eirp,
                non_operable_channels=list(payload[start:end]),
            ),
            end - offset,
        )


@dataclass(slots=True)
class ApRadioBasicCapabilities:
    TLV_TYPE: ClassVar[int] = 0x85
    TLV_NAME: ClassVar[str] = "AP radio basic capabilities"

    radio_id: bytes
    max_bsses_supported: int
    operating_classes: list[OperatingClassCapability] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.radio_id) != MAC_LEN:
            raise ValueError("radio_id must be 6 bytes")
        if len(self.operating_classes) > 0xFF:
            raise ValueError("too many operating classes (8-bit count)")

    def to_payload(self) -> bytes:
        return (
            bytes(self.radio_id)
            + bytes([self.max_bsses_supported & 0xFF, len(self.operating_classes) & 0xFF])
            + b"".join(oc.to_bytes() for oc in self.operating_classes)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> ApRadioBasicCapabilities:
        if len(payload) < MAC_LEN + 2:
            raise ValueError("AP radio basic capabilities TLV too short")
        radio_id = parse_mac(payload)
        max_bss = payload[MAC_LEN]
        count = payload[MAC_LEN + 1]
        offset = MAC_LEN + 2
        ocs: list[OperatingClassCapability] = []
        for _ in range(count):
            oc, consumed = OperatingClassCapability.parse(payload, offset)
            ocs.append(oc)
            offset += consumed
        if offset != len(payload):
            raise ValueError(
                f"AP radio basic capabilities TLV has {len(payload) - offset} trailing bytes"
            )
        return cls(radio_id=radio_id, max_bsses_supported=max_bss, operating_classes=ocs)


register_typed(ApRadioBasicCapabilities, spec_ref="Multi-AP v1.0 §17.2.6")


# ---------------------------------------------------------------------------
# 0x86 AP HT Capabilities — §17.2.7
# 0x87 AP VHT Capabilities — §17.2.8
# 0x88 AP HE Capabilities — §17.2.9
# Bit-packed capability blobs.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ApHtCapabilities:
    TLV_TYPE: ClassVar[int] = 0x86
    TLV_NAME: ClassVar[str] = "AP HT capabilities"

    radio_id: bytes
    #: Raw HT capability byte (bits 7-6 max Tx SS, 5-4 max Rx SS, 3 SGI 20,
    #: 2 SGI 40, 1 HT-40, 0 reserved).
    flags: int

    def __post_init__(self) -> None:
        if len(self.radio_id) != MAC_LEN:
            raise ValueError("radio_id must be 6 bytes")

    @property
    def max_tx_streams(self) -> int:
        return ((self.flags >> 6) & 0x3) + 1

    @property
    def max_rx_streams(self) -> int:
        return ((self.flags >> 4) & 0x3) + 1

    @property
    def sgi_20mhz(self) -> bool:
        return bool(self.flags & 0x08)

    @property
    def sgi_40mhz(self) -> bool:
        return bool(self.flags & 0x04)

    @property
    def ht_40mhz(self) -> bool:
        return bool(self.flags & 0x02)

    def to_payload(self) -> bytes:
        return bytes(self.radio_id) + bytes([self.flags & 0xFF])

    @classmethod
    def from_payload(cls, payload: bytes) -> ApHtCapabilities:
        if len(payload) != MAC_LEN + 1:
            raise ValueError(
                f"AP HT capabilities TLV must be {MAC_LEN + 1} bytes, got {len(payload)}"
            )
        return cls(radio_id=parse_mac(payload), flags=payload[MAC_LEN])


register_typed(ApHtCapabilities, spec_ref="Multi-AP v1.0 §17.2.7")


@dataclass(slots=True)
class ApVhtCapabilities:
    TLV_TYPE: ClassVar[int] = 0x87
    TLV_NAME: ClassVar[str] = "AP VHT capabilities"

    radio_id: bytes
    vht_tx_mcs_map: int  # u16 BE
    vht_rx_mcs_map: int  # u16 BE
    #: 2-byte capability bitmap; see Multi-AP v1.0 Table 17-8 for layout.
    flags: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(">HHH")
    SIZE: ClassVar[int] = MAC_LEN + _STRUCT.size

    def __post_init__(self) -> None:
        if len(self.radio_id) != MAC_LEN:
            raise ValueError("radio_id must be 6 bytes")

    @property
    def max_tx_streams(self) -> int:
        return ((self.flags >> 13) & 0x7) + 1

    @property
    def max_rx_streams(self) -> int:
        return ((self.flags >> 10) & 0x7) + 1

    @property
    def sgi_80mhz(self) -> bool:
        return bool(self.flags & (1 << 9))

    @property
    def sgi_160mhz(self) -> bool:
        return bool(self.flags & (1 << 8))

    @property
    def vht_80plus80mhz(self) -> bool:
        return bool(self.flags & (1 << 7))

    @property
    def vht_160mhz(self) -> bool:
        return bool(self.flags & (1 << 6))

    @property
    def su_beamformer(self) -> bool:
        return bool(self.flags & (1 << 5))

    @property
    def mu_beamformer(self) -> bool:
        return bool(self.flags & (1 << 4))

    def to_payload(self) -> bytes:
        return bytes(self.radio_id) + self._STRUCT.pack(
            self.vht_tx_mcs_map & 0xFFFF,
            self.vht_rx_mcs_map & 0xFFFF,
            self.flags & 0xFFFF,
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> ApVhtCapabilities:
        if len(payload) != cls.SIZE:
            raise ValueError(
                f"AP VHT capabilities TLV must be {cls.SIZE} bytes, got {len(payload)}"
            )
        tx, rx, fl = cls._STRUCT.unpack_from(payload, MAC_LEN)
        return cls(radio_id=parse_mac(payload), vht_tx_mcs_map=tx, vht_rx_mcs_map=rx, flags=fl)


register_typed(ApVhtCapabilities, spec_ref="Multi-AP v1.0 §17.2.8")


@dataclass(slots=True)
class ApHeCapabilities:
    TLV_TYPE: ClassVar[int] = 0x88
    TLV_NAME: ClassVar[str] = "AP HE capabilities"

    radio_id: bytes
    supported_he_mcs: bytes
    #: 2-byte capability bitmap (see Multi-AP v1.0 Table 17-10).
    flags: int

    _FLAGS: ClassVar[struct.Struct] = struct.Struct(">H")

    def __post_init__(self) -> None:
        if len(self.radio_id) != MAC_LEN:
            raise ValueError("radio_id must be 6 bytes")
        if len(self.supported_he_mcs) > 0xFF:
            raise ValueError("supported_he_mcs exceeds 8-bit length field")

    @property
    def max_tx_streams(self) -> int:
        return ((self.flags >> 13) & 0x7) + 1

    @property
    def max_rx_streams(self) -> int:
        return ((self.flags >> 10) & 0x7) + 1

    @property
    def he_80plus80mhz(self) -> bool:
        return bool(self.flags & (1 << 9))

    @property
    def he_160mhz(self) -> bool:
        return bool(self.flags & (1 << 8))

    @property
    def su_beamformer(self) -> bool:
        return bool(self.flags & (1 << 7))

    @property
    def mu_beamformer(self) -> bool:
        return bool(self.flags & (1 << 6))

    @property
    def ul_mu_mimo(self) -> bool:
        return bool(self.flags & (1 << 5))

    @property
    def ul_ofdma(self) -> bool:
        return bool(self.flags & (1 << 4))

    @property
    def dl_ofdma(self) -> bool:
        return bool(self.flags & (1 << 3))

    def to_payload(self) -> bytes:
        return (
            bytes(self.radio_id)
            + bytes([len(self.supported_he_mcs) & 0xFF])
            + bytes(self.supported_he_mcs)
            + self._FLAGS.pack(self.flags & 0xFFFF)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> ApHeCapabilities:
        if len(payload) < MAC_LEN + 1 + cls._FLAGS.size:
            raise ValueError("AP HE capabilities TLV too short")
        radio_id = parse_mac(payload)
        mcs_len = payload[MAC_LEN]
        mcs_start = MAC_LEN + 1
        mcs_end = mcs_start + mcs_len
        if mcs_end + cls._FLAGS.size != len(payload):
            raise ValueError(
                f"AP HE capabilities TLV length mismatch: expected "
                f"{mcs_end + cls._FLAGS.size}, got {len(payload)}"
            )
        (flags,) = cls._FLAGS.unpack_from(payload, mcs_end)
        return cls(
            radio_id=radio_id,
            supported_he_mcs=bytes(payload[mcs_start:mcs_end]),
            flags=flags,
        )


register_typed(ApHeCapabilities, spec_ref="Multi-AP v1.0 §17.2.9")


# ---------------------------------------------------------------------------
# 0x89 Steering Policy — §17.2.10
# 0x8A Metric Reporting Policy — §17.2.11
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SteeringPolicyRadio:
    radio_id: bytes
    policy: int  # 0=agent-initiated, 1=mandate, 2=disallowed
    channel_utilization_threshold: int
    rcpi_steering_threshold: int

    SIZE: ClassVar[int] = MAC_LEN + 3

    def to_bytes(self) -> bytes:
        return bytes(self.radio_id) + bytes(
            [
                self.policy & 0xFF,
                self.channel_utilization_threshold & 0xFF,
                self.rcpi_steering_threshold & 0xFF,
            ]
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> SteeringPolicyRadio:
        if offset + cls.SIZE > len(payload):
            raise ValueError("truncated steering-policy radio entry")
        return cls(
            radio_id=parse_mac(payload, offset),
            policy=payload[offset + MAC_LEN],
            channel_utilization_threshold=payload[offset + MAC_LEN + 1],
            rcpi_steering_threshold=payload[offset + MAC_LEN + 2],
        )


@dataclass(slots=True)
class SteeringPolicy:
    TLV_TYPE: ClassVar[int] = 0x89
    TLV_NAME: ClassVar[str] = "Steering policy"

    local_steering_disallowed: list[bytes] = field(default_factory=list)
    btm_steering_disallowed: list[bytes] = field(default_factory=list)
    radios: list[SteeringPolicyRadio] = field(default_factory=list)

    def __post_init__(self) -> None:
        for label, lst in (
            ("local_steering_disallowed", self.local_steering_disallowed),
            ("btm_steering_disallowed", self.btm_steering_disallowed),
        ):
            if len(lst) > 0xFF:
                raise ValueError(f"too many {label} entries (8-bit count)")
            for m in lst:
                if len(m) != MAC_LEN:
                    raise ValueError(f"{label} MAC must be 6 bytes")
        if len(self.radios) > 0xFF:
            raise ValueError("too many radios (8-bit count)")

    def to_payload(self) -> bytes:
        parts = [
            bytes([len(self.local_steering_disallowed)]),
            b"".join(bytes(m) for m in self.local_steering_disallowed),
            bytes([len(self.btm_steering_disallowed)]),
            b"".join(bytes(m) for m in self.btm_steering_disallowed),
            bytes([len(self.radios)]),
            b"".join(r.to_bytes() for r in self.radios),
        ]
        return b"".join(parts)

    @classmethod
    def from_payload(cls, payload: bytes) -> SteeringPolicy:
        offset = 0
        if offset + 1 > len(payload):
            raise ValueError("Steering policy TLV too short")
        local_count = payload[offset]
        offset += 1
        local = [
            bytes(payload[offset + i * MAC_LEN : offset + (i + 1) * MAC_LEN])
            for i in range(local_count)
        ]
        offset += local_count * MAC_LEN
        if offset + 1 > len(payload):
            raise ValueError("Steering policy TLV truncated at BTM count")
        btm_count = payload[offset]
        offset += 1
        btm = [
            bytes(payload[offset + i * MAC_LEN : offset + (i + 1) * MAC_LEN])
            for i in range(btm_count)
        ]
        offset += btm_count * MAC_LEN
        if offset + 1 > len(payload):
            raise ValueError("Steering policy TLV truncated at radio count")
        radio_count = payload[offset]
        offset += 1
        radios = [
            SteeringPolicyRadio.parse(payload, offset + i * SteeringPolicyRadio.SIZE)
            for i in range(radio_count)
        ]
        offset += radio_count * SteeringPolicyRadio.SIZE
        if offset != len(payload):
            raise ValueError(
                f"Steering policy TLV has {len(payload) - offset} trailing bytes"
            )
        return cls(
            local_steering_disallowed=local,
            btm_steering_disallowed=btm,
            radios=radios,
        )


register_typed(SteeringPolicy, spec_ref="Multi-AP v1.0 §17.2.10")


@dataclass(slots=True)
class MetricReportingPolicyRadio:
    radio_id: bytes
    sta_rcpi_threshold: int
    sta_rcpi_hysteresis_margin: int
    ap_channel_utilization_threshold: int
    flags: int  # bit 7: incl traffic stats, bit 6: incl link metrics, bit 5: incl wifi6 stats

    SIZE: ClassVar[int] = MAC_LEN + 4

    def to_bytes(self) -> bytes:
        return bytes(self.radio_id) + bytes(
            [
                self.sta_rcpi_threshold & 0xFF,
                self.sta_rcpi_hysteresis_margin & 0xFF,
                self.ap_channel_utilization_threshold & 0xFF,
                self.flags & 0xFF,
            ]
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> MetricReportingPolicyRadio:
        if offset + cls.SIZE > len(payload):
            raise ValueError("truncated metric-reporting radio entry")
        return cls(
            radio_id=parse_mac(payload, offset),
            sta_rcpi_threshold=payload[offset + MAC_LEN],
            sta_rcpi_hysteresis_margin=payload[offset + MAC_LEN + 1],
            ap_channel_utilization_threshold=payload[offset + MAC_LEN + 2],
            flags=payload[offset + MAC_LEN + 3],
        )


@dataclass(slots=True)
class MetricReportingPolicy:
    TLV_TYPE: ClassVar[int] = 0x8A
    TLV_NAME: ClassVar[str] = "Metric reporting policy"

    ap_metrics_reporting_interval_s: int
    radios: list[MetricReportingPolicyRadio] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.radios) > 0xFF:
            raise ValueError("too many radios (8-bit count)")

    def to_payload(self) -> bytes:
        return (
            bytes([self.ap_metrics_reporting_interval_s & 0xFF, len(self.radios) & 0xFF])
            + b"".join(r.to_bytes() for r in self.radios)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> MetricReportingPolicy:
        if len(payload) < 2:
            raise ValueError("Metric reporting policy TLV too short")
        interval = payload[0]
        count = payload[1]
        expected = 2 + count * MetricReportingPolicyRadio.SIZE
        if len(payload) != expected:
            raise ValueError(
                f"Metric reporting policy length mismatch: expected {expected}, got {len(payload)}"
            )
        radios = [
            MetricReportingPolicyRadio.parse(payload, 2 + i * MetricReportingPolicyRadio.SIZE)
            for i in range(count)
        ]
        return cls(ap_metrics_reporting_interval_s=interval, radios=radios)


register_typed(MetricReportingPolicy, spec_ref="Multi-AP v1.0 §17.2.11")


# ---------------------------------------------------------------------------
# 0x8B Channel Preference — §17.2.13
# 0x8C Radio Operation Restriction — §17.2.14
# 0x8D Transmit Power Limit — §17.2.15
# 0x8E Channel Selection Response — §17.2.16
# 0x8F Operating Channel Report — §17.2.17
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ChannelPreferenceOpClass:
    op_class: int
    channels: list[int] = field(default_factory=list)
    #: bits 7-4: preference (0=non-operable .. 14=most preferred);
    #: bits 3-0: reason code (see Multi-AP Table 17-13).
    preference: int = 0xF0

    def to_bytes(self) -> bytes:
        return (
            bytes([self.op_class & 0xFF, len(self.channels) & 0xFF])
            + bytes(c & 0xFF for c in self.channels)
            + bytes([self.preference & 0xFF])
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[ChannelPreferenceOpClass, int]:
        if offset + 2 > len(payload):
            raise ValueError("truncated channel-preference op-class header")
        op_class = payload[offset]
        count = payload[offset + 1]
        ch_start = offset + 2
        ch_end = ch_start + count
        if ch_end + 1 > len(payload):
            raise ValueError("truncated channel-preference channel list")
        channels = list(payload[ch_start:ch_end])
        preference = payload[ch_end]
        return cls(op_class=op_class, channels=channels, preference=preference), ch_end + 1 - offset


@dataclass(slots=True)
class ChannelPreference:
    TLV_TYPE: ClassVar[int] = 0x8B
    TLV_NAME: ClassVar[str] = "Channel preference"

    radio_id: bytes
    operating_classes: list[ChannelPreferenceOpClass] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.radio_id) != MAC_LEN:
            raise ValueError("radio_id must be 6 bytes")
        if len(self.operating_classes) > 0xFF:
            raise ValueError("too many operating classes (8-bit count)")

    def to_payload(self) -> bytes:
        return (
            bytes(self.radio_id)
            + bytes([len(self.operating_classes)])
            + b"".join(oc.to_bytes() for oc in self.operating_classes)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> ChannelPreference:
        if len(payload) < MAC_LEN + 1:
            raise ValueError("Channel preference TLV too short")
        rid = parse_mac(payload)
        count = payload[MAC_LEN]
        offset = MAC_LEN + 1
        items: list[ChannelPreferenceOpClass] = []
        for _ in range(count):
            oc, consumed = ChannelPreferenceOpClass.parse(payload, offset)
            items.append(oc)
            offset += consumed
        if offset != len(payload):
            raise ValueError(
                f"Channel preference TLV has {len(payload) - offset} trailing bytes"
            )
        return cls(radio_id=rid, operating_classes=items)


register_typed(ChannelPreference, spec_ref="Multi-AP v1.0 §17.2.13")


@dataclass(slots=True)
class RestrictedChannel:
    channel: int
    min_frequency_separation_mhz: int  # multiples of 10 MHz per spec

    SIZE: ClassVar[int] = 2

    def to_bytes(self) -> bytes:
        return bytes([self.channel & 0xFF, self.min_frequency_separation_mhz & 0xFF])

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> RestrictedChannel:
        if offset + cls.SIZE > len(payload):
            raise ValueError("truncated restricted-channel entry")
        return cls(channel=payload[offset], min_frequency_separation_mhz=payload[offset + 1])


@dataclass(slots=True)
class RestrictedOpClass:
    op_class: int
    channels: list[RestrictedChannel] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        return (
            bytes([self.op_class & 0xFF, len(self.channels) & 0xFF])
            + b"".join(c.to_bytes() for c in self.channels)
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[RestrictedOpClass, int]:
        if offset + 2 > len(payload):
            raise ValueError("truncated radio-op-restriction op-class header")
        op_class = payload[offset]
        count = payload[offset + 1]
        start = offset + 2
        end = start + count * RestrictedChannel.SIZE
        if end > len(payload):
            raise ValueError("truncated radio-op-restriction channel list")
        channels = [
            RestrictedChannel.parse(payload, start + i * RestrictedChannel.SIZE)
            for i in range(count)
        ]
        return cls(op_class=op_class, channels=channels), end - offset


@dataclass(slots=True)
class RadioOperationRestriction:
    TLV_TYPE: ClassVar[int] = 0x8C
    TLV_NAME: ClassVar[str] = "Radio operation restriction"

    radio_id: bytes
    operating_classes: list[RestrictedOpClass] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.radio_id) != MAC_LEN:
            raise ValueError("radio_id must be 6 bytes")
        if len(self.operating_classes) > 0xFF:
            raise ValueError("too many operating classes (8-bit count)")

    def to_payload(self) -> bytes:
        return (
            bytes(self.radio_id)
            + bytes([len(self.operating_classes)])
            + b"".join(oc.to_bytes() for oc in self.operating_classes)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> RadioOperationRestriction:
        if len(payload) < MAC_LEN + 1:
            raise ValueError("Radio op restriction TLV too short")
        rid = parse_mac(payload)
        count = payload[MAC_LEN]
        offset = MAC_LEN + 1
        items: list[RestrictedOpClass] = []
        for _ in range(count):
            oc, consumed = RestrictedOpClass.parse(payload, offset)
            items.append(oc)
            offset += consumed
        if offset != len(payload):
            raise ValueError(
                f"Radio op restriction TLV has {len(payload) - offset} trailing bytes"
            )
        return cls(radio_id=rid, operating_classes=items)


register_typed(RadioOperationRestriction, spec_ref="Multi-AP v1.0 §17.2.14")


@dataclass(slots=True)
class TransmitPowerLimit:
    TLV_TYPE: ClassVar[int] = 0x8D
    TLV_NAME: ClassVar[str] = "Transmit power limit"

    radio_id: bytes
    transmit_power_eirp_dbm: int

    SIZE: ClassVar[int] = MAC_LEN + 1

    def __post_init__(self) -> None:
        if len(self.radio_id) != MAC_LEN:
            raise ValueError("radio_id must be 6 bytes")

    def to_payload(self) -> bytes:
        return bytes(self.radio_id) + bytes([self.transmit_power_eirp_dbm & 0xFF])

    @classmethod
    def from_payload(cls, payload: bytes) -> TransmitPowerLimit:
        if len(payload) != cls.SIZE:
            raise ValueError(
                f"Transmit power limit TLV must be {cls.SIZE} bytes, got {len(payload)}"
            )
        return cls(radio_id=parse_mac(payload), transmit_power_eirp_dbm=payload[MAC_LEN])


register_typed(TransmitPowerLimit, spec_ref="Multi-AP v1.0 §17.2.15")


@dataclass(slots=True)
class ChannelSelectionResponse:
    TLV_TYPE: ClassVar[int] = 0x8E
    TLV_NAME: ClassVar[str] = "Channel selection response"

    radio_id: bytes
    #: 0=accept, 1=decline (preference violation), 2=decline (op required), 3=decline (other).
    response_code: int

    SIZE: ClassVar[int] = MAC_LEN + 1

    def __post_init__(self) -> None:
        if len(self.radio_id) != MAC_LEN:
            raise ValueError("radio_id must be 6 bytes")

    def to_payload(self) -> bytes:
        return bytes(self.radio_id) + bytes([self.response_code & 0xFF])

    @classmethod
    def from_payload(cls, payload: bytes) -> ChannelSelectionResponse:
        if len(payload) != cls.SIZE:
            raise ValueError(
                f"Channel selection response TLV must be {cls.SIZE} bytes, got {len(payload)}"
            )
        return cls(radio_id=parse_mac(payload), response_code=payload[MAC_LEN])


register_typed(ChannelSelectionResponse, spec_ref="Multi-AP v1.0 §17.2.16")


@dataclass(slots=True)
class OperatingChannelOpClass:
    op_class: int
    channel: int

    SIZE: ClassVar[int] = 2

    def to_bytes(self) -> bytes:
        return bytes([self.op_class & 0xFF, self.channel & 0xFF])

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> OperatingChannelOpClass:
        if offset + cls.SIZE > len(payload):
            raise ValueError("truncated operating-channel op-class entry")
        return cls(op_class=payload[offset], channel=payload[offset + 1])


@dataclass(slots=True)
class OperatingChannelReport:
    TLV_TYPE: ClassVar[int] = 0x8F
    TLV_NAME: ClassVar[str] = "Operating channel report"

    radio_id: bytes
    operating_classes: list[OperatingChannelOpClass] = field(default_factory=list)
    current_transmit_power_dbm: int = 0

    def __post_init__(self) -> None:
        if len(self.radio_id) != MAC_LEN:
            raise ValueError("radio_id must be 6 bytes")
        if len(self.operating_classes) > 0xFF:
            raise ValueError("too many operating classes (8-bit count)")

    def to_payload(self) -> bytes:
        return (
            bytes(self.radio_id)
            + bytes([len(self.operating_classes)])
            + b"".join(oc.to_bytes() for oc in self.operating_classes)
            + bytes([self.current_transmit_power_dbm & 0xFF])
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> OperatingChannelReport:
        if len(payload) < MAC_LEN + 2:
            raise ValueError("Operating channel report TLV too short")
        rid = parse_mac(payload)
        count = payload[MAC_LEN]
        expected = MAC_LEN + 1 + count * OperatingChannelOpClass.SIZE + 1
        if len(payload) != expected:
            raise ValueError(
                f"Operating channel report length mismatch: expected {expected}, got {len(payload)}"
            )
        ocs = [
            OperatingChannelOpClass.parse(payload, MAC_LEN + 1 + i * OperatingChannelOpClass.SIZE)
            for i in range(count)
        ]
        tx_power = payload[MAC_LEN + 1 + count * OperatingChannelOpClass.SIZE]
        return cls(
            radio_id=rid,
            operating_classes=ocs,
            current_transmit_power_dbm=tx_power,
        )


register_typed(OperatingChannelReport, spec_ref="Multi-AP v1.0 §17.2.17")


# ---------------------------------------------------------------------------
# 0x90 Client Info — §17.2.18
# 0x91 Client Capability Report — §17.2.19
# 0x92 Client Association Event — §17.2.20
# 0x95 STA MAC Address Type — §17.2.23
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ClientInfo:
    TLV_TYPE: ClassVar[int] = 0x90
    TLV_NAME: ClassVar[str] = "Client info"

    bssid: bytes
    client_mac: bytes

    SIZE: ClassVar[int] = 2 * MAC_LEN

    def __post_init__(self) -> None:
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")
        if len(self.client_mac) != MAC_LEN:
            raise ValueError("client_mac must be 6 bytes")

    def to_payload(self) -> bytes:
        return bytes(self.bssid) + bytes(self.client_mac)

    @classmethod
    def from_payload(cls, payload: bytes) -> ClientInfo:
        if len(payload) != cls.SIZE:
            raise ValueError(
                f"Client info TLV must be {cls.SIZE} bytes, got {len(payload)}"
            )
        return cls(
            bssid=parse_mac(payload, 0),
            client_mac=parse_mac(payload, BSSID_LEN),
        )


register_typed(ClientInfo, spec_ref="Multi-AP v1.0 §17.2.18")


@dataclass(slots=True)
class ClientCapabilityReport:
    TLV_TYPE: ClassVar[int] = 0x91
    TLV_NAME: ClassVar[str] = "Client capability report"

    #: 0 = success, 1 = failure.
    result_code: int
    #: IEEE 802.11 (re)association request frame body; only present on success.
    frame_body: bytes = b""

    def to_payload(self) -> bytes:
        return bytes([self.result_code & 0xFF]) + bytes(self.frame_body)

    @classmethod
    def from_payload(cls, payload: bytes) -> ClientCapabilityReport:
        if not payload:
            raise ValueError("Client capability report TLV needs a result-code byte")
        return cls(result_code=payload[0], frame_body=bytes(payload[1:]))


register_typed(ClientCapabilityReport, spec_ref="Multi-AP v1.0 §17.2.19")


@dataclass(slots=True)
class ClientAssociationEvent:
    TLV_TYPE: ClassVar[int] = 0x92
    TLV_NAME: ClassVar[str] = "Client association event"

    client_mac: bytes
    bssid: bytes
    associated: bool  # bit 7 of the event byte

    SIZE: ClassVar[int] = 2 * MAC_LEN + 1

    def __post_init__(self) -> None:
        if len(self.client_mac) != MAC_LEN:
            raise ValueError("client_mac must be 6 bytes")
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")

    def to_payload(self) -> bytes:
        event = 0x80 if self.associated else 0x00
        return bytes(self.client_mac) + bytes(self.bssid) + bytes([event])

    @classmethod
    def from_payload(cls, payload: bytes) -> ClientAssociationEvent:
        if len(payload) != cls.SIZE:
            raise ValueError(
                f"Client association event TLV must be {cls.SIZE} bytes, got {len(payload)}"
            )
        return cls(
            client_mac=parse_mac(payload, 0),
            bssid=parse_mac(payload, MAC_LEN),
            associated=bool(payload[2 * MAC_LEN] & 0x80),
        )


register_typed(ClientAssociationEvent, spec_ref="Multi-AP v1.0 §17.2.20")


@dataclass(slots=True)
class StaMacAddressType:
    TLV_TYPE: ClassVar[int] = 0x95
    TLV_NAME: ClassVar[str] = "STA MAC address"

    sta_mac: bytes

    def __post_init__(self) -> None:
        if len(self.sta_mac) != MAC_LEN:
            raise ValueError("sta_mac must be 6 bytes")

    def to_payload(self) -> bytes:
        return bytes(self.sta_mac)

    @classmethod
    def from_payload(cls, payload: bytes) -> StaMacAddressType:
        return cls(sta_mac=parse_mac(payload))


register_typed(StaMacAddressType, spec_ref="Multi-AP v1.0 §17.2.23")


# ---------------------------------------------------------------------------
# 0x93 AP Metric Query — §17.2.21
# 0x94 AP Metrics — §17.2.22
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ApMetricQuery:
    TLV_TYPE: ClassVar[int] = 0x93
    TLV_NAME: ClassVar[str] = "AP metric query"

    bssids: list[bytes] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.bssids) > 0xFF:
            raise ValueError("too many BSSIDs (8-bit count)")
        for b in self.bssids:
            if len(b) != BSSID_LEN:
                raise ValueError("BSSID must be 6 bytes")

    def to_payload(self) -> bytes:
        return bytes([len(self.bssids)]) + b"".join(bytes(b) for b in self.bssids)

    @classmethod
    def from_payload(cls, payload: bytes) -> ApMetricQuery:
        if not payload:
            raise ValueError("AP metric query TLV needs a count byte")
        count = payload[0]
        expected = 1 + count * BSSID_LEN
        if len(payload) != expected:
            raise ValueError(
                f"AP metric query length mismatch: expected {expected}, got {len(payload)}"
            )
        bssids = [
            bytes(payload[1 + i * BSSID_LEN : 1 + (i + 1) * BSSID_LEN]) for i in range(count)
        ]
        return cls(bssids=bssids)


register_typed(ApMetricQuery, spec_ref="Multi-AP v1.0 §17.2.21")


@dataclass(slots=True)
class ApMetrics:
    TLV_TYPE: ClassVar[int] = 0x94
    TLV_NAME: ClassVar[str] = "AP metrics"

    bssid: bytes
    channel_utilization: int
    num_associated_stas: int  # u16 BE
    #: ESP info as raw bytes (1-byte indicator + 0..4 x 3-byte ESP records).
    #: Interpretation is left to the UI / higher-level analyzers.
    esp_info: bytes = b""

    _STATIC: ClassVar[struct.Struct] = struct.Struct(">BH")

    def __post_init__(self) -> None:
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")

    def to_payload(self) -> bytes:
        return (
            bytes(self.bssid)
            + self._STATIC.pack(self.channel_utilization & 0xFF, self.num_associated_stas & 0xFFFF)
            + bytes(self.esp_info)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> ApMetrics:
        if len(payload) < BSSID_LEN + cls._STATIC.size:
            raise ValueError("AP metrics TLV too short")
        ch_util, num_stas = cls._STATIC.unpack_from(payload, BSSID_LEN)
        return cls(
            bssid=parse_mac(payload, 0),
            channel_utilization=ch_util,
            num_associated_stas=num_stas,
            esp_info=bytes(payload[BSSID_LEN + cls._STATIC.size :]),
        )


register_typed(ApMetrics, spec_ref="Multi-AP v1.0 §17.2.22")


# ---------------------------------------------------------------------------
# 0x96 Associated STA Link Metrics — §17.2.24
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class AssociatedStaLink:
    bssid: bytes
    earliest_measurement_ms: int  # u32 BE
    estimated_dl_mac_rate_mbps: int  # u32 BE
    estimated_ul_mac_rate_mbps: int  # u32 BE
    uplink_rcpi: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(">IIIB")
    SIZE: ClassVar[int] = BSSID_LEN + _STRUCT.size

    def __post_init__(self) -> None:
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")

    def to_bytes(self) -> bytes:
        return bytes(self.bssid) + self._STRUCT.pack(
            self.earliest_measurement_ms & 0xFFFFFFFF,
            self.estimated_dl_mac_rate_mbps & 0xFFFFFFFF,
            self.estimated_ul_mac_rate_mbps & 0xFFFFFFFF,
            self.uplink_rcpi & 0xFF,
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> AssociatedStaLink:
        if offset + cls.SIZE > len(payload):
            raise ValueError("truncated associated-STA-link entry")
        bssid = parse_mac(payload, offset)
        earliest, dl, ul, rcpi = cls._STRUCT.unpack_from(payload, offset + BSSID_LEN)
        return cls(
            bssid=bssid,
            earliest_measurement_ms=earliest,
            estimated_dl_mac_rate_mbps=dl,
            estimated_ul_mac_rate_mbps=ul,
            uplink_rcpi=rcpi,
        )


@dataclass(slots=True)
class AssociatedStaLinkMetrics:
    TLV_TYPE: ClassVar[int] = 0x96
    TLV_NAME: ClassVar[str] = "Associated STA link metrics"

    sta_mac: bytes
    bsses: list[AssociatedStaLink] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.sta_mac) != MAC_LEN:
            raise ValueError("sta_mac must be 6 bytes")
        if len(self.bsses) > 0xFF:
            raise ValueError("too many BSSes (8-bit count)")

    def to_payload(self) -> bytes:
        return (
            bytes(self.sta_mac)
            + bytes([len(self.bsses)])
            + b"".join(b.to_bytes() for b in self.bsses)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> AssociatedStaLinkMetrics:
        if len(payload) < MAC_LEN + 1:
            raise ValueError("Associated STA link metrics TLV too short")
        sta = parse_mac(payload)
        count = payload[MAC_LEN]
        expected = MAC_LEN + 1 + count * AssociatedStaLink.SIZE
        if len(payload) != expected:
            raise ValueError(
                f"Associated STA link metrics length mismatch: expected {expected}, "
                f"got {len(payload)}"
            )
        bsses = [
            AssociatedStaLink.parse(payload, MAC_LEN + 1 + i * AssociatedStaLink.SIZE)
            for i in range(count)
        ]
        return cls(sta_mac=sta, bsses=bsses)


register_typed(AssociatedStaLinkMetrics, spec_ref="Multi-AP v1.0 §17.2.24")


# ---------------------------------------------------------------------------
# 0x97 Unassociated STA Link Metrics Query — §17.2.25
# 0x98 Unassociated STA Link Metrics Response — §17.2.26
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class UnassociatedStaQueryChannel:
    channel: int
    sta_macs: list[bytes] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        return (
            bytes([self.channel & 0xFF, len(self.sta_macs) & 0xFF])
            + b"".join(bytes(m) for m in self.sta_macs)
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[UnassociatedStaQueryChannel, int]:
        if offset + 2 > len(payload):
            raise ValueError("truncated unassociated-STA query channel header")
        channel = payload[offset]
        count = payload[offset + 1]
        start = offset + 2
        end = start + count * MAC_LEN
        if end > len(payload):
            raise ValueError("truncated unassociated-STA query MAC list")
        macs = [bytes(payload[start + i * MAC_LEN : start + (i + 1) * MAC_LEN]) for i in range(count)]
        return cls(channel=channel, sta_macs=macs), end - offset


@dataclass(slots=True)
class UnassociatedStaLinkMetricsQuery:
    TLV_TYPE: ClassVar[int] = 0x97
    TLV_NAME: ClassVar[str] = "Unassociated STA link metrics query"

    operating_class: int
    channels: list[UnassociatedStaQueryChannel] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.channels) > 0xFF:
            raise ValueError("too many channels (8-bit count)")

    def to_payload(self) -> bytes:
        return (
            bytes([self.operating_class & 0xFF, len(self.channels) & 0xFF])
            + b"".join(c.to_bytes() for c in self.channels)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> UnassociatedStaLinkMetricsQuery:
        if len(payload) < 2:
            raise ValueError("Unassociated STA link metrics query TLV too short")
        op_class = payload[0]
        count = payload[1]
        offset = 2
        channels: list[UnassociatedStaQueryChannel] = []
        for _ in range(count):
            ch, consumed = UnassociatedStaQueryChannel.parse(payload, offset)
            channels.append(ch)
            offset += consumed
        if offset != len(payload):
            raise ValueError(
                f"Unassociated STA query has {len(payload) - offset} trailing bytes"
            )
        return cls(operating_class=op_class, channels=channels)


register_typed(UnassociatedStaLinkMetricsQuery, spec_ref="Multi-AP v1.0 §17.2.25")


@dataclass(slots=True)
class UnassociatedStaResponseEntry:
    sta_mac: bytes
    channel: int
    time_delta_ms: int  # u32 BE
    uplink_rcpi: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(">BIB")
    SIZE: ClassVar[int] = MAC_LEN + _STRUCT.size

    def to_bytes(self) -> bytes:
        return bytes(self.sta_mac) + self._STRUCT.pack(
            self.channel & 0xFF,
            self.time_delta_ms & 0xFFFFFFFF,
            self.uplink_rcpi & 0xFF,
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> UnassociatedStaResponseEntry:
        if offset + cls.SIZE > len(payload):
            raise ValueError("truncated unassociated-STA response entry")
        ch, delta, rcpi = cls._STRUCT.unpack_from(payload, offset + MAC_LEN)
        return cls(
            sta_mac=parse_mac(payload, offset),
            channel=ch,
            time_delta_ms=delta,
            uplink_rcpi=rcpi,
        )


@dataclass(slots=True)
class UnassociatedStaLinkMetricsResponse:
    TLV_TYPE: ClassVar[int] = 0x98
    TLV_NAME: ClassVar[str] = "Unassociated STA link metrics response"

    operating_class: int
    entries: list[UnassociatedStaResponseEntry] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.entries) > 0xFF:
            raise ValueError("too many entries (8-bit count)")

    def to_payload(self) -> bytes:
        return (
            bytes([self.operating_class & 0xFF, len(self.entries) & 0xFF])
            + b"".join(e.to_bytes() for e in self.entries)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> UnassociatedStaLinkMetricsResponse:
        if len(payload) < 2:
            raise ValueError("Unassociated STA response TLV too short")
        op_class = payload[0]
        count = payload[1]
        expected = 2 + count * UnassociatedStaResponseEntry.SIZE
        if len(payload) != expected:
            raise ValueError(
                f"Unassociated STA response length mismatch: expected {expected}, "
                f"got {len(payload)}"
            )
        entries = [
            UnassociatedStaResponseEntry.parse(payload, 2 + i * UnassociatedStaResponseEntry.SIZE)
            for i in range(count)
        ]
        return cls(operating_class=op_class, entries=entries)


register_typed(UnassociatedStaLinkMetricsResponse, spec_ref="Multi-AP v1.0 §17.2.26")


# ---------------------------------------------------------------------------
# 0x99 Beacon Metrics Query — §17.2.27
# 0x9A Beacon Metrics Response — §17.2.28
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class BeaconApChannelReport:
    """One AP channel report sub-element used in a Beacon Metrics Query.

    Wire layout per spec: length (u8) followed by op_class (u8) and
    (length - 1) channel bytes.
    """

    op_class: int
    channels: list[int] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        length = 1 + len(self.channels)
        if length > 0xFF:
            raise ValueError("too many channels for AP channel report")
        return bytes([length, self.op_class & 0xFF]) + bytes(c & 0xFF for c in self.channels)

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[BeaconApChannelReport, int]:
        if offset + 1 > len(payload):
            raise ValueError("truncated AP channel report length")
        length = payload[offset]
        if length < 1:
            raise ValueError("AP channel report length must be >= 1")
        end = offset + 1 + length
        if end > len(payload):
            raise ValueError("truncated AP channel report body")
        op_class = payload[offset + 1]
        channels = list(payload[offset + 2 : end])
        return cls(op_class=op_class, channels=channels), end - offset


@dataclass(slots=True)
class BeaconMetricsQuery:
    TLV_TYPE: ClassVar[int] = 0x99
    TLV_NAME: ClassVar[str] = "Beacon metrics query"

    sta_mac: bytes
    operating_class: int
    channel: int  # 255 = wildcard
    bssid: bytes
    reporting_detail: int
    ssid: bytes
    ap_channel_reports: list[BeaconApChannelReport] = field(default_factory=list)
    element_ids: list[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.sta_mac) != MAC_LEN:
            raise ValueError("sta_mac must be 6 bytes")
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")
        if len(self.ssid) > 0xFF:
            raise ValueError("SSID exceeds 8-bit length field")
        if len(self.ap_channel_reports) > 0xFF:
            raise ValueError("too many AP channel reports (8-bit count)")
        if len(self.element_ids) > 0xFF:
            raise ValueError("too many element IDs (8-bit count)")

    def to_payload(self) -> bytes:
        return (
            bytes(self.sta_mac)
            + bytes([self.operating_class & 0xFF, self.channel & 0xFF])
            + bytes(self.bssid)
            + bytes([self.reporting_detail & 0xFF, len(self.ssid)])
            + bytes(self.ssid)
            + bytes([len(self.ap_channel_reports)])
            + b"".join(r.to_bytes() for r in self.ap_channel_reports)
            + bytes([len(self.element_ids)])
            + bytes(e & 0xFF for e in self.element_ids)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> BeaconMetricsQuery:
        offset = 0
        if offset + MAC_LEN + 2 + BSSID_LEN + 2 > len(payload):
            raise ValueError("Beacon metrics query TLV too short")
        sta = parse_mac(payload, offset)
        offset += MAC_LEN
        op_class = payload[offset]
        channel = payload[offset + 1]
        offset += 2
        bssid = parse_mac(payload, offset)
        offset += BSSID_LEN
        reporting_detail = payload[offset]
        offset += 1
        ssid_len = payload[offset]
        offset += 1
        if offset + ssid_len > len(payload):
            raise ValueError("truncated beacon-metrics SSID")
        ssid = bytes(payload[offset : offset + ssid_len])
        offset += ssid_len
        if offset + 1 > len(payload):
            raise ValueError("truncated AP channel report count")
        ap_count = payload[offset]
        offset += 1
        reports: list[BeaconApChannelReport] = []
        for _ in range(ap_count):
            r, consumed = BeaconApChannelReport.parse(payload, offset)
            reports.append(r)
            offset += consumed
        if offset + 1 > len(payload):
            raise ValueError("truncated element-ID count")
        eid_count = payload[offset]
        offset += 1
        if offset + eid_count != len(payload):
            raise ValueError(
                f"Beacon metrics query length mismatch at tail: "
                f"expected {eid_count}, have {len(payload) - offset}"
            )
        eids = list(payload[offset : offset + eid_count])
        return cls(
            sta_mac=sta,
            operating_class=op_class,
            channel=channel,
            bssid=bssid,
            reporting_detail=reporting_detail,
            ssid=ssid,
            ap_channel_reports=reports,
            element_ids=eids,
        )


register_typed(BeaconMetricsQuery, spec_ref="Multi-AP v1.0 §17.2.27")


@dataclass(slots=True)
class BeaconMetricsResponse:
    TLV_TYPE: ClassVar[int] = 0x9A
    TLV_NAME: ClassVar[str] = "Beacon metrics response"

    sta_mac: bytes
    reserved: int = 0
    #: Each measurement report is a complete IEEE 802.11 element
    #: (Element ID + Length + body). Stored opaquely; the UI re-parses
    #: them when displaying.
    measurement_reports: list[bytes] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.sta_mac) != MAC_LEN:
            raise ValueError("sta_mac must be 6 bytes")
        if len(self.measurement_reports) > 0xFF:
            raise ValueError("too many measurement reports (8-bit count)")

    def to_payload(self) -> bytes:
        return (
            bytes(self.sta_mac)
            + bytes([self.reserved & 0xFF, len(self.measurement_reports)])
            + b"".join(bytes(r) for r in self.measurement_reports)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> BeaconMetricsResponse:
        if len(payload) < MAC_LEN + 2:
            raise ValueError("Beacon metrics response TLV too short")
        sta = parse_mac(payload)
        reserved = payload[MAC_LEN]
        count = payload[MAC_LEN + 1]
        offset = MAC_LEN + 2
        reports: list[bytes] = []
        for _ in range(count):
            if offset + 2 > len(payload):
                raise ValueError("truncated 802.11 measurement-report header")
            # element_id at offset, length at offset+1; full element is 2+length bytes
            length = payload[offset + 1]
            end = offset + 2 + length
            if end > len(payload):
                raise ValueError("truncated 802.11 measurement-report body")
            reports.append(bytes(payload[offset:end]))
            offset = end
        if offset != len(payload):
            raise ValueError(
                f"Beacon metrics response has {len(payload) - offset} trailing bytes"
            )
        return cls(sta_mac=sta, reserved=reserved, measurement_reports=reports)


register_typed(BeaconMetricsResponse, spec_ref="Multi-AP v1.0 §17.2.28")


# ---------------------------------------------------------------------------
# 0x9B Steering Request — §17.2.29
# 0x9C Steering BTM Report — §17.2.30
# 0x9D Client Association Control Request — §17.2.31
# 0x9E Backhaul Steering Request — §17.2.32
# 0x9F Backhaul Steering Response — §17.2.33
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SteeringTargetBssid:
    bssid: bytes
    op_class: int
    channel: int

    SIZE: ClassVar[int] = BSSID_LEN + 2

    def __post_init__(self) -> None:
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")

    def to_bytes(self) -> bytes:
        return bytes(self.bssid) + bytes([self.op_class & 0xFF, self.channel & 0xFF])

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> SteeringTargetBssid:
        if offset + cls.SIZE > len(payload):
            raise ValueError("truncated steering-target entry")
        return cls(
            bssid=parse_mac(payload, offset),
            op_class=payload[offset + BSSID_LEN],
            channel=payload[offset + BSSID_LEN + 1],
        )


@dataclass(slots=True)
class SteeringRequest:
    TLV_TYPE: ClassVar[int] = 0x9B
    TLV_NAME: ClassVar[str] = "Steering request"

    bssid: bytes
    request_mode_flags: int  # bit 7 mandate, bit 6 BTM disassoc imminent, bit 5 BTM abridged
    steering_opportunity_window_s: int  # u16 BE
    btm_disassociation_timer_tus: int  # u16 BE
    sta_macs: list[bytes] = field(default_factory=list)
    target_bssids: list[SteeringTargetBssid] = field(default_factory=list)

    _STATIC: ClassVar[struct.Struct] = struct.Struct(">BHH")

    def __post_init__(self) -> None:
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")
        if len(self.sta_macs) > 0xFF:
            raise ValueError("too many STAs (8-bit count)")
        if len(self.target_bssids) > 0xFF:
            raise ValueError("too many targets (8-bit count)")
        for m in self.sta_macs:
            if len(m) != MAC_LEN:
                raise ValueError("STA MAC must be 6 bytes")

    def to_payload(self) -> bytes:
        return (
            bytes(self.bssid)
            + self._STATIC.pack(
                self.request_mode_flags & 0xFF,
                self.steering_opportunity_window_s & 0xFFFF,
                self.btm_disassociation_timer_tus & 0xFFFF,
            )
            + bytes([len(self.sta_macs)])
            + b"".join(bytes(m) for m in self.sta_macs)
            + bytes([len(self.target_bssids)])
            + b"".join(t.to_bytes() for t in self.target_bssids)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> SteeringRequest:
        head = BSSID_LEN + cls._STATIC.size + 1
        if len(payload) < head:
            raise ValueError("Steering request TLV too short")
        bssid = parse_mac(payload)
        mode, window, btm_timer = cls._STATIC.unpack_from(payload, BSSID_LEN)
        offset = BSSID_LEN + cls._STATIC.size
        sta_count = payload[offset]
        offset += 1
        end_sta = offset + sta_count * MAC_LEN
        if end_sta + 1 > len(payload):
            raise ValueError("Steering request truncated at STA list")
        sta_macs = [
            bytes(payload[offset + i * MAC_LEN : offset + (i + 1) * MAC_LEN])
            for i in range(sta_count)
        ]
        offset = end_sta
        target_count = payload[offset]
        offset += 1
        end_targets = offset + target_count * SteeringTargetBssid.SIZE
        if end_targets != len(payload):
            raise ValueError(
                f"Steering request length mismatch: expected {end_targets}, got {len(payload)}"
            )
        targets = [
            SteeringTargetBssid.parse(payload, offset + i * SteeringTargetBssid.SIZE)
            for i in range(target_count)
        ]
        return cls(
            bssid=bssid,
            request_mode_flags=mode,
            steering_opportunity_window_s=window,
            btm_disassociation_timer_tus=btm_timer,
            sta_macs=sta_macs,
            target_bssids=targets,
        )


register_typed(SteeringRequest, spec_ref="Multi-AP v1.0 §17.2.29")


@dataclass(slots=True)
class SteeringBtmReport:
    TLV_TYPE: ClassVar[int] = 0x9C
    TLV_NAME: ClassVar[str] = "Steering BTM report"

    bssid: bytes
    sta_mac: bytes
    btm_status_code: int
    target_bssid: bytes | None = None  # present iff btm_status_code == 0

    _SHORT_SIZE: ClassVar[int] = 2 * MAC_LEN + 1
    _FULL_SIZE: ClassVar[int] = 2 * MAC_LEN + 1 + BSSID_LEN

    def __post_init__(self) -> None:
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")
        if len(self.sta_mac) != MAC_LEN:
            raise ValueError("sta_mac must be 6 bytes")
        if self.target_bssid is not None and len(self.target_bssid) != BSSID_LEN:
            raise ValueError("target_bssid must be 6 bytes")

    def to_payload(self) -> bytes:
        out = bytes(self.bssid) + bytes(self.sta_mac) + bytes([self.btm_status_code & 0xFF])
        if self.target_bssid is not None:
            out += bytes(self.target_bssid)
        return out

    @classmethod
    def from_payload(cls, payload: bytes) -> SteeringBtmReport:
        if len(payload) == cls._SHORT_SIZE:
            return cls(
                bssid=parse_mac(payload, 0),
                sta_mac=parse_mac(payload, BSSID_LEN),
                btm_status_code=payload[2 * MAC_LEN],
                target_bssid=None,
            )
        if len(payload) == cls._FULL_SIZE:
            return cls(
                bssid=parse_mac(payload, 0),
                sta_mac=parse_mac(payload, BSSID_LEN),
                btm_status_code=payload[2 * MAC_LEN],
                target_bssid=parse_mac(payload, 2 * MAC_LEN + 1),
            )
        raise ValueError(
            f"Steering BTM report TLV must be {cls._SHORT_SIZE} or {cls._FULL_SIZE} bytes, "
            f"got {len(payload)}"
        )


register_typed(SteeringBtmReport, spec_ref="Multi-AP v1.0 §17.2.30")


@dataclass(slots=True)
class ClientAssociationControlRequest:
    TLV_TYPE: ClassVar[int] = 0x9D
    TLV_NAME: ClassVar[str] = "Client association control request"

    bssid: bytes
    #: 0=block, 1=unblock, 2=timed-block, 3=indefinite-block.
    association_control: int
    validity_period_s: int  # u16 BE
    sta_macs: list[bytes] = field(default_factory=list)

    _STATIC: ClassVar[struct.Struct] = struct.Struct(">BH")

    def __post_init__(self) -> None:
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")
        if len(self.sta_macs) > 0xFF:
            raise ValueError("too many STAs (8-bit count)")
        for m in self.sta_macs:
            if len(m) != MAC_LEN:
                raise ValueError("STA MAC must be 6 bytes")

    def to_payload(self) -> bytes:
        return (
            bytes(self.bssid)
            + self._STATIC.pack(self.association_control & 0xFF, self.validity_period_s & 0xFFFF)
            + bytes([len(self.sta_macs)])
            + b"".join(bytes(m) for m in self.sta_macs)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> ClientAssociationControlRequest:
        head = BSSID_LEN + cls._STATIC.size + 1
        if len(payload) < head:
            raise ValueError("Client association control request TLV too short")
        bssid = parse_mac(payload)
        ac, validity = cls._STATIC.unpack_from(payload, BSSID_LEN)
        offset = BSSID_LEN + cls._STATIC.size
        count = payload[offset]
        offset += 1
        expected = offset + count * MAC_LEN
        if expected != len(payload):
            raise ValueError(
                f"Client assoc control request length mismatch: expected {expected}, "
                f"got {len(payload)}"
            )
        macs = [
            bytes(payload[offset + i * MAC_LEN : offset + (i + 1) * MAC_LEN]) for i in range(count)
        ]
        return cls(
            bssid=bssid,
            association_control=ac,
            validity_period_s=validity,
            sta_macs=macs,
        )


register_typed(ClientAssociationControlRequest, spec_ref="Multi-AP v1.0 §17.2.31")


@dataclass(slots=True)
class BackhaulSteeringRequest:
    TLV_TYPE: ClassVar[int] = 0x9E
    TLV_NAME: ClassVar[str] = "Backhaul steering request"

    backhaul_sta_mac: bytes
    target_bssid: bytes
    target_op_class: int
    target_channel: int

    SIZE: ClassVar[int] = 2 * MAC_LEN + 2

    def __post_init__(self) -> None:
        if len(self.backhaul_sta_mac) != MAC_LEN:
            raise ValueError("backhaul_sta_mac must be 6 bytes")
        if len(self.target_bssid) != BSSID_LEN:
            raise ValueError("target_bssid must be 6 bytes")

    def to_payload(self) -> bytes:
        return (
            bytes(self.backhaul_sta_mac)
            + bytes(self.target_bssid)
            + bytes([self.target_op_class & 0xFF, self.target_channel & 0xFF])
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> BackhaulSteeringRequest:
        if len(payload) != cls.SIZE:
            raise ValueError(
                f"Backhaul steering request TLV must be {cls.SIZE} bytes, got {len(payload)}"
            )
        return cls(
            backhaul_sta_mac=parse_mac(payload, 0),
            target_bssid=parse_mac(payload, MAC_LEN),
            target_op_class=payload[2 * MAC_LEN],
            target_channel=payload[2 * MAC_LEN + 1],
        )


register_typed(BackhaulSteeringRequest, spec_ref="Multi-AP v1.0 §17.2.32")


@dataclass(slots=True)
class BackhaulSteeringResponse:
    TLV_TYPE: ClassVar[int] = 0x9F
    TLV_NAME: ClassVar[str] = "Backhaul steering response"

    backhaul_sta_mac: bytes
    target_bssid: bytes
    result_code: int  # 0=success, 1=failure

    SIZE: ClassVar[int] = 2 * MAC_LEN + 1

    def __post_init__(self) -> None:
        if len(self.backhaul_sta_mac) != MAC_LEN:
            raise ValueError("backhaul_sta_mac must be 6 bytes")
        if len(self.target_bssid) != BSSID_LEN:
            raise ValueError("target_bssid must be 6 bytes")

    def to_payload(self) -> bytes:
        return (
            bytes(self.backhaul_sta_mac)
            + bytes(self.target_bssid)
            + bytes([self.result_code & 0xFF])
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> BackhaulSteeringResponse:
        if len(payload) != cls.SIZE:
            raise ValueError(
                f"Backhaul steering response TLV must be {cls.SIZE} bytes, got {len(payload)}"
            )
        return cls(
            backhaul_sta_mac=parse_mac(payload, 0),
            target_bssid=parse_mac(payload, MAC_LEN),
            result_code=payload[2 * MAC_LEN],
        )


register_typed(BackhaulSteeringResponse, spec_ref="Multi-AP v1.0 §17.2.33")


# ---------------------------------------------------------------------------
# 0xA0 Higher Layer Data — §17.2.34
# 0xA1 AP Capability — §17.2.35
# 0xA2 Associated STA Traffic Stats — §17.2.36
# 0xA3 Error Code — §17.2.37
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class HigherLayerData:
    TLV_TYPE: ClassVar[int] = 0xA0
    TLV_NAME: ClassVar[str] = "Higher layer data"

    protocol: int  # see Multi-AP v1.0 Table 17-21
    data: bytes

    def to_payload(self) -> bytes:
        return bytes([self.protocol & 0xFF]) + bytes(self.data)

    @classmethod
    def from_payload(cls, payload: bytes) -> HigherLayerData:
        if not payload:
            raise ValueError("Higher layer data TLV needs a protocol byte")
        return cls(protocol=payload[0], data=bytes(payload[1:]))


register_typed(HigherLayerData, spec_ref="Multi-AP v1.0 §17.2.34")


@dataclass(slots=True)
class ApCapability:
    TLV_TYPE: ClassVar[int] = 0xA1
    TLV_NAME: ClassVar[str] = "AP capability"

    #: bit 7: unassoc STA link metrics on a channel the AP currently operates on
    #: bit 6: unassoc STA link metrics on a non-operating channel
    #: bit 5: agent-initiated RCPI-based steering supported
    flags: int

    @property
    def unassoc_metrics_supported_channel(self) -> bool:
        return bool(self.flags & 0x80)

    @property
    def unassoc_metrics_nonoperating_channel(self) -> bool:
        return bool(self.flags & 0x40)

    @property
    def agent_initiated_rcpi_steering(self) -> bool:
        return bool(self.flags & 0x20)

    def to_payload(self) -> bytes:
        return bytes([self.flags & 0xFF])

    @classmethod
    def from_payload(cls, payload: bytes) -> ApCapability:
        if len(payload) != 1:
            raise ValueError(f"AP capability TLV must be 1 byte, got {len(payload)}")
        return cls(flags=payload[0])


register_typed(ApCapability, spec_ref="Multi-AP v1.0 §17.2.35")


@dataclass(slots=True)
class AssociatedStaTrafficStats:
    TLV_TYPE: ClassVar[int] = 0xA2
    TLV_NAME: ClassVar[str] = "Associated STA traffic stats"

    sta_mac: bytes
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    tx_packet_errors: int
    rx_packet_errors: int
    retransmission_count: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(">IIIIIII")
    SIZE: ClassVar[int] = MAC_LEN + _STRUCT.size

    def __post_init__(self) -> None:
        if len(self.sta_mac) != MAC_LEN:
            raise ValueError("sta_mac must be 6 bytes")

    def to_payload(self) -> bytes:
        return bytes(self.sta_mac) + self._STRUCT.pack(
            self.bytes_sent & 0xFFFFFFFF,
            self.bytes_received & 0xFFFFFFFF,
            self.packets_sent & 0xFFFFFFFF,
            self.packets_received & 0xFFFFFFFF,
            self.tx_packet_errors & 0xFFFFFFFF,
            self.rx_packet_errors & 0xFFFFFFFF,
            self.retransmission_count & 0xFFFFFFFF,
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> AssociatedStaTrafficStats:
        if len(payload) != cls.SIZE:
            raise ValueError(
                f"Associated STA traffic stats TLV must be {cls.SIZE} bytes, "
                f"got {len(payload)}"
            )
        fields_ = cls._STRUCT.unpack_from(payload, MAC_LEN)
        return cls(
            sta_mac=parse_mac(payload, 0),
            bytes_sent=fields_[0],
            bytes_received=fields_[1],
            packets_sent=fields_[2],
            packets_received=fields_[3],
            tx_packet_errors=fields_[4],
            rx_packet_errors=fields_[5],
            retransmission_count=fields_[6],
        )


register_typed(AssociatedStaTrafficStats, spec_ref="Multi-AP v1.0 §17.2.36")


@dataclass(slots=True)
class ErrorCode:
    TLV_TYPE: ClassVar[int] = 0xA3
    TLV_NAME: ClassVar[str] = "Error code"

    #: See Multi-AP v1.0 Table 17-23 (e.g. 1=STA assoc reject, 2=STA already associated).
    reason_code: int
    sta_mac: bytes  # may be zeros when not applicable

    SIZE: ClassVar[int] = 1 + MAC_LEN

    def __post_init__(self) -> None:
        if len(self.sta_mac) != MAC_LEN:
            raise ValueError("sta_mac must be 6 bytes")

    def to_payload(self) -> bytes:
        return bytes([self.reason_code & 0xFF]) + bytes(self.sta_mac)

    @classmethod
    def from_payload(cls, payload: bytes) -> ErrorCode:
        if len(payload) != cls.SIZE:
            raise ValueError(
                f"Error code TLV must be {cls.SIZE} bytes, got {len(payload)}"
            )
        return cls(reason_code=payload[0], sta_mac=parse_mac(payload, 1))


register_typed(ErrorCode, spec_ref="Multi-AP v1.0 §17.2.37")
