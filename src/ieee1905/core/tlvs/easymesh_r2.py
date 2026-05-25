# SPDX-License-Identifier: GPL-2.0-or-later
"""Wi-Fi EasyMesh R2 TLV implementations.

Spec: Wi-Fi Alliance *Multi-AP Specification* v2.0 §17.2.x.

R2 adds channel scanning, Profile-2 capability advertisement, traffic
separation (VLAN tagging on Multi-AP backhaul), security capability
advertising, tunneled messages, extended per-radio and per-STA metrics,
and a few error/status TLVs.

Profile-2 also defines an extended 32-bit TLV length format; that
arrives separately when we touch the wire framer (see ROADMAP note).
Every TLV here uses the standard 1-byte-type + 2-byte-length header
inherited from 1905.1.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import ClassVar

from ieee1905.core.tlvs._helpers import MAC_LEN, parse_mac, register_typed

BSSID_LEN = 6


# ---------------------------------------------------------------------------
# 0xA4 Channel Scan Reporting Policy — §17.2.38
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ChannelScanReportingPolicy:
    TLV_TYPE: ClassVar[int] = 0xA4
    TLV_NAME: ClassVar[str] = "Channel scan reporting policy"

    #: bit 7: report independent channel scans (otherwise only requested scans).
    flags: int

    @property
    def report_independent_scans(self) -> bool:
        return bool(self.flags & 0x80)

    def to_payload(self) -> bytes:
        return bytes([self.flags & 0xFF])

    @classmethod
    def from_payload(cls, payload: bytes) -> ChannelScanReportingPolicy:
        if len(payload) != 1:
            raise ValueError(
                f"Channel scan reporting policy TLV must be 1 byte, got {len(payload)}"
            )
        return cls(flags=payload[0])


register_typed(ChannelScanReportingPolicy, spec_ref="Multi-AP v2.0 §17.2.38")


# ---------------------------------------------------------------------------
# 0xA5 Channel Scan Capabilities — §17.2.39
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ChannelScanCapabilityOpClass:
    op_class: int
    channels: list[int] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        return bytes([self.op_class & 0xFF, len(self.channels) & 0xFF]) + bytes(
            c & 0xFF for c in self.channels
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[ChannelScanCapabilityOpClass, int]:
        if offset + 2 > len(payload):
            raise ValueError("truncated channel-scan op-class header")
        op_class = payload[offset]
        count = payload[offset + 1]
        start = offset + 2
        end = start + count
        if end > len(payload):
            raise ValueError("truncated channel-scan channel list")
        return cls(op_class=op_class, channels=list(payload[start:end])), end - offset


@dataclass(slots=True)
class ChannelScanCapabilityRadio:
    radio_id: bytes
    #: bit 7: only-on-boot scan supported.
    flags: int
    min_scan_interval_s: int  # u32 BE
    operating_classes: list[ChannelScanCapabilityOpClass] = field(default_factory=list)

    _STATIC: ClassVar[struct.Struct] = struct.Struct(">BI")  # flags, min_interval

    def __post_init__(self) -> None:
        if len(self.radio_id) != MAC_LEN:
            raise ValueError("radio_id must be 6 bytes")
        if len(self.operating_classes) > 0xFF:
            raise ValueError("too many operating classes (8-bit count)")

    def to_bytes(self) -> bytes:
        return (
            bytes(self.radio_id)
            + self._STATIC.pack(self.flags & 0xFF, self.min_scan_interval_s & 0xFFFFFFFF)
            + bytes([len(self.operating_classes)])
            + b"".join(oc.to_bytes() for oc in self.operating_classes)
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[ChannelScanCapabilityRadio, int]:
        start = offset
        head = MAC_LEN + cls._STATIC.size + 1
        if offset + head > len(payload):
            raise ValueError("truncated channel-scan radio header")
        radio_id = parse_mac(payload, offset)
        flags, interval = cls._STATIC.unpack_from(payload, offset + MAC_LEN)
        offset += MAC_LEN + cls._STATIC.size
        count = payload[offset]
        offset += 1
        ocs: list[ChannelScanCapabilityOpClass] = []
        for _ in range(count):
            oc, consumed = ChannelScanCapabilityOpClass.parse(payload, offset)
            ocs.append(oc)
            offset += consumed
        return (
            cls(radio_id=radio_id, flags=flags, min_scan_interval_s=interval, operating_classes=ocs),
            offset - start,
        )


@dataclass(slots=True)
class ChannelScanCapabilities:
    TLV_TYPE: ClassVar[int] = 0xA5
    TLV_NAME: ClassVar[str] = "Channel scan capabilities"

    radios: list[ChannelScanCapabilityRadio] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.radios) > 0xFF:
            raise ValueError("too many radios (8-bit count)")

    def to_payload(self) -> bytes:
        return bytes([len(self.radios)]) + b"".join(r.to_bytes() for r in self.radios)

    @classmethod
    def from_payload(cls, payload: bytes) -> ChannelScanCapabilities:
        if not payload:
            raise ValueError("Channel scan capabilities TLV needs a count byte")
        count = payload[0]
        offset = 1
        radios: list[ChannelScanCapabilityRadio] = []
        for _ in range(count):
            r, consumed = ChannelScanCapabilityRadio.parse(payload, offset)
            radios.append(r)
            offset += consumed
        if offset != len(payload):
            raise ValueError(
                f"Channel scan capabilities has {len(payload) - offset} trailing bytes"
            )
        return cls(radios=radios)


register_typed(ChannelScanCapabilities, spec_ref="Multi-AP v2.0 §17.2.39")


# ---------------------------------------------------------------------------
# 0xA6 Channel Scan Request — §17.2.40
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ChannelScanRequestOpClass:
    op_class: int
    channels: list[int] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        return bytes([self.op_class & 0xFF, len(self.channels) & 0xFF]) + bytes(
            c & 0xFF for c in self.channels
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[ChannelScanRequestOpClass, int]:
        if offset + 2 > len(payload):
            raise ValueError("truncated channel-scan-request op-class header")
        op_class = payload[offset]
        count = payload[offset + 1]
        end = offset + 2 + count
        if end > len(payload):
            raise ValueError("truncated channel-scan-request channel list")
        return cls(op_class=op_class, channels=list(payload[offset + 2 : end])), end - offset


@dataclass(slots=True)
class ChannelScanRequestRadio:
    radio_id: bytes
    operating_classes: list[ChannelScanRequestOpClass] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        return (
            bytes(self.radio_id)
            + bytes([len(self.operating_classes)])
            + b"".join(oc.to_bytes() for oc in self.operating_classes)
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[ChannelScanRequestRadio, int]:
        start = offset
        if offset + MAC_LEN + 1 > len(payload):
            raise ValueError("truncated channel-scan-request radio header")
        radio_id = parse_mac(payload, offset)
        offset += MAC_LEN
        count = payload[offset]
        offset += 1
        ocs: list[ChannelScanRequestOpClass] = []
        for _ in range(count):
            oc, consumed = ChannelScanRequestOpClass.parse(payload, offset)
            ocs.append(oc)
            offset += consumed
        return cls(radio_id=radio_id, operating_classes=ocs), offset - start


@dataclass(slots=True)
class ChannelScanRequest:
    TLV_TYPE: ClassVar[int] = 0xA6
    TLV_NAME: ClassVar[str] = "Channel scan request"

    #: bit 7 = perform fresh scan; bit 6 = return cached results allowed.
    flags: int
    radios: list[ChannelScanRequestRadio] = field(default_factory=list)

    @property
    def perform_fresh_scan(self) -> bool:
        return bool(self.flags & 0x80)

    def to_payload(self) -> bytes:
        return (
            bytes([self.flags & 0xFF, len(self.radios) & 0xFF])
            + b"".join(r.to_bytes() for r in self.radios)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> ChannelScanRequest:
        if len(payload) < 2:
            raise ValueError("Channel scan request TLV too short")
        flags = payload[0]
        count = payload[1]
        offset = 2
        radios: list[ChannelScanRequestRadio] = []
        for _ in range(count):
            r, consumed = ChannelScanRequestRadio.parse(payload, offset)
            radios.append(r)
            offset += consumed
        if offset != len(payload):
            raise ValueError(
                f"Channel scan request has {len(payload) - offset} trailing bytes"
            )
        return cls(flags=flags, radios=radios)


register_typed(ChannelScanRequest, spec_ref="Multi-AP v2.0 §17.2.40")


# ---------------------------------------------------------------------------
# 0xA7 Channel Scan Result — §17.2.41
# Complex TLV with optional BSS-Load extension per neighbor. Stored as
# structured records; the UI can re-render the neighbor list.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ChannelScanNeighbor:
    bssid: bytes
    ssid: bytes
    signal_strength: int  # RCPI (uint8)
    channel_bandwidth: str  # e.g. "20", "40", "80", "80+80", "160"
    #: bit 7: BSS Load element present (the following two fields meaningful).
    flags: int = 0
    channel_utilization: int = 0
    station_count: int = 0

    _BSS_LOAD: ClassVar[struct.Struct] = struct.Struct(">BH")

    def __post_init__(self) -> None:
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")

    @property
    def has_bss_load(self) -> bool:
        return bool(self.flags & 0x80)

    def to_bytes(self) -> bytes:
        ssid_bytes = bytes(self.ssid)
        bw_bytes = self.channel_bandwidth.encode("ascii")
        out = (
            bytes(self.bssid)
            + bytes([len(ssid_bytes)])
            + ssid_bytes
            + bytes([self.signal_strength & 0xFF, len(bw_bytes)])
            + bw_bytes
            + bytes([self.flags & 0xFF])
        )
        if self.has_bss_load:
            out += self._BSS_LOAD.pack(
                self.channel_utilization & 0xFF, self.station_count & 0xFFFF
            )
        return out

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[ChannelScanNeighbor, int]:
        start = offset
        if offset + BSSID_LEN + 1 > len(payload):
            raise ValueError("truncated scan-neighbor header")
        bssid = parse_mac(payload, offset)
        offset += BSSID_LEN
        ssid_len = payload[offset]
        offset += 1
        if offset + ssid_len + 2 > len(payload):
            raise ValueError("truncated scan-neighbor SSID/RCPI")
        ssid = bytes(payload[offset : offset + ssid_len])
        offset += ssid_len
        rcpi = payload[offset]
        bw_len = payload[offset + 1]
        offset += 2
        if offset + bw_len + 1 > len(payload):
            raise ValueError("truncated scan-neighbor bandwidth string")
        bw = bytes(payload[offset : offset + bw_len]).decode("ascii")
        offset += bw_len
        flags = payload[offset]
        offset += 1
        ch_util = 0
        sta_count = 0
        if flags & 0x80:
            if offset + cls._BSS_LOAD.size > len(payload):
                raise ValueError("truncated scan-neighbor BSS Load fields")
            ch_util, sta_count = cls._BSS_LOAD.unpack_from(payload, offset)
            offset += cls._BSS_LOAD.size
        return (
            cls(
                bssid=bssid,
                ssid=ssid,
                signal_strength=rcpi,
                channel_bandwidth=bw,
                flags=flags,
                channel_utilization=ch_util,
                station_count=sta_count,
            ),
            offset - start,
        )


@dataclass(slots=True)
class ChannelScanResult:
    TLV_TYPE: ClassVar[int] = 0xA7
    TLV_NAME: ClassVar[str] = "Channel scan result"

    radio_id: bytes
    op_class: int
    channel: int
    #: 0=success, 1=opclass unsupported, 2=channel unsupported, 3=busy,
    #: 4=scan not completed, 5=scan aborted, 6=fresh scan unsupported.
    scan_status: int
    timestamp: str = ""  # ISO 8601 per spec
    utilization: int = 0
    noise: int = 0
    neighbors: list[ChannelScanNeighbor] = field(default_factory=list)
    #: Aggregate scan duration in milliseconds (u32 BE).
    aggregate_scan_duration_ms: int = 0
    #: Scan type (u8): 0=passive, 1=active.
    scan_type: int = 0

    _COUNT: ClassVar[struct.Struct] = struct.Struct(">H")
    _AGG: ClassVar[struct.Struct] = struct.Struct(">IB")

    def __post_init__(self) -> None:
        if len(self.radio_id) != MAC_LEN:
            raise ValueError("radio_id must be 6 bytes")

    def to_payload(self) -> bytes:
        ts_bytes = self.timestamp.encode("ascii")
        return (
            bytes(self.radio_id)
            + bytes([self.op_class & 0xFF, self.channel & 0xFF, self.scan_status & 0xFF])
            + bytes([len(ts_bytes)])
            + ts_bytes
            + bytes([self.utilization & 0xFF, self.noise & 0xFF])
            + self._COUNT.pack(len(self.neighbors) & 0xFFFF)
            + b"".join(n.to_bytes() for n in self.neighbors)
            + self._AGG.pack(
                self.aggregate_scan_duration_ms & 0xFFFFFFFF, self.scan_type & 0xFF
            )
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> ChannelScanResult:
        offset = 0
        if offset + MAC_LEN + 4 > len(payload):
            raise ValueError("Channel scan result TLV too short")
        radio_id = parse_mac(payload, offset)
        offset += MAC_LEN
        op_class = payload[offset]
        channel = payload[offset + 1]
        scan_status = payload[offset + 2]
        offset += 3
        ts_len = payload[offset]
        offset += 1
        if offset + ts_len + 2 + cls._COUNT.size > len(payload):
            raise ValueError("Channel scan result truncated in fixed fields")
        timestamp = bytes(payload[offset : offset + ts_len]).decode("ascii")
        offset += ts_len
        utilization = payload[offset]
        noise = payload[offset + 1]
        offset += 2
        (n_count,) = cls._COUNT.unpack_from(payload, offset)
        offset += cls._COUNT.size
        neighbors: list[ChannelScanNeighbor] = []
        for _ in range(n_count):
            n, consumed = ChannelScanNeighbor.parse(payload, offset)
            neighbors.append(n)
            offset += consumed
        if offset + cls._AGG.size != len(payload):
            raise ValueError(
                f"Channel scan result trailing length mismatch: expected "
                f"{cls._AGG.size} bytes, have {len(payload) - offset}"
            )
        agg_duration, scan_type = cls._AGG.unpack_from(payload, offset)
        return cls(
            radio_id=radio_id,
            op_class=op_class,
            channel=channel,
            scan_status=scan_status,
            timestamp=timestamp,
            utilization=utilization,
            noise=noise,
            neighbors=neighbors,
            aggregate_scan_duration_ms=agg_duration,
            scan_type=scan_type,
        )


register_typed(ChannelScanResult, spec_ref="Multi-AP v2.0 §17.2.41")


# ---------------------------------------------------------------------------
# 0xA8 Timestamp — §17.2.42
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Timestamp:
    TLV_TYPE: ClassVar[int] = 0xA8
    TLV_NAME: ClassVar[str] = "Timestamp"

    timestamp: str  # ISO 8601

    def to_payload(self) -> bytes:
        b = self.timestamp.encode("ascii")
        return bytes([len(b) & 0xFF]) + b

    @classmethod
    def from_payload(cls, payload: bytes) -> Timestamp:
        if not payload:
            raise ValueError("Timestamp TLV needs a length byte")
        n = payload[0]
        if 1 + n != len(payload):
            raise ValueError(
                f"Timestamp TLV length mismatch: declared {n}, got {len(payload) - 1}"
            )
        return cls(timestamp=bytes(payload[1 : 1 + n]).decode("ascii"))


register_typed(Timestamp, spec_ref="Multi-AP v2.0 §17.2.42")


# ---------------------------------------------------------------------------
# 0xAA 1905 Layer Security Capability — §17.2.44
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class LayerSecurityCapability:
    TLV_TYPE: ClassVar[int] = 0xAA
    TLV_NAME: ClassVar[str] = "1905 layer security capability"

    onboarding_protocols: int  # bit 0 = DPP
    mic_algorithms: int  # bit 0 = HMAC-SHA256
    encryption_algorithms: int  # bit 0 = AES-SIV

    SIZE: ClassVar[int] = 3

    def to_payload(self) -> bytes:
        return bytes(
            [
                self.onboarding_protocols & 0xFF,
                self.mic_algorithms & 0xFF,
                self.encryption_algorithms & 0xFF,
            ]
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> LayerSecurityCapability:
        if len(payload) != cls.SIZE:
            raise ValueError(
                f"1905 layer security capability TLV must be {cls.SIZE} bytes, "
                f"got {len(payload)}"
            )
        return cls(
            onboarding_protocols=payload[0],
            mic_algorithms=payload[1],
            encryption_algorithms=payload[2],
        )


register_typed(LayerSecurityCapability, spec_ref="Multi-AP v2.0 §17.2.44")


# ---------------------------------------------------------------------------
# 0xAE Profile-2 AP Capability — §17.2.47
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Profile2ApCapability:
    TLV_TYPE: ClassVar[int] = 0xAE
    TLV_NAME: ClassVar[str] = "Profile-2 AP capability"

    reserved: int
    #: bit 7: BSS configuration parameter advertisement.
    #: bit 6: byte-count units (0=bytes, 1=KiB).
    #: bit 5: TLV-byte-count units (0=bytes, 1=KiB).
    capabilities: int
    max_prioritization_rules: int  # u8

    SIZE: ClassVar[int] = 3

    def to_payload(self) -> bytes:
        return bytes(
            [
                self.reserved & 0xFF,
                self.capabilities & 0xFF,
                self.max_prioritization_rules & 0xFF,
            ]
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> Profile2ApCapability:
        if len(payload) != cls.SIZE:
            raise ValueError(
                f"Profile-2 AP capability TLV must be {cls.SIZE} bytes, got {len(payload)}"
            )
        return cls(
            reserved=payload[0],
            capabilities=payload[1],
            max_prioritization_rules=payload[2],
        )


register_typed(Profile2ApCapability, spec_ref="Multi-AP v2.0 §17.2.47")


# ---------------------------------------------------------------------------
# 0xAF Default 802.1Q Settings — §17.2.48
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Default8021QSettings:
    TLV_TYPE: ClassVar[int] = 0xAF
    TLV_NAME: ClassVar[str] = "Default 802.1Q settings"

    primary_vlan_id: int  # u16 BE
    default_pcp: int  # u8 (bits 7-5 in spec; we expose the raw byte)

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(">HB")

    def to_payload(self) -> bytes:
        return self._STRUCT.pack(self.primary_vlan_id & 0xFFFF, self.default_pcp & 0xFF)

    @classmethod
    def from_payload(cls, payload: bytes) -> Default8021QSettings:
        if len(payload) != cls._STRUCT.size:
            raise ValueError(
                f"Default 802.1Q settings TLV must be {cls._STRUCT.size} bytes, got {len(payload)}"
            )
        vid, pcp = cls._STRUCT.unpack_from(payload, 0)
        return cls(primary_vlan_id=vid, default_pcp=pcp)


register_typed(Default8021QSettings, spec_ref="Multi-AP v2.0 §17.2.48")


# ---------------------------------------------------------------------------
# 0xB0 Traffic Separation Policy — §17.2.49
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SsidVlanMapping:
    ssid: bytes
    vlan_id: int  # u16 BE

    _VLAN: ClassVar[struct.Struct] = struct.Struct(">H")

    def to_bytes(self) -> bytes:
        return bytes([len(self.ssid) & 0xFF]) + bytes(self.ssid) + self._VLAN.pack(
            self.vlan_id & 0xFFFF
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[SsidVlanMapping, int]:
        start = offset
        if offset + 1 > len(payload):
            raise ValueError("truncated SSID-VLAN mapping length")
        n = payload[offset]
        offset += 1
        if offset + n + cls._VLAN.size > len(payload):
            raise ValueError("truncated SSID-VLAN mapping body")
        ssid = bytes(payload[offset : offset + n])
        offset += n
        (vid,) = cls._VLAN.unpack_from(payload, offset)
        offset += cls._VLAN.size
        return cls(ssid=ssid, vlan_id=vid), offset - start


@dataclass(slots=True)
class TrafficSeparationPolicy:
    TLV_TYPE: ClassVar[int] = 0xB0
    TLV_NAME: ClassVar[str] = "Traffic separation policy"

    mappings: list[SsidVlanMapping] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.mappings) > 0xFF:
            raise ValueError("too many SSID mappings (8-bit count)")

    def to_payload(self) -> bytes:
        return bytes([len(self.mappings)]) + b"".join(m.to_bytes() for m in self.mappings)

    @classmethod
    def from_payload(cls, payload: bytes) -> TrafficSeparationPolicy:
        if not payload:
            raise ValueError("Traffic separation policy TLV needs a count byte")
        count = payload[0]
        offset = 1
        items: list[SsidVlanMapping] = []
        for _ in range(count):
            m, consumed = SsidVlanMapping.parse(payload, offset)
            items.append(m)
            offset += consumed
        if offset != len(payload):
            raise ValueError(
                f"Traffic separation policy has {len(payload) - offset} trailing bytes"
            )
        return cls(mappings=items)


register_typed(TrafficSeparationPolicy, spec_ref="Multi-AP v2.0 §17.2.49")


# ---------------------------------------------------------------------------
# 0xBC Profile-2 Error Code — §17.2.51
# Reason codes per Multi-AP v2.0 Table 17-30 (1=service-prio-rule not
# found, 2=resource limit, 3=unsupported, ... etc.). We store the raw byte.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Profile2ErrorCode:
    TLV_TYPE: ClassVar[int] = 0xBC
    TLV_NAME: ClassVar[str] = "Profile-2 error code"

    reason_code: int
    bssid: bytes = b"\x00" * 6  # may be all-zero when not applicable

    SIZE: ClassVar[int] = 1 + BSSID_LEN

    def __post_init__(self) -> None:
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")

    def to_payload(self) -> bytes:
        return bytes([self.reason_code & 0xFF]) + bytes(self.bssid)

    @classmethod
    def from_payload(cls, payload: bytes) -> Profile2ErrorCode:
        if len(payload) != cls.SIZE:
            raise ValueError(
                f"Profile-2 error code TLV must be {cls.SIZE} bytes, got {len(payload)}"
            )
        return cls(reason_code=payload[0], bssid=parse_mac(payload, 1))


register_typed(Profile2ErrorCode, spec_ref="Multi-AP v2.0 §17.2.51")


# ---------------------------------------------------------------------------
# 0xBE AP Radio Advanced Capabilities — §17.2.52
# 0xBF Association Status Notification — §17.2.53
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ApRadioAdvancedCapabilities:
    TLV_TYPE: ClassVar[int] = 0xBE
    TLV_NAME: ClassVar[str] = "AP radio advanced capabilities"

    radio_id: bytes
    #: bit 7: Combined Front/Back capability supported.
    #: bit 6: Combined P1/P2 capability supported.
    flags: int

    SIZE: ClassVar[int] = MAC_LEN + 1

    def __post_init__(self) -> None:
        if len(self.radio_id) != MAC_LEN:
            raise ValueError("radio_id must be 6 bytes")

    def to_payload(self) -> bytes:
        return bytes(self.radio_id) + bytes([self.flags & 0xFF])

    @classmethod
    def from_payload(cls, payload: bytes) -> ApRadioAdvancedCapabilities:
        if len(payload) != cls.SIZE:
            raise ValueError(
                f"AP radio advanced capabilities TLV must be {cls.SIZE} bytes, "
                f"got {len(payload)}"
            )
        return cls(radio_id=parse_mac(payload), flags=payload[MAC_LEN])


register_typed(ApRadioAdvancedCapabilities, spec_ref="Multi-AP v2.0 §17.2.52")


@dataclass(slots=True)
class BssidAssociationStatus:
    bssid: bytes
    association_allowed: bool  # 0 = stop accepting; 1 = accept

    SIZE: ClassVar[int] = BSSID_LEN + 1

    def __post_init__(self) -> None:
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")

    def to_bytes(self) -> bytes:
        return bytes(self.bssid) + bytes([1 if self.association_allowed else 0])

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> BssidAssociationStatus:
        if offset + cls.SIZE > len(payload):
            raise ValueError("truncated BSSID association status entry")
        return cls(
            bssid=parse_mac(payload, offset),
            association_allowed=bool(payload[offset + BSSID_LEN] & 0x01),
        )


@dataclass(slots=True)
class AssociationStatusNotification:
    TLV_TYPE: ClassVar[int] = 0xBF
    TLV_NAME: ClassVar[str] = "Association status notification"

    bsses: list[BssidAssociationStatus] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.bsses) > 0xFF:
            raise ValueError("too many BSSes (8-bit count)")

    def to_payload(self) -> bytes:
        return bytes([len(self.bsses)]) + b"".join(b.to_bytes() for b in self.bsses)

    @classmethod
    def from_payload(cls, payload: bytes) -> AssociationStatusNotification:
        if not payload:
            raise ValueError("Association status notification TLV needs a count byte")
        count = payload[0]
        expected = 1 + count * BssidAssociationStatus.SIZE
        if len(payload) != expected:
            raise ValueError(
                f"Association status notification length mismatch: expected {expected}, "
                f"got {len(payload)}"
            )
        bsses = [
            BssidAssociationStatus.parse(payload, 1 + i * BssidAssociationStatus.SIZE)
            for i in range(count)
        ]
        return cls(bsses=bsses)


register_typed(AssociationStatusNotification, spec_ref="Multi-AP v2.0 §17.2.53")


# ---------------------------------------------------------------------------
# 0xC0 Source Info — §17.2.54
# 0xC1 Tunneled Message Type — §17.2.55
# 0xC2 Tunneled — §17.2.56
# Used to wrap an opaque payload between Multi-AP nodes.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SourceInfo:
    TLV_TYPE: ClassVar[int] = 0xC0
    TLV_NAME: ClassVar[str] = "Source info"

    mac_address: bytes  # source STA/agent MAC

    def __post_init__(self) -> None:
        if len(self.mac_address) != MAC_LEN:
            raise ValueError("mac_address must be 6 bytes")

    def to_payload(self) -> bytes:
        return bytes(self.mac_address)

    @classmethod
    def from_payload(cls, payload: bytes) -> SourceInfo:
        return cls(mac_address=parse_mac(payload))


register_typed(SourceInfo, spec_ref="Multi-AP v2.0 §17.2.54")


@dataclass(slots=True)
class TunneledMessageType:
    TLV_TYPE: ClassVar[int] = 0xC1
    TLV_NAME: ClassVar[str] = "Tunneled message type"

    #: 0=Association Request, 1=Re-association Request, 2=BTM Query,
    #: 3=WNM Request, 4=ANQP Request, ... per Multi-AP v2.0 Table 17-32.
    protocol: int

    def to_payload(self) -> bytes:
        return bytes([self.protocol & 0xFF])

    @classmethod
    def from_payload(cls, payload: bytes) -> TunneledMessageType:
        if len(payload) != 1:
            raise ValueError(f"Tunneled message type TLV must be 1 byte, got {len(payload)}")
        return cls(protocol=payload[0])


register_typed(TunneledMessageType, spec_ref="Multi-AP v2.0 §17.2.55")


@dataclass(slots=True)
class Tunneled:
    TLV_TYPE: ClassVar[int] = 0xC2
    TLV_NAME: ClassVar[str] = "Tunneled"

    #: Opaque payload — meaning is governed by the accompanying
    #: TunneledMessageType TLV.
    data: bytes

    def to_payload(self) -> bytes:
        return bytes(self.data)

    @classmethod
    def from_payload(cls, payload: bytes) -> Tunneled:
        return cls(data=bytes(payload))


register_typed(Tunneled, spec_ref="Multi-AP v2.0 §17.2.56")


# ---------------------------------------------------------------------------
# 0xC3 Profile-2 Steering Request — §17.2.57
# Same wire layout as R1 Steering Request plus a Profile-2 BSS bitmap.
# Stored as a thin extension over the R1 dataclass via composition.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Profile2SteeringRequest:
    TLV_TYPE: ClassVar[int] = 0xC3
    TLV_NAME: ClassVar[str] = "Profile-2 steering request"

    bssid: bytes
    request_mode_flags: int
    steering_opportunity_window_s: int
    btm_disassociation_timer_tus: int
    sta_macs: list[bytes] = field(default_factory=list)
    target_bssids: list[tuple[bytes, int, int, int]] = field(default_factory=list)
    """List of (bssid, op_class, channel, reason_code) — reason_code is the
    Profile-2 addition (u8) over the R1 target tuple."""

    _STATIC: ClassVar[struct.Struct] = struct.Struct(">BHH")

    def __post_init__(self) -> None:
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")
        if len(self.sta_macs) > 0xFF or len(self.target_bssids) > 0xFF:
            raise ValueError("STA / target count exceeds 8-bit field")
        for m in self.sta_macs:
            if len(m) != MAC_LEN:
                raise ValueError("STA MAC must be 6 bytes")
        for b, _, _, _ in self.target_bssids:
            if len(b) != BSSID_LEN:
                raise ValueError("target bssid must be 6 bytes")

    def to_payload(self) -> bytes:
        target_bytes = b"".join(
            bytes(b) + bytes([oc & 0xFF, ch & 0xFF, rc & 0xFF])
            for (b, oc, ch, rc) in self.target_bssids
        )
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
            + target_bytes
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> Profile2SteeringRequest:
        head = BSSID_LEN + cls._STATIC.size + 1
        if len(payload) < head:
            raise ValueError("Profile-2 steering request TLV too short")
        bssid = parse_mac(payload)
        mode, window, btm_timer = cls._STATIC.unpack_from(payload, BSSID_LEN)
        offset = BSSID_LEN + cls._STATIC.size
        sta_count = payload[offset]
        offset += 1
        end_sta = offset + sta_count * MAC_LEN
        if end_sta + 1 > len(payload):
            raise ValueError("Profile-2 steering request truncated at STA list")
        sta_macs = [
            bytes(payload[offset + i * MAC_LEN : offset + (i + 1) * MAC_LEN])
            for i in range(sta_count)
        ]
        offset = end_sta
        target_count = payload[offset]
        offset += 1
        entry_size = BSSID_LEN + 3  # +3 = op_class, channel, reason_code
        if offset + target_count * entry_size != len(payload):
            raise ValueError(
                "Profile-2 steering request target list length mismatch"
            )
        targets: list[tuple[bytes, int, int, int]] = []
        for i in range(target_count):
            base = offset + i * entry_size
            targets.append(
                (
                    parse_mac(payload, base),
                    payload[base + BSSID_LEN],
                    payload[base + BSSID_LEN + 1],
                    payload[base + BSSID_LEN + 2],
                )
            )
        return cls(
            bssid=bssid,
            request_mode_flags=mode,
            steering_opportunity_window_s=window,
            btm_disassociation_timer_tus=btm_timer,
            sta_macs=sta_macs,
            target_bssids=targets,
        )


register_typed(Profile2SteeringRequest, spec_ref="Multi-AP v2.0 §17.2.57")


# ---------------------------------------------------------------------------
# 0xC4 Unsuccessful Association Policy — §17.2.58
# 0xC5 Metric Collection Interval — §17.2.59
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class UnsuccessfulAssociationPolicy:
    TLV_TYPE: ClassVar[int] = 0xC4
    TLV_NAME: ClassVar[str] = "Unsuccessful association policy"

    #: bit 7: report unsuccessful associations.
    flags: int
    max_reporting_rate: int  # u32 BE (events per minute cap)

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(">BI")

    @property
    def report_enabled(self) -> bool:
        return bool(self.flags & 0x80)

    def to_payload(self) -> bytes:
        return self._STRUCT.pack(self.flags & 0xFF, self.max_reporting_rate & 0xFFFFFFFF)

    @classmethod
    def from_payload(cls, payload: bytes) -> UnsuccessfulAssociationPolicy:
        if len(payload) != cls._STRUCT.size:
            raise ValueError(
                f"Unsuccessful association policy TLV must be {cls._STRUCT.size} bytes, "
                f"got {len(payload)}"
            )
        flags, rate = cls._STRUCT.unpack_from(payload, 0)
        return cls(flags=flags, max_reporting_rate=rate)


register_typed(UnsuccessfulAssociationPolicy, spec_ref="Multi-AP v2.0 §17.2.58")


@dataclass(slots=True)
class MetricCollectionInterval:
    TLV_TYPE: ClassVar[int] = 0xC5
    TLV_NAME: ClassVar[str] = "Metric collection interval"

    interval_ms: int  # u32 BE

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(">I")

    def to_payload(self) -> bytes:
        return self._STRUCT.pack(self.interval_ms & 0xFFFFFFFF)

    @classmethod
    def from_payload(cls, payload: bytes) -> MetricCollectionInterval:
        if len(payload) != cls._STRUCT.size:
            raise ValueError(
                f"Metric collection interval TLV must be {cls._STRUCT.size} bytes, "
                f"got {len(payload)}"
            )
        (interval,) = cls._STRUCT.unpack_from(payload, 0)
        return cls(interval_ms=interval)


register_typed(MetricCollectionInterval, spec_ref="Multi-AP v2.0 §17.2.59")


# ---------------------------------------------------------------------------
# 0xC6 Radio Metrics — §17.2.60
# 0xC7 AP Extended Metrics — §17.2.61
# 0xC8 Associated STA Extended Link Metrics — §17.2.62
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class RadioMetrics:
    TLV_TYPE: ClassVar[int] = 0xC6
    TLV_NAME: ClassVar[str] = "Radio metrics"

    radio_id: bytes
    noise: int  # u8 dBm
    transmit_utilization: int  # u8 percent
    receive_utilization: int
    receive_other_utilization: int

    SIZE: ClassVar[int] = MAC_LEN + 4

    def __post_init__(self) -> None:
        if len(self.radio_id) != MAC_LEN:
            raise ValueError("radio_id must be 6 bytes")

    def to_payload(self) -> bytes:
        return bytes(self.radio_id) + bytes(
            [
                self.noise & 0xFF,
                self.transmit_utilization & 0xFF,
                self.receive_utilization & 0xFF,
                self.receive_other_utilization & 0xFF,
            ]
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> RadioMetrics:
        if len(payload) != cls.SIZE:
            raise ValueError(
                f"Radio metrics TLV must be {cls.SIZE} bytes, got {len(payload)}"
            )
        return cls(
            radio_id=parse_mac(payload),
            noise=payload[MAC_LEN],
            transmit_utilization=payload[MAC_LEN + 1],
            receive_utilization=payload[MAC_LEN + 2],
            receive_other_utilization=payload[MAC_LEN + 3],
        )


register_typed(RadioMetrics, spec_ref="Multi-AP v2.0 §17.2.60")


@dataclass(slots=True)
class ApExtendedMetrics:
    TLV_TYPE: ClassVar[int] = 0xC7
    TLV_NAME: ClassVar[str] = "AP extended metrics"

    bssid: bytes
    unicast_bytes_sent: int  # u32 BE
    unicast_bytes_received: int
    multicast_bytes_sent: int
    multicast_bytes_received: int
    broadcast_bytes_sent: int
    broadcast_bytes_received: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(">IIIIII")
    SIZE: ClassVar[int] = BSSID_LEN + _STRUCT.size

    def __post_init__(self) -> None:
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")

    def to_payload(self) -> bytes:
        return bytes(self.bssid) + self._STRUCT.pack(
            self.unicast_bytes_sent & 0xFFFFFFFF,
            self.unicast_bytes_received & 0xFFFFFFFF,
            self.multicast_bytes_sent & 0xFFFFFFFF,
            self.multicast_bytes_received & 0xFFFFFFFF,
            self.broadcast_bytes_sent & 0xFFFFFFFF,
            self.broadcast_bytes_received & 0xFFFFFFFF,
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> ApExtendedMetrics:
        if len(payload) != cls.SIZE:
            raise ValueError(
                f"AP extended metrics TLV must be {cls.SIZE} bytes, got {len(payload)}"
            )
        vals = cls._STRUCT.unpack_from(payload, BSSID_LEN)
        return cls(
            bssid=parse_mac(payload, 0),
            unicast_bytes_sent=vals[0],
            unicast_bytes_received=vals[1],
            multicast_bytes_sent=vals[2],
            multicast_bytes_received=vals[3],
            broadcast_bytes_sent=vals[4],
            broadcast_bytes_received=vals[5],
        )


register_typed(ApExtendedMetrics, spec_ref="Multi-AP v2.0 §17.2.61")


@dataclass(slots=True)
class AssociatedStaExtendedLink:
    bssid: bytes
    last_data_dl_rate_kbps: int  # u32 BE
    last_data_ul_rate_kbps: int  # u32 BE
    utilization_receive: int  # u32 BE (microseconds active for receive)
    utilization_transmit: int  # u32 BE (microseconds active for transmit)

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(">IIII")
    SIZE: ClassVar[int] = BSSID_LEN + _STRUCT.size

    def __post_init__(self) -> None:
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")

    def to_bytes(self) -> bytes:
        return bytes(self.bssid) + self._STRUCT.pack(
            self.last_data_dl_rate_kbps & 0xFFFFFFFF,
            self.last_data_ul_rate_kbps & 0xFFFFFFFF,
            self.utilization_receive & 0xFFFFFFFF,
            self.utilization_transmit & 0xFFFFFFFF,
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> AssociatedStaExtendedLink:
        if offset + cls.SIZE > len(payload):
            raise ValueError("truncated associated-STA extended link entry")
        bssid = parse_mac(payload, offset)
        dl, ul, rx_u, tx_u = cls._STRUCT.unpack_from(payload, offset + BSSID_LEN)
        return cls(
            bssid=bssid,
            last_data_dl_rate_kbps=dl,
            last_data_ul_rate_kbps=ul,
            utilization_receive=rx_u,
            utilization_transmit=tx_u,
        )


@dataclass(slots=True)
class AssociatedStaExtendedLinkMetrics:
    TLV_TYPE: ClassVar[int] = 0xC8
    TLV_NAME: ClassVar[str] = "Associated STA extended link metrics"

    sta_mac: bytes
    bsses: list[AssociatedStaExtendedLink] = field(default_factory=list)

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
    def from_payload(cls, payload: bytes) -> AssociatedStaExtendedLinkMetrics:
        if len(payload) < MAC_LEN + 1:
            raise ValueError("Associated STA extended link metrics TLV too short")
        sta = parse_mac(payload)
        count = payload[MAC_LEN]
        expected = MAC_LEN + 1 + count * AssociatedStaExtendedLink.SIZE
        if len(payload) != expected:
            raise ValueError(
                f"Associated STA extended link metrics length mismatch: "
                f"expected {expected}, got {len(payload)}"
            )
        bsses = [
            AssociatedStaExtendedLink.parse(
                payload, MAC_LEN + 1 + i * AssociatedStaExtendedLink.SIZE
            )
            for i in range(count)
        ]
        return cls(sta_mac=sta, bsses=bsses)


register_typed(AssociatedStaExtendedLinkMetrics, spec_ref="Multi-AP v2.0 §17.2.62")


# ---------------------------------------------------------------------------
# 0xC9 Status Code — §17.2.63 (single u16 BE)
# 0xCA Reason Code — §17.2.64 (single u16 BE)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class StatusCode:
    TLV_TYPE: ClassVar[int] = 0xC9
    TLV_NAME: ClassVar[str] = "Status code"

    status_code: int

    def to_payload(self) -> bytes:
        return struct.pack(">H", self.status_code & 0xFFFF)

    @classmethod
    def from_payload(cls, payload: bytes) -> StatusCode:
        if len(payload) != 2:
            raise ValueError(f"Status code TLV must be 2 bytes, got {len(payload)}")
        (code,) = struct.unpack_from(">H", payload, 0)
        return cls(status_code=code)


register_typed(StatusCode, spec_ref="Multi-AP v2.0 §17.2.63")


@dataclass(slots=True)
class ReasonCode:
    TLV_TYPE: ClassVar[int] = 0xCA
    TLV_NAME: ClassVar[str] = "Reason code"

    reason_code: int

    def to_payload(self) -> bytes:
        return struct.pack(">H", self.reason_code & 0xFFFF)

    @classmethod
    def from_payload(cls, payload: bytes) -> ReasonCode:
        if len(payload) != 2:
            raise ValueError(f"Reason code TLV must be 2 bytes, got {len(payload)}")
        (code,) = struct.unpack_from(">H", payload, 0)
        return cls(reason_code=code)


register_typed(ReasonCode, spec_ref="Multi-AP v2.0 §17.2.64")


# ---------------------------------------------------------------------------
# 0xCB Backhaul STA Radio Capabilities — §17.2.65
# 0xCC AKM Suite Capabilities — §17.2.66
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class BackhaulStaRadioCapabilities:
    TLV_TYPE: ClassVar[int] = 0xCB
    TLV_NAME: ClassVar[str] = "Backhaul STA radio capabilities"

    radio_id: bytes
    #: bit 7: backhaul STA MAC address included.
    flags: int
    backhaul_sta_mac: bytes | None = None

    _MIN_SIZE: ClassVar[int] = MAC_LEN + 1
    _FULL_SIZE: ClassVar[int] = MAC_LEN + 1 + MAC_LEN

    def __post_init__(self) -> None:
        if len(self.radio_id) != MAC_LEN:
            raise ValueError("radio_id must be 6 bytes")
        if self.backhaul_sta_mac is not None and len(self.backhaul_sta_mac) != MAC_LEN:
            raise ValueError("backhaul_sta_mac must be 6 bytes")

    def to_payload(self) -> bytes:
        out = bytes(self.radio_id) + bytes([self.flags & 0xFF])
        if self.backhaul_sta_mac is not None:
            out += bytes(self.backhaul_sta_mac)
        return out

    @classmethod
    def from_payload(cls, payload: bytes) -> BackhaulStaRadioCapabilities:
        if len(payload) == cls._MIN_SIZE:
            return cls(radio_id=parse_mac(payload), flags=payload[MAC_LEN], backhaul_sta_mac=None)
        if len(payload) == cls._FULL_SIZE:
            return cls(
                radio_id=parse_mac(payload),
                flags=payload[MAC_LEN],
                backhaul_sta_mac=parse_mac(payload, MAC_LEN + 1),
            )
        raise ValueError(
            f"Backhaul STA radio capabilities TLV must be {cls._MIN_SIZE} or "
            f"{cls._FULL_SIZE} bytes, got {len(payload)}"
        )


register_typed(BackhaulStaRadioCapabilities, spec_ref="Multi-AP v2.0 §17.2.65")


@dataclass(slots=True)
class AkmSuite:
    """A 4-byte AKM suite selector (OUI + suite type)."""

    oui: bytes  # 3 bytes
    suite_type: int  # u8

    SIZE: ClassVar[int] = 4

    def __post_init__(self) -> None:
        if len(self.oui) != 3:
            raise ValueError("AKM OUI must be 3 bytes")

    def to_bytes(self) -> bytes:
        return bytes(self.oui) + bytes([self.suite_type & 0xFF])

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> AkmSuite:
        if offset + cls.SIZE > len(payload):
            raise ValueError("truncated AKM suite selector")
        return cls(oui=bytes(payload[offset : offset + 3]), suite_type=payload[offset + 3])


@dataclass(slots=True)
class AkmSuiteCapabilities:
    TLV_TYPE: ClassVar[int] = 0xCC
    TLV_NAME: ClassVar[str] = "AKM suite capabilities"

    backhaul_bss_akm_suites: list[AkmSuite] = field(default_factory=list)
    fronthaul_bss_akm_suites: list[AkmSuite] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.backhaul_bss_akm_suites) > 0xFF:
            raise ValueError("too many backhaul AKM suites (8-bit count)")
        if len(self.fronthaul_bss_akm_suites) > 0xFF:
            raise ValueError("too many fronthaul AKM suites (8-bit count)")

    def to_payload(self) -> bytes:
        return (
            bytes([len(self.backhaul_bss_akm_suites)])
            + b"".join(s.to_bytes() for s in self.backhaul_bss_akm_suites)
            + bytes([len(self.fronthaul_bss_akm_suites)])
            + b"".join(s.to_bytes() for s in self.fronthaul_bss_akm_suites)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> AkmSuiteCapabilities:
        if len(payload) < 2:
            raise ValueError("AKM suite capabilities TLV too short")
        n_bh = payload[0]
        offset = 1
        end_bh = offset + n_bh * AkmSuite.SIZE
        if end_bh + 1 > len(payload):
            raise ValueError("AKM suite capabilities truncated at fronthaul count")
        bh_suites = [
            AkmSuite.parse(payload, offset + i * AkmSuite.SIZE) for i in range(n_bh)
        ]
        offset = end_bh
        n_fh = payload[offset]
        offset += 1
        end_fh = offset + n_fh * AkmSuite.SIZE
        if end_fh != len(payload):
            raise ValueError(
                f"AKM suite capabilities length mismatch: expected {end_fh}, got {len(payload)}"
            )
        fh_suites = [
            AkmSuite.parse(payload, offset + i * AkmSuite.SIZE) for i in range(n_fh)
        ]
        return cls(backhaul_bss_akm_suites=bh_suites, fronthaul_bss_akm_suites=fh_suites)


register_typed(AkmSuiteCapabilities, spec_ref="Multi-AP v2.0 §17.2.66")
