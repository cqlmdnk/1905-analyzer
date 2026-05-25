# SPDX-License-Identifier: GPL-2.0-or-later
"""Wi-Fi EasyMesh R3 TLV implementations.

Spec: Wi-Fi Alliance *Multi-AP Specification* v3.0 §17.2.x.

R3 introduces DPP-based onboarding (Device Provisioning Protocol),
explicit BSS Configuration request/response/report, a Device Inventory
TLV with vendor/serial/sw-version strings, an Agent List TLV, and a
handful of supporting wrappers (1905 Encap DPP / EAPOL, Bootstrapping
URI notifications, Chirp values).

Where the payload is essentially "an opaque blob defined by another
spec" (DPP frames, EAPOL frames, BSS configuration objects), we keep
the wire bytes as ``bytes`` rather than re-implement another protocol's
parser. The analyzer UI surfaces them as hex; specialised dissectors
can land later as plugins.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import ClassVar

from ieee1905.core.tlvs._helpers import (
    MAC_LEN,
    encode_padded_ascii,
    parse_mac,
    parse_padded_ascii,
    register_typed,
)

BSSID_LEN = 6


# ---------------------------------------------------------------------------
# 0xCD 1905 Encap DPP — §17.2.67
# 0xCE 1905 Encap EAPOL — §17.2.68
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Encap1905Dpp:
    TLV_TYPE: ClassVar[int] = 0xCD
    TLV_NAME: ClassVar[str] = "1905 Encap DPP"

    destination_sta_mac: bytes
    #: bit 7: encap DPP frame body indicates a chirp value.
    flags: int
    encap_frame_type: int  # u8 per spec
    encap_frame_body: bytes  # length-prefixed (u16 BE in wire)

    _STATIC: ClassVar[struct.Struct] = struct.Struct(">BBH")  # flags, type, len

    def __post_init__(self) -> None:
        if len(self.destination_sta_mac) != MAC_LEN:
            raise ValueError("destination_sta_mac must be 6 bytes")

    def to_payload(self) -> bytes:
        return (
            bytes(self.destination_sta_mac)
            + self._STATIC.pack(
                self.flags & 0xFF,
                self.encap_frame_type & 0xFF,
                len(self.encap_frame_body) & 0xFFFF,
            )
            + bytes(self.encap_frame_body)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> Encap1905Dpp:
        if len(payload) < MAC_LEN + cls._STATIC.size:
            raise ValueError("1905 Encap DPP TLV too short")
        dst = parse_mac(payload, 0)
        flags, ft, n = cls._STATIC.unpack_from(payload, MAC_LEN)
        offset = MAC_LEN + cls._STATIC.size
        if offset + n != len(payload):
            raise ValueError(
                f"1905 Encap DPP length mismatch: expected {offset + n}, got {len(payload)}"
            )
        return cls(
            destination_sta_mac=dst,
            flags=flags,
            encap_frame_type=ft,
            encap_frame_body=bytes(payload[offset : offset + n]),
        )


register_typed(Encap1905Dpp, spec_ref="Multi-AP v3.0 §17.2.67")


@dataclass(slots=True)
class Encap1905Eapol:
    TLV_TYPE: ClassVar[int] = 0xCE
    TLV_NAME: ClassVar[str] = "1905 Encap EAPOL"

    eapol_frame: bytes  # length-prefixed (u16 BE)

    _LEN: ClassVar[struct.Struct] = struct.Struct(">H")

    def to_payload(self) -> bytes:
        return self._LEN.pack(len(self.eapol_frame) & 0xFFFF) + bytes(self.eapol_frame)

    @classmethod
    def from_payload(cls, payload: bytes) -> Encap1905Eapol:
        if len(payload) < cls._LEN.size:
            raise ValueError("1905 Encap EAPOL TLV too short")
        (n,) = cls._LEN.unpack_from(payload, 0)
        if cls._LEN.size + n != len(payload):
            raise ValueError(
                f"1905 Encap EAPOL length mismatch: declared {n}, "
                f"got {len(payload) - cls._LEN.size}"
            )
        return cls(eapol_frame=bytes(payload[cls._LEN.size :]))


register_typed(Encap1905Eapol, spec_ref="Multi-AP v3.0 §17.2.68")


# ---------------------------------------------------------------------------
# 0xCF DPP Bootstrapping URI Notification — §17.2.69
# 0xD1 DPP Message — §17.2.71
# 0xD2 DPP CCE Indication — §17.2.72
# 0xD3 DPP Chirp Value — §17.2.73
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class DppBootstrappingUriNotification:
    TLV_TYPE: ClassVar[int] = 0xCF
    TLV_NAME: ClassVar[str] = "DPP bootstrapping URI notification"

    radio_id: bytes
    local_interface_mac: bytes
    bssid: bytes
    bootstrapping_uri: bytes  # ASCII, fills the rest of the payload

    def __post_init__(self) -> None:
        if len(self.radio_id) != MAC_LEN:
            raise ValueError("radio_id must be 6 bytes")
        if len(self.local_interface_mac) != MAC_LEN:
            raise ValueError("local_interface_mac must be 6 bytes")
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")

    def to_payload(self) -> bytes:
        return (
            bytes(self.radio_id)
            + bytes(self.local_interface_mac)
            + bytes(self.bssid)
            + bytes(self.bootstrapping_uri)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> DppBootstrappingUriNotification:
        head = 3 * MAC_LEN
        if len(payload) < head:
            raise ValueError("DPP bootstrapping URI notification TLV too short")
        return cls(
            radio_id=parse_mac(payload, 0),
            local_interface_mac=parse_mac(payload, MAC_LEN),
            bssid=parse_mac(payload, 2 * MAC_LEN),
            bootstrapping_uri=bytes(payload[head:]),
        )


register_typed(DppBootstrappingUriNotification, spec_ref="Multi-AP v3.0 §17.2.69")


@dataclass(slots=True)
class DppMessage:
    TLV_TYPE: ClassVar[int] = 0xD1
    TLV_NAME: ClassVar[str] = "DPP message"

    #: Opaque DPP frame body, as defined by the Wi-Fi DPP spec.
    dpp_frame: bytes

    def to_payload(self) -> bytes:
        return bytes(self.dpp_frame)

    @classmethod
    def from_payload(cls, payload: bytes) -> DppMessage:
        return cls(dpp_frame=bytes(payload))


register_typed(DppMessage, spec_ref="Multi-AP v3.0 §17.2.71")


@dataclass(slots=True)
class DppCceIndication:
    TLV_TYPE: ClassVar[int] = 0xD2
    TLV_NAME: ClassVar[str] = "DPP CCE indication"

    #: 0x00 = advertise CCE, 0x01 = stop advertising. (Multi-AP v3.0 Table 17-X.)
    advertise: int

    def to_payload(self) -> bytes:
        return bytes([self.advertise & 0xFF])

    @classmethod
    def from_payload(cls, payload: bytes) -> DppCceIndication:
        if len(payload) != 1:
            raise ValueError(f"DPP CCE indication TLV must be 1 byte, got {len(payload)}")
        return cls(advertise=payload[0])


register_typed(DppCceIndication, spec_ref="Multi-AP v3.0 §17.2.72")


@dataclass(slots=True)
class DppChirpValue:
    TLV_TYPE: ClassVar[int] = 0xD3
    TLV_NAME: ClassVar[str] = "DPP chirp value"

    #: bit 7: hash validity (1 = enrollee MAC field is valid).
    #: bit 6: establish (1 = establish DPP connection).
    flags: int
    enrollee_mac: bytes  # 6 bytes, all-zero when not valid
    hash_value: bytes  # length-prefixed (u8 length)

    _HASH_LEN: ClassVar[struct.Struct] = struct.Struct(">B")

    def __post_init__(self) -> None:
        if len(self.enrollee_mac) != MAC_LEN:
            raise ValueError("enrollee_mac must be 6 bytes")
        if len(self.hash_value) > 0xFF:
            raise ValueError("hash_value exceeds 8-bit length field")

    def to_payload(self) -> bytes:
        return (
            bytes([self.flags & 0xFF])
            + bytes(self.enrollee_mac)
            + bytes([len(self.hash_value)])
            + bytes(self.hash_value)
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> DppChirpValue:
        head = 1 + MAC_LEN + 1
        if len(payload) < head:
            raise ValueError("DPP chirp value TLV too short")
        flags = payload[0]
        mac = parse_mac(payload, 1)
        n = payload[1 + MAC_LEN]
        if head + n != len(payload):
            raise ValueError(
                f"DPP chirp value length mismatch: hash declared {n}, "
                f"have {len(payload) - head}"
            )
        return cls(
            flags=flags,
            enrollee_mac=mac,
            hash_value=bytes(payload[head : head + n]),
        )


register_typed(DppChirpValue, spec_ref="Multi-AP v3.0 §17.2.73")


# ---------------------------------------------------------------------------
# 0xD0 Backhaul BSS Configuration — §17.2.70
# Captures backhaul BSS policy bits (P1/P2, disallow MLO).
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class BackhaulBssConfiguration:
    TLV_TYPE: ClassVar[int] = 0xD0
    TLV_NAME: ClassVar[str] = "Backhaul BSS configuration"

    bssid: bytes
    #: bit 7: P1 backhaul disallow, bit 6: P2 backhaul disallow.
    flags: int

    SIZE: ClassVar[int] = BSSID_LEN + 1

    def __post_init__(self) -> None:
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")

    def to_payload(self) -> bytes:
        return bytes(self.bssid) + bytes([self.flags & 0xFF])

    @classmethod
    def from_payload(cls, payload: bytes) -> BackhaulBssConfiguration:
        if len(payload) != cls.SIZE:
            raise ValueError(
                f"Backhaul BSS configuration TLV must be {cls.SIZE} bytes, got {len(payload)}"
            )
        return cls(bssid=parse_mac(payload, 0), flags=payload[BSSID_LEN])


register_typed(BackhaulBssConfiguration, spec_ref="Multi-AP v3.0 §17.2.70")


# ---------------------------------------------------------------------------
# 0xD4 BSS Configuration Report — §17.2.74
# 0xD5 BSSID — §17.2.75 (a one-shot 6-byte TLV)
# 0xD8 BSS Configuration Request — §17.2.78 (opaque DPP/Multi-AP object)
# 0xDA BSS Configuration Response — §17.2.79
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class BssConfigReportEntry:
    """One BSS entry in a BSS Configuration Report TLV (per radio, per BSS)."""

    bssid: bytes
    #: bit 7 = backhaul BSS, bit 6 = fronthaul BSS, bit 5 = R1-disallowed,
    #: bit 4 = R2-disallowed, bit 3 = multiple BSSID set, bit 2 = transmitted BSSID
    flags: int
    ssid: bytes

    def __post_init__(self) -> None:
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")
        if len(self.ssid) > 0xFF:
            raise ValueError("SSID exceeds 8-bit length field")

    def to_bytes(self) -> bytes:
        return (
            bytes(self.bssid)
            + bytes([self.flags & 0xFF, len(self.ssid)])
            + bytes(self.ssid)
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[BssConfigReportEntry, int]:
        start = offset
        if offset + BSSID_LEN + 2 > len(payload):
            raise ValueError("truncated BSS configuration report entry header")
        bssid = parse_mac(payload, offset)
        offset += BSSID_LEN
        flags = payload[offset]
        ssid_len = payload[offset + 1]
        offset += 2
        if offset + ssid_len > len(payload):
            raise ValueError("truncated BSS configuration report SSID")
        ssid = bytes(payload[offset : offset + ssid_len])
        offset += ssid_len
        return cls(bssid=bssid, flags=flags, ssid=ssid), offset - start


@dataclass(slots=True)
class BssConfigReportRadio:
    radio_id: bytes
    bsses: list[BssConfigReportEntry] = field(default_factory=list)

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
    def parse(cls, payload: bytes, offset: int) -> tuple[BssConfigReportRadio, int]:
        start = offset
        if offset + MAC_LEN + 1 > len(payload):
            raise ValueError("truncated BSS configuration report radio header")
        radio_id = parse_mac(payload, offset)
        offset += MAC_LEN
        count = payload[offset]
        offset += 1
        bsses: list[BssConfigReportEntry] = []
        for _ in range(count):
            b, consumed = BssConfigReportEntry.parse(payload, offset)
            bsses.append(b)
            offset += consumed
        return cls(radio_id=radio_id, bsses=bsses), offset - start


@dataclass(slots=True)
class BssConfigurationReport:
    TLV_TYPE: ClassVar[int] = 0xD4
    TLV_NAME: ClassVar[str] = "BSS configuration report"

    radios: list[BssConfigReportRadio] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.radios) > 0xFF:
            raise ValueError("too many radios (8-bit count)")

    def to_payload(self) -> bytes:
        return bytes([len(self.radios)]) + b"".join(r.to_bytes() for r in self.radios)

    @classmethod
    def from_payload(cls, payload: bytes) -> BssConfigurationReport:
        if not payload:
            raise ValueError("BSS configuration report TLV needs a count byte")
        count = payload[0]
        offset = 1
        radios: list[BssConfigReportRadio] = []
        for _ in range(count):
            r, consumed = BssConfigReportRadio.parse(payload, offset)
            radios.append(r)
            offset += consumed
        if offset != len(payload):
            raise ValueError(
                f"BSS configuration report has {len(payload) - offset} trailing bytes"
            )
        return cls(radios=radios)


register_typed(BssConfigurationReport, spec_ref="Multi-AP v3.0 §17.2.74")


@dataclass(slots=True)
class BssidTlv:
    TLV_TYPE: ClassVar[int] = 0xD5
    TLV_NAME: ClassVar[str] = "BSSID"

    bssid: bytes

    def __post_init__(self) -> None:
        if len(self.bssid) != BSSID_LEN:
            raise ValueError("bssid must be 6 bytes")

    def to_payload(self) -> bytes:
        return bytes(self.bssid)

    @classmethod
    def from_payload(cls, payload: bytes) -> BssidTlv:
        return cls(bssid=parse_mac(payload, 0))


register_typed(BssidTlv, spec_ref="Multi-AP v3.0 §17.2.75")


@dataclass(slots=True)
class BssConfigurationRequest:
    TLV_TYPE: ClassVar[int] = 0xD8
    TLV_NAME: ClassVar[str] = "BSS configuration request"

    #: Opaque DPP / Multi-AP configuration request object. The DPP layer
    #: defines the inner format.
    configuration_request_object: bytes

    def to_payload(self) -> bytes:
        return bytes(self.configuration_request_object)

    @classmethod
    def from_payload(cls, payload: bytes) -> BssConfigurationRequest:
        return cls(configuration_request_object=bytes(payload))


register_typed(BssConfigurationRequest, spec_ref="Multi-AP v3.0 §17.2.78")


@dataclass(slots=True)
class BssConfigurationResponse:
    TLV_TYPE: ClassVar[int] = 0xDA
    TLV_NAME: ClassVar[str] = "BSS configuration response"

    #: Opaque DPP / Multi-AP configuration response object.
    configuration_response_object: bytes

    def to_payload(self) -> bytes:
        return bytes(self.configuration_response_object)

    @classmethod
    def from_payload(cls, payload: bytes) -> BssConfigurationResponse:
        return cls(configuration_response_object=bytes(payload))


register_typed(BssConfigurationResponse, spec_ref="Multi-AP v3.0 §17.2.79")


# ---------------------------------------------------------------------------
# 0xD6 Service Prioritization Rule — §17.2.76
# 0xD7 DSCP Mapping Table — §17.2.77
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ServicePrioritizationRule:
    TLV_TYPE: ClassVar[int] = 0xD6
    TLV_NAME: ClassVar[str] = "Service prioritization rule"

    rule_id: int  # u32 BE
    #: bit 7 add(1) / remove(0), bit 6 always-match wildcard, bits 5-0 reserved.
    flags: int
    rule_precedence: int
    rule_output: int
    rule_match_filter: bytes  # opaque DSCP / DA / SA / VLAN match filter object

    _STATIC: ClassVar[struct.Struct] = struct.Struct(">IBBB")

    def to_payload(self) -> bytes:
        return self._STATIC.pack(
            self.rule_id & 0xFFFFFFFF,
            self.flags & 0xFF,
            self.rule_precedence & 0xFF,
            self.rule_output & 0xFF,
        ) + bytes(self.rule_match_filter)

    @classmethod
    def from_payload(cls, payload: bytes) -> ServicePrioritizationRule:
        if len(payload) < cls._STATIC.size:
            raise ValueError("Service prioritization rule TLV too short")
        rid, flags, prec, output = cls._STATIC.unpack_from(payload, 0)
        return cls(
            rule_id=rid,
            flags=flags,
            rule_precedence=prec,
            rule_output=output,
            rule_match_filter=bytes(payload[cls._STATIC.size :]),
        )


register_typed(ServicePrioritizationRule, spec_ref="Multi-AP v3.0 §17.2.76")


@dataclass(slots=True)
class DscpMappingTable:
    TLV_TYPE: ClassVar[int] = 0xD7
    TLV_NAME: ClassVar[str] = "DSCP mapping table"

    #: 64-byte table indexed by DSCP value (0..63) → 802.1Q PCP value.
    dscp_to_pcp: bytes

    SIZE: ClassVar[int] = 64

    def __post_init__(self) -> None:
        if len(self.dscp_to_pcp) != self.SIZE:
            raise ValueError(
                f"DSCP mapping table TLV must contain {self.SIZE} bytes, "
                f"got {len(self.dscp_to_pcp)}"
            )

    def to_payload(self) -> bytes:
        return bytes(self.dscp_to_pcp)

    @classmethod
    def from_payload(cls, payload: bytes) -> DscpMappingTable:
        if len(payload) != cls.SIZE:
            raise ValueError(
                f"DSCP mapping table TLV must be {cls.SIZE} bytes, got {len(payload)}"
            )
        return cls(dscp_to_pcp=bytes(payload))


register_typed(DscpMappingTable, spec_ref="Multi-AP v3.0 §17.2.77")


# ---------------------------------------------------------------------------
# 0xDB Device Inventory — §17.2.80
# Lists vendor / serial number / sw version strings for the agent and
# per-radio chipset vendor info.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class InventoryRadio:
    radio_id: bytes
    chipset_vendor: bytes  # length-prefixed (u8 len) ASCII

    def __post_init__(self) -> None:
        if len(self.radio_id) != MAC_LEN:
            raise ValueError("radio_id must be 6 bytes")
        if len(self.chipset_vendor) > 0xFF:
            raise ValueError("chipset_vendor exceeds 8-bit length field")

    def to_bytes(self) -> bytes:
        return (
            bytes(self.radio_id)
            + bytes([len(self.chipset_vendor)])
            + bytes(self.chipset_vendor)
        )

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> tuple[InventoryRadio, int]:
        start = offset
        if offset + MAC_LEN + 1 > len(payload):
            raise ValueError("truncated inventory radio header")
        rid = parse_mac(payload, offset)
        offset += MAC_LEN
        n = payload[offset]
        offset += 1
        if offset + n > len(payload):
            raise ValueError("truncated inventory chipset_vendor")
        cv = bytes(payload[offset : offset + n])
        offset += n
        return cls(radio_id=rid, chipset_vendor=cv), offset - start


@dataclass(slots=True)
class DeviceInventory:
    TLV_TYPE: ClassVar[int] = 0xDB
    TLV_NAME: ClassVar[str] = "Device inventory"

    serial_number: bytes  # length-prefixed (u8) ASCII
    software_version: bytes  # length-prefixed (u8) ASCII
    execution_env: bytes  # length-prefixed (u8) ASCII (e.g. firmware build id)
    radios: list[InventoryRadio] = field(default_factory=list)

    def __post_init__(self) -> None:
        for label, b in (
            ("serial_number", self.serial_number),
            ("software_version", self.software_version),
            ("execution_env", self.execution_env),
        ):
            if len(b) > 0xFF:
                raise ValueError(f"{label} exceeds 8-bit length field")
        if len(self.radios) > 0xFF:
            raise ValueError("too many radios (8-bit count)")

    def to_payload(self) -> bytes:
        return (
            bytes([len(self.serial_number)])
            + bytes(self.serial_number)
            + bytes([len(self.software_version)])
            + bytes(self.software_version)
            + bytes([len(self.execution_env)])
            + bytes(self.execution_env)
            + bytes([len(self.radios)])
            + b"".join(r.to_bytes() for r in self.radios)
        )

    @classmethod
    def _read_lp(cls, payload: bytes, offset: int) -> tuple[bytes, int]:
        if offset + 1 > len(payload):
            raise ValueError("truncated Device inventory length-prefixed field")
        n = payload[offset]
        end = offset + 1 + n
        if end > len(payload):
            raise ValueError("truncated Device inventory variable field body")
        return bytes(payload[offset + 1 : end]), end

    @classmethod
    def from_payload(cls, payload: bytes) -> DeviceInventory:
        offset = 0
        serial, offset = cls._read_lp(payload, offset)
        version, offset = cls._read_lp(payload, offset)
        exec_env, offset = cls._read_lp(payload, offset)
        if offset + 1 > len(payload):
            raise ValueError("Device inventory truncated at radio count")
        count = payload[offset]
        offset += 1
        radios: list[InventoryRadio] = []
        for _ in range(count):
            r, consumed = InventoryRadio.parse(payload, offset)
            radios.append(r)
            offset += consumed
        if offset != len(payload):
            raise ValueError(
                f"Device inventory has {len(payload) - offset} trailing bytes"
            )
        return cls(
            serial_number=serial,
            software_version=version,
            execution_env=exec_env,
            radios=radios,
        )


register_typed(DeviceInventory, spec_ref="Multi-AP v3.0 §17.2.80")


# ---------------------------------------------------------------------------
# 0xDF Agent List — §17.2.84
# List of agents in the network; the controller publishes this so each
# agent knows its peers.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class AgentListEntry:
    al_mac: bytes
    profile: int  # u8: 1=Profile-1, 2=Profile-2, 3=Profile-3, etc.
    security: int  # u8 bit-flag set (DPP-onboarded, ...)

    SIZE: ClassVar[int] = MAC_LEN + 2

    def __post_init__(self) -> None:
        if len(self.al_mac) != MAC_LEN:
            raise ValueError("al_mac must be 6 bytes")

    def to_bytes(self) -> bytes:
        return bytes(self.al_mac) + bytes([self.profile & 0xFF, self.security & 0xFF])

    @classmethod
    def parse(cls, payload: bytes, offset: int) -> AgentListEntry:
        if offset + cls.SIZE > len(payload):
            raise ValueError("truncated agent-list entry")
        return cls(
            al_mac=parse_mac(payload, offset),
            profile=payload[offset + MAC_LEN],
            security=payload[offset + MAC_LEN + 1],
        )


@dataclass(slots=True)
class AgentList:
    TLV_TYPE: ClassVar[int] = 0xDF
    TLV_NAME: ClassVar[str] = "Agent list"

    agents: list[AgentListEntry] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.agents) > 0xFF:
            raise ValueError("too many agents (8-bit count)")

    def to_payload(self) -> bytes:
        return bytes([len(self.agents)]) + b"".join(a.to_bytes() for a in self.agents)

    @classmethod
    def from_payload(cls, payload: bytes) -> AgentList:
        if not payload:
            raise ValueError("Agent list TLV needs a count byte")
        count = payload[0]
        expected = 1 + count * AgentListEntry.SIZE
        if len(payload) != expected:
            raise ValueError(
                f"Agent list length mismatch: expected {expected}, got {len(payload)}"
            )
        agents = [
            AgentListEntry.parse(payload, 1 + i * AgentListEntry.SIZE)
            for i in range(count)
        ]
        return cls(agents=agents)


register_typed(AgentList, spec_ref="Multi-AP v3.0 §17.2.84")


# Reference `encode_padded_ascii` / `parse_padded_ascii` so static analysers
# know the helpers are intentionally available for plugins that want fixed-
# width string fields. (Both are exported for reuse from the helper module.)
_ = (encode_padded_ascii, parse_padded_ascii)
