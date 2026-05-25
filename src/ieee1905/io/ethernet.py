# SPDX-License-Identifier: GPL-2.0-or-later
"""Minimal Ethernet II frame parser.

Just enough to peel the L2 header off a captured frame so the caller
can hand the payload to :func:`ieee1905.core.cmdu.CMDU.from_bytes`.
802.1Q VLAN tags are recognized and stripped; QinQ and exotic L2
encapsulations are out of scope here — Scapy is the right tool for
those when we need them.
"""

from __future__ import annotations

from dataclasses import dataclass

ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8
ETH_HEADER_SIZE = 14
VLAN_TAG_SIZE = 4


class EthernetParseError(ValueError):
    """Raised when a byte stream cannot be parsed as an Ethernet II frame."""


@dataclass(frozen=True, slots=True)
class EthernetFrame:
    """An Ethernet II frame, optionally carrying a single VLAN tag."""

    dst: bytes
    src: bytes
    ethertype: int
    payload: bytes
    vlan_id: int | None = None
    vlan_pcp: int | None = None

    def to_bytes(self) -> bytes:
        header = bytes(self.dst) + bytes(self.src)
        if self.vlan_id is not None:
            pcp = (self.vlan_pcp or 0) & 0x7
            tci = (pcp << 13) | (self.vlan_id & 0x0FFF)
            header += ETHERTYPE_VLAN.to_bytes(2, "big") + tci.to_bytes(2, "big")
        header += self.ethertype.to_bytes(2, "big")
        return header + bytes(self.payload)

    @classmethod
    def parse(cls, raw: bytes) -> EthernetFrame:
        if len(raw) < ETH_HEADER_SIZE:
            raise EthernetParseError(
                f"frame too short: {len(raw)} < {ETH_HEADER_SIZE}"
            )
        dst = bytes(raw[0:6])
        src = bytes(raw[6:12])
        ethertype = int.from_bytes(raw[12:14], "big")
        offset = ETH_HEADER_SIZE
        vlan_id: int | None = None
        vlan_pcp: int | None = None
        if ethertype == ETHERTYPE_VLAN:
            if len(raw) < offset + VLAN_TAG_SIZE:
                raise EthernetParseError("truncated 802.1Q tag")
            tci = int.from_bytes(raw[offset : offset + 2], "big")
            vlan_id = tci & 0x0FFF
            vlan_pcp = (tci >> 13) & 0x7
            ethertype = int.from_bytes(raw[offset + 2 : offset + 4], "big")
            offset += VLAN_TAG_SIZE
        return cls(
            dst=dst,
            src=src,
            ethertype=ethertype,
            payload=bytes(raw[offset:]),
            vlan_id=vlan_id,
            vlan_pcp=vlan_pcp,
        )
