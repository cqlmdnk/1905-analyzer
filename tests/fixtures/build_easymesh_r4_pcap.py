# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate ``easymesh_r4.pcap`` covering implemented R4 TLVs (Wi-Fi 7 / EHT / MLD)."""

from __future__ import annotations

from pathlib import Path

from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from ieee1905.core import CMDU, CMDUHeader
from ieee1905.core.tlv import encode_typed
from ieee1905.core.tlvs import (
    AffiliatedApMetrics,
    AffiliatedLink,
    AffiliatedStaMetrics,
    AgentApMldConfiguration,
    ApEhtOperations,
    ApWifi6Capabilities,
    ApWifi7AgentCapabilities,
    AssociatedStaMldConfiguration,
    BackhaulStaMldConfiguration,
    EhtOperations,
    EhtOperationsBss,
    HeRoleCapabilities,
    TidToLinkMappingPolicy,
    Wifi7RadioCapability,
)

SRC_MAC = "00:11:22:33:44:55"
DST_MAC = "01:80:c2:00:00:13"
ETHERTYPE_IEEE1905 = 0x893A

RADIO_A = b"\x10\x20\x30\x40\x50\x60"
RADIO_B = b"\x10\x20\x30\x40\x50\x70"
BSSID_A = b"\xaa\xbb\xcc\x00\x00\x01"
BSSID_B = b"\xaa\xbb\xcc\x00\x00\x02"
STA_A = b"\xc0\xff\xee\x00\x00\x01"
STA_B = b"\xc0\xff\xee\x00\x00\x02"
MLD_A = b"\x02\x80\x00\x00\x00\x01"


def _r4_tlvs() -> list[object]:
    eht_bss = EhtOperationsBss(
        bssid=BSSID_A,
        eht_operation_information_length=3,
        eht_operation_information=b"\x00\x01\x02",
        basic_eht_mcs_nss_set=b"\xff\xff\xff\xff",
        disabled_subchannel_bitmap=b"\x00\x00",
    )
    return [
        ApWifi6Capabilities(
            radio_id=RADIO_A,
            roles=[
                HeRoleCapabilities(
                    role=0,
                    he_mcs_length=4,
                    he_mcs=b"\xaa\xbb\xcc\xdd",
                    he_flags_1=0xC0,
                    he_flags_2=0x40,
                ),
                HeRoleCapabilities(
                    role=2,
                    he_mcs_length=4,
                    he_mcs=b"\x11\x22\x33\x44",
                    he_flags_1=0x80,
                    he_flags_2=0x00,
                ),
            ],
        ),
        ApEhtOperations(radio_id=RADIO_A, bsses=[eht_bss]),
        ApWifi7AgentCapabilities(
            agent_flags=0xF0,
            radios=[
                Wifi7RadioCapability(radio_id=RADIO_A, flags=0xC0),
                Wifi7RadioCapability(radio_id=RADIO_B, flags=0x80),
            ],
        ),
        AgentApMldConfiguration(
            mld_mac=MLD_A,
            mld_flags=0x80,
            links=[
                AffiliatedLink(link_mac=BSSID_A, flags=0xC0),
                AffiliatedLink(link_mac=BSSID_B, flags=0x80),
            ],
        ),
        BackhaulStaMldConfiguration(
            mld_mac=MLD_A,
            mld_flags=0x40,
            links=[AffiliatedLink(link_mac=STA_A, flags=0x80)],
        ),
        AssociatedStaMldConfiguration(
            mld_mac=MLD_A,
            mld_flags=0x80,
            links=[AffiliatedLink(link_mac=STA_B, flags=0x40)],
        ),
        AffiliatedStaMetrics(
            sta_mac=STA_A,
            bssid=BSSID_A,
            bytes_sent=100_000,
            bytes_received=200_000,
            packets_sent=500,
            packets_received=1000,
            packets_sent_errors=3,
        ),
        AffiliatedApMetrics(
            bssid=BSSID_A,
            channel_utilization=35,
            num_associated_stas=12,
            unicast_bytes_sent=50_000_000,
            unicast_bytes_received=100_000_000,
            multicast_bytes_sent=500_000,
            multicast_bytes_received=200_000,
        ),
        TidToLinkMappingPolicy(
            mld_mac=MLD_A,
            flags=0x80,
            tid_to_link_bitmap=bytes([0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03]),
        ),
        EhtOperations(
            radios=[
                ApEhtOperations(
                    radio_id=RADIO_B,
                    bsses=[
                        EhtOperationsBss(
                            bssid=BSSID_B,
                            eht_operation_information_length=2,
                            eht_operation_information=b"\xaa\xbb",
                            basic_eht_mcs_nss_set=b"\xff\xff\xff\xff",
                            disabled_subchannel_bitmap=b"\x00\x00",
                        )
                    ],
                )
            ]
        ),
    ]


def build_frames(start_mid: int = 0x5000) -> list[Ether]:
    frames: list[Ether] = []
    for i, tlv in enumerate(_r4_tlvs()):
        cmdu = CMDU(
            header=CMDUHeader(message_type=0x8002, message_id=start_mid + i),
            tlvs=[encode_typed(tlv)],  # type: ignore[arg-type]
        )
        wire = cmdu.to_bytes()
        eth = Ether(src=SRC_MAC, dst=DST_MAC, type=ETHERTYPE_IEEE1905) / Raw(load=wire)
        eth.time = float(i)
        frames.append(eth)
    return frames


def write(path: Path) -> None:
    wrpcap(str(path), build_frames())


if __name__ == "__main__":
    target = Path(__file__).parent / "easymesh_r4.pcap"
    write(target)
    print(f"wrote {target} with {len(build_frames())} frames")
