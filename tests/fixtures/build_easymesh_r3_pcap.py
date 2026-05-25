# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate ``easymesh_r3.pcap`` covering every implemented R3 TLV."""

from __future__ import annotations

from pathlib import Path

from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from ieee1905.core import CMDU, CMDUHeader
from ieee1905.core.tlv import encode_typed
from ieee1905.core.tlvs import (
    AgentList,
    AgentListEntry,
    BackhaulBssConfiguration,
    BssConfigReportEntry,
    BssConfigReportRadio,
    BssConfigurationReport,
    BssConfigurationRequest,
    BssConfigurationResponse,
    BssidTlv,
    DeviceInventory,
    DppBootstrappingUriNotification,
    DppCceIndication,
    DppChirpValue,
    DppMessage,
    DscpMappingTable,
    Encap1905Dpp,
    Encap1905Eapol,
    InventoryRadio,
    ServicePrioritizationRule,
)

SRC_MAC = "00:11:22:33:44:55"
DST_MAC = "01:80:c2:00:00:13"
ETHERTYPE_IEEE1905 = 0x893A

RADIO_A = b"\x10\x20\x30\x40\x50\x60"
BSSID_A = b"\xaa\xbb\xcc\x00\x00\x01"
BSSID_B = b"\xaa\xbb\xcc\x00\x00\x02"
STA_A = b"\xc0\xff\xee\x00\x00\x01"
STA_B = b"\xc0\xff\xee\x00\x00\x02"
AGENT_A = b"\x02\x00\x00\x00\x00\x01"
AGENT_B = b"\x02\x00\x00\x00\x00\x02"


def _r3_tlvs() -> list[object]:
    return [
        Encap1905Dpp(
            destination_sta_mac=STA_A,
            flags=0x80,
            encap_frame_type=0x00,
            encap_frame_body=b"\xde\xad\xbe\xef" * 8,
        ),
        Encap1905Eapol(eapol_frame=b"\x02\x03\x00\x05" + b"\xab" * 5),
        DppBootstrappingUriNotification(
            radio_id=RADIO_A,
            local_interface_mac=BSSID_A,
            bssid=BSSID_A,
            bootstrapping_uri=b"DPP:V:2;M:" + b"a" * 20,
        ),
        BackhaulBssConfiguration(bssid=BSSID_B, flags=0xC0),
        DppMessage(dpp_frame=b"\x09\x50\x6f\x9a\x1a\x01" + b"\x00" * 24),
        DppCceIndication(advertise=1),
        DppChirpValue(
            flags=0xC0,
            enrollee_mac=STA_A,
            hash_value=b"\xa5" * 32,
        ),
        BssConfigurationReport(
            radios=[
                BssConfigReportRadio(
                    radio_id=RADIO_A,
                    bsses=[
                        BssConfigReportEntry(bssid=BSSID_A, flags=0xC0, ssid=b"home"),
                        BssConfigReportEntry(bssid=BSSID_B, flags=0x80, ssid=b"backhaul"),
                    ],
                )
            ]
        ),
        BssidTlv(bssid=BSSID_A),
        ServicePrioritizationRule(
            rule_id=1,
            flags=0x80,
            rule_precedence=10,
            rule_output=3,
            rule_match_filter=b"\x01\x02\x03\x04",
        ),
        DscpMappingTable(dscp_to_pcp=bytes(range(64))),
        BssConfigurationRequest(
            configuration_request_object=b'{"name":"BackhaulBSS"}',
        ),
        BssConfigurationResponse(
            configuration_response_object=b'{"status":0}',
        ),
        DeviceInventory(
            serial_number=b"SN123456",
            software_version=b"v1.2.3",
            execution_env=b"linux-arm-2026.05",
            radios=[
                InventoryRadio(radio_id=RADIO_A, chipset_vendor=b"Vendor X"),
            ],
        ),
        AgentList(
            agents=[
                AgentListEntry(al_mac=AGENT_A, profile=2, security=0x01),
                AgentListEntry(al_mac=AGENT_B, profile=3, security=0x01),
            ]
        ),
    ]


def build_frames(start_mid: int = 0x4000) -> list[Ether]:
    frames: list[Ether] = []
    for i, tlv in enumerate(_r3_tlvs()):
        cmdu = CMDU(
            header=CMDUHeader(message_type=0x8037, message_id=start_mid + i),
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
    target = Path(__file__).parent / "easymesh_r3.pcap"
    write(target)
    print(f"wrote {target} with {len(build_frames())} frames")
