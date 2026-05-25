# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate ``easymesh_r2.pcap`` covering every implemented R2 TLV.

Run with::

    python -m tests.fixtures.build_easymesh_r2_pcap
"""

from __future__ import annotations

from pathlib import Path

from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from ieee1905.core import CMDU, CMDUHeader
from ieee1905.core.tlv import encode_typed
from ieee1905.core.tlvs import (
    AkmSuite,
    AkmSuiteCapabilities,
    ApExtendedMetrics,
    ApRadioAdvancedCapabilities,
    AssociatedStaExtendedLink,
    AssociatedStaExtendedLinkMetrics,
    AssociationStatusNotification,
    BackhaulStaRadioCapabilities,
    BssidAssociationStatus,
    ChannelScanCapabilities,
    ChannelScanCapabilityOpClass,
    ChannelScanCapabilityRadio,
    ChannelScanNeighbor,
    ChannelScanReportingPolicy,
    ChannelScanRequest,
    ChannelScanRequestOpClass,
    ChannelScanRequestRadio,
    ChannelScanResult,
    Default8021QSettings,
    LayerSecurityCapability,
    MetricCollectionInterval,
    Profile2ApCapability,
    Profile2ErrorCode,
    Profile2SteeringRequest,
    RadioMetrics,
    ReasonCode,
    SourceInfo,
    SsidVlanMapping,
    StatusCode,
    Timestamp,
    TrafficSeparationPolicy,
    Tunneled,
    TunneledMessageType,
    UnsuccessfulAssociationPolicy,
)

SRC_MAC = "00:11:22:33:44:55"
DST_MAC = "01:80:c2:00:00:13"
ETHERTYPE_IEEE1905 = 0x893A

RADIO_A = b"\x10\x20\x30\x40\x50\x60"
BSSID_A = b"\xaa\xbb\xcc\x00\x00\x01"
BSSID_B = b"\xaa\xbb\xcc\x00\x00\x02"
STA_A = b"\xc0\xff\xee\x00\x00\x01"
STA_B = b"\xc0\xff\xee\x00\x00\x02"


def _r2_tlvs() -> list[object]:
    return [
        ChannelScanReportingPolicy(flags=0x80),
        ChannelScanCapabilities(
            radios=[
                ChannelScanCapabilityRadio(
                    radio_id=RADIO_A,
                    flags=0x80,
                    min_scan_interval_s=60,
                    operating_classes=[
                        ChannelScanCapabilityOpClass(op_class=81, channels=[1, 6, 11]),
                    ],
                )
            ]
        ),
        ChannelScanRequest(
            flags=0x80,
            radios=[
                ChannelScanRequestRadio(
                    radio_id=RADIO_A,
                    operating_classes=[
                        ChannelScanRequestOpClass(op_class=115, channels=[36, 40]),
                    ],
                )
            ],
        ),
        ChannelScanResult(
            radio_id=RADIO_A,
            op_class=115,
            channel=36,
            scan_status=0,
            timestamp="2026-05-25T15:00:00Z",
            utilization=42,
            noise=180,
            neighbors=[
                ChannelScanNeighbor(
                    bssid=BSSID_A,
                    ssid=b"home",
                    signal_strength=200,
                    channel_bandwidth="80",
                    flags=0x80,
                    channel_utilization=50,
                    station_count=4,
                ),
                ChannelScanNeighbor(
                    bssid=BSSID_B,
                    ssid=b"",
                    signal_strength=150,
                    channel_bandwidth="40",
                ),
            ],
            aggregate_scan_duration_ms=2500,
            scan_type=1,
        ),
        Timestamp(timestamp="2026-05-25T15:30:00Z"),
        LayerSecurityCapability(
            onboarding_protocols=0x01,  # DPP
            mic_algorithms=0x01,  # HMAC-SHA256
            encryption_algorithms=0x01,  # AES-SIV
        ),
        Profile2ApCapability(
            reserved=0,
            capabilities=0x80,
            max_prioritization_rules=10,
        ),
        Default8021QSettings(primary_vlan_id=100, default_pcp=0xC0),
        TrafficSeparationPolicy(
            mappings=[
                SsidVlanMapping(ssid=b"home", vlan_id=100),
                SsidVlanMapping(ssid=b"guest", vlan_id=200),
            ]
        ),
        Profile2ErrorCode(reason_code=0x02, bssid=BSSID_A),
        ApRadioAdvancedCapabilities(radio_id=RADIO_A, flags=0xC0),
        AssociationStatusNotification(
            bsses=[
                BssidAssociationStatus(bssid=BSSID_A, association_allowed=True),
                BssidAssociationStatus(bssid=BSSID_B, association_allowed=False),
            ]
        ),
        SourceInfo(mac_address=STA_A),
        TunneledMessageType(protocol=0),
        Tunneled(data=b"opaque-tunneled-frame-bytes"),
        Profile2SteeringRequest(
            bssid=BSSID_A,
            request_mode_flags=0x80,
            steering_opportunity_window_s=0,
            btm_disassociation_timer_tus=200,
            sta_macs=[STA_A],
            target_bssids=[(BSSID_B, 115, 36, 0x05)],
        ),
        UnsuccessfulAssociationPolicy(flags=0x80, max_reporting_rate=60),
        MetricCollectionInterval(interval_ms=5000),
        RadioMetrics(
            radio_id=RADIO_A,
            noise=180,
            transmit_utilization=40,
            receive_utilization=20,
            receive_other_utilization=10,
        ),
        ApExtendedMetrics(
            bssid=BSSID_A,
            unicast_bytes_sent=10_000_000,
            unicast_bytes_received=20_000_000,
            multicast_bytes_sent=100_000,
            multicast_bytes_received=50_000,
            broadcast_bytes_sent=10_000,
            broadcast_bytes_received=5_000,
        ),
        AssociatedStaExtendedLinkMetrics(
            sta_mac=STA_A,
            bsses=[
                AssociatedStaExtendedLink(
                    bssid=BSSID_A,
                    last_data_dl_rate_kbps=433_000,
                    last_data_ul_rate_kbps=216_000,
                    utilization_receive=1_000_000,
                    utilization_transmit=500_000,
                )
            ],
        ),
        StatusCode(status_code=0),
        ReasonCode(reason_code=1),
        BackhaulStaRadioCapabilities(radio_id=RADIO_A, flags=0x80, backhaul_sta_mac=STA_B),
        AkmSuiteCapabilities(
            backhaul_bss_akm_suites=[AkmSuite(oui=b"\x00\x0F\xAC", suite_type=8)],  # WPA3-SAE
            fronthaul_bss_akm_suites=[
                AkmSuite(oui=b"\x00\x0F\xAC", suite_type=2),  # WPA2-PSK
                AkmSuite(oui=b"\x00\x0F\xAC", suite_type=8),  # WPA3-SAE
            ],
        ),
    ]


def build_frames(start_mid: int = 0x3000) -> list[Ether]:
    frames: list[Ether] = []
    for i, tlv in enumerate(_r2_tlvs()):
        cmdu = CMDU(
            header=CMDUHeader(message_type=0x801B, message_id=start_mid + i),
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
    target = Path(__file__).parent / "easymesh_r2.pcap"
    write(target)
    print(f"wrote {target} with {len(build_frames())} frames")
