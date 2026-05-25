# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate ``easymesh_r1.pcap`` covering every implemented R1 TLV.

Run with::

    python -m tests.fixtures.build_easymesh_r1_pcap

One frame per R1 TLV type (35 frames), each a single-fragment CMDU.
Mirrors the layout of :mod:`tests.fixtures.build_baseline_pcap`.
"""

from __future__ import annotations

from pathlib import Path

from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from ieee1905.core import CMDU, CMDUHeader
from ieee1905.core.tlv import encode_typed
from ieee1905.core.tlvs import (
    ApCapability,
    ApHeCapabilities,
    ApHtCapabilities,
    ApMetricQuery,
    ApMetrics,
    ApOperationalBss,
    ApRadioBasicCapabilities,
    ApRadioIdentifier,
    ApVhtCapabilities,
    AssociatedClient,
    AssociatedClients,
    AssociatedClientsBss,
    AssociatedStaLink,
    AssociatedStaLinkMetrics,
    AssociatedStaTrafficStats,
    BackhaulSteeringRequest,
    BackhaulSteeringResponse,
    BeaconApChannelReport,
    BeaconMetricsQuery,
    BeaconMetricsResponse,
    ChannelPreference,
    ChannelPreferenceOpClass,
    ChannelSelectionResponse,
    ClientAssociationControlRequest,
    ClientAssociationEvent,
    ClientCapabilityReport,
    ClientInfo,
    ErrorCode,
    HigherLayerData,
    MetricReportingPolicy,
    MetricReportingPolicyRadio,
    OperatingChannelOpClass,
    OperatingChannelReport,
    OperatingClassCapability,
    OperationalBss,
    OperationalBssRadio,
    RadioOperationRestriction,
    RestrictedChannel,
    RestrictedOpClass,
    SearchedService,
    StaMacAddressType,
    SteeringBtmReport,
    SteeringPolicy,
    SteeringPolicyRadio,
    SteeringRequest,
    SteeringTargetBssid,
    SupportedService,
    TransmitPowerLimit,
    UnassociatedStaLinkMetricsQuery,
    UnassociatedStaLinkMetricsResponse,
    UnassociatedStaQueryChannel,
    UnassociatedStaResponseEntry,
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


def _r1_tlvs() -> list[object]:
    return [
        SupportedService(services=[0x00, 0x01]),
        SearchedService(services=[0x00]),
        ApRadioIdentifier(radio_id=RADIO_A),
        ApOperationalBss(
            radios=[
                OperationalBssRadio(
                    radio_id=RADIO_A,
                    bsses=[
                        OperationalBss(bssid=BSSID_A, ssid=b"home"),
                        OperationalBss(bssid=BSSID_B, ssid=b""),
                    ],
                )
            ]
        ),
        AssociatedClients(
            bsses=[
                AssociatedClientsBss(
                    bssid=BSSID_A,
                    clients=[
                        AssociatedClient(client_mac=STA_A, seconds_since_assoc=60),
                        AssociatedClient(client_mac=STA_B, seconds_since_assoc=3600),
                    ],
                )
            ]
        ),
        ApRadioBasicCapabilities(
            radio_id=RADIO_A,
            max_bsses_supported=4,
            operating_classes=[
                OperatingClassCapability(
                    op_class=81, max_tx_eirp_dbm=23, non_operable_channels=[12, 13]
                ),
                OperatingClassCapability(
                    op_class=115, max_tx_eirp_dbm=30, non_operable_channels=[]
                ),
            ],
        ),
        ApHtCapabilities(radio_id=RADIO_A, flags=0xCE),  # 4SS Tx, 4SS Rx, SGI20/40, HT40
        ApVhtCapabilities(
            radio_id=RADIO_A,
            vht_tx_mcs_map=0xFFFC,
            vht_rx_mcs_map=0xFFFC,
            flags=0b1110_1011_0000_0000,
        ),
        ApHeCapabilities(
            radio_id=RADIO_A,
            supported_he_mcs=bytes(range(8)),
            flags=0b1110_1011_0000_0000,
        ),
        SteeringPolicy(
            local_steering_disallowed=[STA_A],
            btm_steering_disallowed=[STA_B],
            radios=[
                SteeringPolicyRadio(
                    radio_id=RADIO_A,
                    policy=1,
                    channel_utilization_threshold=80,
                    rcpi_steering_threshold=200,
                )
            ],
        ),
        MetricReportingPolicy(
            ap_metrics_reporting_interval_s=10,
            radios=[
                MetricReportingPolicyRadio(
                    radio_id=RADIO_A,
                    sta_rcpi_threshold=180,
                    sta_rcpi_hysteresis_margin=10,
                    ap_channel_utilization_threshold=70,
                    flags=0xC0,
                )
            ],
        ),
        ChannelPreference(
            radio_id=RADIO_A,
            operating_classes=[
                ChannelPreferenceOpClass(op_class=81, channels=[1, 6, 11], preference=0xE0),
            ],
        ),
        RadioOperationRestriction(
            radio_id=RADIO_A,
            operating_classes=[
                RestrictedOpClass(
                    op_class=115,
                    channels=[
                        RestrictedChannel(channel=36, min_frequency_separation_mhz=40),
                    ],
                )
            ],
        ),
        TransmitPowerLimit(radio_id=RADIO_A, transmit_power_eirp_dbm=20),
        ChannelSelectionResponse(radio_id=RADIO_A, response_code=0),
        OperatingChannelReport(
            radio_id=RADIO_A,
            operating_classes=[
                OperatingChannelOpClass(op_class=81, channel=6),
                OperatingChannelOpClass(op_class=115, channel=36),
            ],
            current_transmit_power_dbm=18,
        ),
        ClientInfo(bssid=BSSID_A, client_mac=STA_A),
        ClientCapabilityReport(result_code=0, frame_body=b"\x00\x00" + b"\xab" * 20),
        ClientAssociationEvent(client_mac=STA_A, bssid=BSSID_A, associated=True),
        ApMetricQuery(bssids=[BSSID_A, BSSID_B]),
        ApMetrics(
            bssid=BSSID_A,
            channel_utilization=42,
            num_associated_stas=3,
            esp_info=b"\x80\x00\x10\x20",  # 1-byte indicator + 1 ESP record
        ),
        StaMacAddressType(sta_mac=STA_A),
        AssociatedStaLinkMetrics(
            sta_mac=STA_A,
            bsses=[
                AssociatedStaLink(
                    bssid=BSSID_A,
                    earliest_measurement_ms=12345,
                    estimated_dl_mac_rate_mbps=433,
                    estimated_ul_mac_rate_mbps=216,
                    uplink_rcpi=180,
                )
            ],
        ),
        UnassociatedStaLinkMetricsQuery(
            operating_class=115,
            channels=[
                UnassociatedStaQueryChannel(channel=36, sta_macs=[STA_A, STA_B]),
            ],
        ),
        UnassociatedStaLinkMetricsResponse(
            operating_class=115,
            entries=[
                UnassociatedStaResponseEntry(
                    sta_mac=STA_A,
                    channel=36,
                    time_delta_ms=100,
                    uplink_rcpi=170,
                ),
            ],
        ),
        BeaconMetricsQuery(
            sta_mac=STA_A,
            operating_class=81,
            channel=255,  # wildcard
            bssid=BSSID_A,
            reporting_detail=2,
            ssid=b"home",
            ap_channel_reports=[
                BeaconApChannelReport(op_class=81, channels=[1, 6, 11]),
            ],
            element_ids=[0, 50],
        ),
        BeaconMetricsResponse(
            sta_mac=STA_A,
            measurement_reports=[
                bytes([39, 26]) + b"\x00" * 26,  # ID=39 Measurement Report, length=26
            ],
        ),
        SteeringRequest(
            bssid=BSSID_A,
            request_mode_flags=0x80,  # mandate
            steering_opportunity_window_s=0,
            btm_disassociation_timer_tus=200,
            sta_macs=[STA_A],
            target_bssids=[
                SteeringTargetBssid(bssid=BSSID_B, op_class=115, channel=36),
            ],
        ),
        SteeringBtmReport(
            bssid=BSSID_A,
            sta_mac=STA_A,
            btm_status_code=0,
            target_bssid=BSSID_B,
        ),
        ClientAssociationControlRequest(
            bssid=BSSID_A,
            association_control=0,
            validity_period_s=30,
            sta_macs=[STA_A, STA_B],
        ),
        BackhaulSteeringRequest(
            backhaul_sta_mac=STA_A,
            target_bssid=BSSID_B,
            target_op_class=115,
            target_channel=36,
        ),
        BackhaulSteeringResponse(
            backhaul_sta_mac=STA_A,
            target_bssid=BSSID_B,
            result_code=0,
        ),
        HigherLayerData(protocol=0x01, data=b"hello-higher-layer"),
        ApCapability(flags=0xE0),
        AssociatedStaTrafficStats(
            sta_mac=STA_A,
            bytes_sent=100_000,
            bytes_received=200_000,
            packets_sent=500,
            packets_received=1000,
            tx_packet_errors=2,
            rx_packet_errors=3,
            retransmission_count=10,
        ),
        ErrorCode(reason_code=2, sta_mac=STA_A),
    ]


def build_frames(start_mid: int = 0x2000) -> list[Ether]:
    frames: list[Ether] = []
    for i, tlv in enumerate(_r1_tlvs()):
        cmdu = CMDU(
            header=CMDUHeader(
                message_type=0x8002,  # AP Capability Report - neutral R1 carrier
                message_id=start_mid + i,
            ),
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
    target = Path(__file__).parent / "easymesh_r1.pcap"
    write(target)
    print(f"wrote {target} with {len(build_frames())} frames")
