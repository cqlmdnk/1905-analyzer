# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate ``baseline_1905.pcap`` covering every implemented 1905.1 TLV.

Run with::

    python -m tests.fixtures.build_baseline_pcap

Each frame is a single-fragment IEEE 1905.1 CMDU (EtherType 0x893a)
wrapping one TLV plus the end-of-message TLV. The result is a small
deterministic PCAP suitable as a regression fixture for the decoder.
"""

from __future__ import annotations

from pathlib import Path

from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from ieee1905.core import CMDU, CMDUHeader
from ieee1905.core.tlv import encode_typed
from ieee1905.core.tlvs import (
    AlMacAddress,
    AutoconfigFreqBand,
    BridgingTuple,
    ControlUrl,
    DeviceBridgingCapability,
    DeviceIdentification,
    DeviceInformation,
    GenericPhyDeviceInformation,
    GenericPhyEventEntry,
    GenericPhyEventNotification,
    GenericPhyInterface,
    InterfacePowerChangeEntry,
    InterfacePowerChangeInformation,
    InterfacePowerChangeStatus,
    IPv4,
    Ipv4Address,
    Ipv4Entry,
    IPv6,
    Ipv6Address,
    Ipv6Entry,
    L2LocalInterface,
    L2Neighbor,
    L2NeighborDevice,
    LinkMetricQuery,
    LinkMetricResultCode,
    LocalInterface,
    MacAddress,
    NeighborDevice,
    NeighborEntry,
    Non1905NeighborDeviceList,
    PbeMediaType,
    PowerOffInterface,
    PowerOffInterfaceEntry,
    ProfileVersion,
    PushButtonEventNotification,
    PushButtonJoinNotification,
    ReceiverLinkEntry,
    ReceiverLinkMetric,
    SearchedRole,
    SupportedFreqBand,
    SupportedRole,
    TransmitterLinkEntry,
    TransmitterLinkMetric,
    VendorSpecific,
    WscFrame,
)

SRC_MAC = "00:11:22:33:44:55"
DST_MAC = "01:80:c2:00:00:13"  # IEEE 1905.1 multicast
ETHERTYPE_IEEE1905 = 0x893A

MAC_A = b"\x00\x11\x22\x33\x44\x55"
MAC_B = b"\xaa\xbb\xcc\xdd\xee\xff"
MAC_C = b"\x01\x02\x03\x04\x05\x06"
OUI_TEST = b"\x00\x1a\x2b"


def _baseline_tlvs() -> list[object]:
    """One sample instance per built-in 1905.1 TLV.

    The end-of-message TLV (0x00) is appended automatically by
    :meth:`CMDU.to_bytes`; we do not include it here.
    """
    return [
        AlMacAddress(al_mac=MAC_A),
        MacAddress(mac=MAC_B),
        DeviceInformation(
            al_mac=MAC_A,
            interfaces=[
                LocalInterface(mac=MAC_A, media_type=0x0100),
                LocalInterface(mac=MAC_B, media_type=0x0102, media_specific=b"\x01\x02\x03"),
            ],
        ),
        DeviceBridgingCapability(
            tuples=[BridgingTuple(macs=[MAC_A, MAC_B]), BridgingTuple(macs=[MAC_C])]
        ),
        Non1905NeighborDeviceList(local_interface_mac=MAC_A, neighbor_macs=[MAC_B, MAC_C]),
        NeighborDevice(
            local_interface_mac=MAC_A,
            neighbors=[
                NeighborEntry(neighbor_al_mac=MAC_B, has_bridge=True),
                NeighborEntry(neighbor_al_mac=MAC_C, has_bridge=False),
            ],
        ),
        LinkMetricQuery(neighbor_type=0x01, neighbor_al_mac=MAC_B, link_metrics=0x02),
        TransmitterLinkMetric(
            responder_al_mac=MAC_A,
            neighbor_al_mac=MAC_B,
            links=[
                TransmitterLinkEntry(
                    local_interface_mac=MAC_A,
                    neighbor_interface_mac=MAC_B,
                    intf_type=0x0100,
                    has_bridge=False,
                    packet_errors=3,
                    transmitted_packets=12345,
                    mac_throughput_mbps=433,
                    link_availability_pct_x100=9800,
                    phy_rate_mbps=866,
                )
            ],
        ),
        ReceiverLinkMetric(
            responder_al_mac=MAC_A,
            neighbor_al_mac=MAC_B,
            links=[
                ReceiverLinkEntry(
                    local_interface_mac=MAC_A,
                    neighbor_interface_mac=MAC_B,
                    intf_type=0x0100,
                    packet_errors=1,
                    packets_received=4242,
                    rssi_db=72,
                )
            ],
        ),
        VendorSpecific(oui=OUI_TEST, data=b"hello-vendor"),
        LinkMetricResultCode(result_code=0x00),
        SearchedRole(role=0x00),
        AutoconfigFreqBand(band=0x01),
        SupportedRole(role=0x00),
        SupportedFreqBand(band=0x02),
        WscFrame(wsc_payload=b"\x10\x4a" + b"\x00" * 32),  # token WSC M1 prefix + filler
        PushButtonEventNotification(
            media_types=[
                PbeMediaType(media_type=0x0100),
                PbeMediaType(media_type=0x0102, media_specific=b"\xde\xad"),
            ]
        ),
        PushButtonJoinNotification(
            notifier_al_mac=MAC_A,
            notifier_mid=0xBEEF,
            transmitter_mac=MAC_B,
            joining_interface_mac=MAC_C,
        ),
        GenericPhyDeviceInformation(
            al_mac=MAC_A,
            interfaces=[
                GenericPhyInterface(
                    interface_mac=MAC_B,
                    phy_oui=OUI_TEST,
                    phy_variant_index=1,
                    phy_variant_name="HomePNA 3.1",
                    description_url=b"http://example.com/phy.xml",
                    media_specific=b"\x01\x02",
                )
            ],
        ),
        DeviceIdentification(
            friendly_name="Test Bridge",
            manufacturer_name="ACME",
            manufacturer_model="X1",
        ),
        ControlUrl(url="http://192.0.2.1:1905/control"),
        IPv4(
            entries=[
                Ipv4Entry(
                    interface_mac=MAC_A,
                    addresses=[
                        Ipv4Address(address_type=1, address="192.0.2.10", dhcp_server="192.0.2.1"),
                        Ipv4Address(address_type=2, address="10.0.0.5", dhcp_server="0.0.0.0"),
                    ],
                )
            ]
        ),
        IPv6(
            entries=[
                Ipv6Entry(
                    interface_mac=MAC_A,
                    link_local="fe80::1",
                    addresses=[
                        Ipv6Address(address_type=2, address="2001:db8::1", origin="::"),
                    ],
                )
            ]
        ),
        GenericPhyEventNotification(
            interfaces=[
                GenericPhyEventEntry(interface_mac=MAC_A, event_data=b"\xab\xcd"),
            ]
        ),
        ProfileVersion(version=0x01),
        PowerOffInterface(
            interfaces=[
                PowerOffInterfaceEntry(
                    interface_mac=MAC_A,
                    media_type=0x0100,
                    phy_oui=b"\x00\x00\x00",
                    phy_variant_index=0,
                )
            ]
        ),
        InterfacePowerChangeInformation(
            entries=[InterfacePowerChangeEntry(interface_mac=MAC_A, state=0)]
        ),
        InterfacePowerChangeStatus(
            entries=[InterfacePowerChangeEntry(interface_mac=MAC_A, state=0)]
        ),
        L2NeighborDevice(
            local_interfaces=[
                L2LocalInterface(
                    local_interface_mac=MAC_A,
                    neighbors=[L2Neighbor(neighbor_mac=MAC_B, behind_macs=[MAC_C])],
                )
            ]
        ),
    ]


def build_frames(start_mid: int = 0x1000) -> list[Ether]:
    frames: list[Ether] = []
    for i, tlv in enumerate(_baseline_tlvs()):
        cmdu = CMDU(
            header=CMDUHeader(
                message_type=0x0004,  # Vendor specific message type — a neutral carrier
                message_id=start_mid + i,
            ),
            tlvs=[encode_typed(tlv)],  # type: ignore[arg-type]
        )
        wire = cmdu.to_bytes()
        eth = Ether(src=SRC_MAC, dst=DST_MAC, type=ETHERTYPE_IEEE1905) / Raw(load=wire)
        # Force deterministic timestamps (relative seconds), no real clock value.
        eth.time = float(i)
        frames.append(eth)
    return frames


def write(path: Path) -> None:
    wrpcap(str(path), build_frames())


if __name__ == "__main__":
    target = Path(__file__).parent / "baseline_1905.pcap"
    write(target)
    print(f"wrote {target} with {len(build_frames())} frames")
