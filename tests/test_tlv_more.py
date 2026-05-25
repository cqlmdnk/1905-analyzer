# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for the remaining 1905.1 baseline TLVs (ieee1905_1_more)."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ieee1905.core import RawTLV
from ieee1905.core.tlv import decode_raw, encode_typed
from ieee1905.core.tlvs import (
    BridgingTuple,
    ControlUrl,
    DeviceBridgingCapability,
    DeviceIdentification,
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
    Non1905NeighborDeviceList,
    PbeMediaType,
    PowerOffInterface,
    PowerOffInterfaceEntry,
    PushButtonEventNotification,
    PushButtonJoinNotification,
    ReceiverLinkEntry,
    ReceiverLinkMetric,
    TransmitterLinkEntry,
    TransmitterLinkMetric,
    WscFrame,
)

MAC_A = b"\x00\x11\x22\x33\x44\x55"
MAC_B = b"\xaa\xbb\xcc\xdd\xee\xff"
MAC_C = b"\x01\x02\x03\x04\x05\x06"
OUI_T = b"\x00\x1a\x2b"


def _rt(tlv: object) -> object:
    return decode_raw(encode_typed(tlv))  # type: ignore[arg-type]


# ---- 0x04 Device bridging capability -----------------------------------------


def test_device_bridging_capability_round_trip() -> None:
    tlv = DeviceBridgingCapability(
        tuples=[
            BridgingTuple(macs=[MAC_A, MAC_B]),
            BridgingTuple(macs=[MAC_C]),
            BridgingTuple(),  # empty tuple is legal: 0 MACs in this bridge
        ]
    )
    decoded = _rt(tlv)
    assert isinstance(decoded, DeviceBridgingCapability)
    assert decoded == tlv


# ---- 0x06 Non-1905 neighbor device list --------------------------------------


def test_non1905_neighbor_round_trip() -> None:
    tlv = Non1905NeighborDeviceList(
        local_interface_mac=MAC_A,
        neighbor_macs=[MAC_B, MAC_C],
    )
    decoded = _rt(tlv)
    assert isinstance(decoded, Non1905NeighborDeviceList)
    assert decoded == tlv


def test_non1905_neighbor_misaligned_rejected() -> None:
    raw = RawTLV(tlv_type=0x06, payload=MAC_A + b"\x01\x02\x03")
    try:
        decode_raw(raw)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- 0x08 Link metric query --------------------------------------------------


def test_link_metric_query_round_trip() -> None:
    for nb_type, nb_mac in [(0x00, b"\x00" * 6), (0x01, MAC_B)]:
        tlv = LinkMetricQuery(neighbor_type=nb_type, neighbor_al_mac=nb_mac, link_metrics=0x02)
        decoded = _rt(tlv)
        assert isinstance(decoded, LinkMetricQuery)
        assert decoded == tlv


def test_link_metric_query_wrong_length_rejected() -> None:
    raw = RawTLV(tlv_type=0x08, payload=b"\x00" * 5)
    try:
        decode_raw(raw)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- 0x09 Transmitter link metric --------------------------------------------


def test_transmitter_link_metric_round_trip() -> None:
    entries = [
        TransmitterLinkEntry(
            local_interface_mac=MAC_A,
            neighbor_interface_mac=MAC_B,
            intf_type=0x0100,
            has_bridge=False,
            packet_errors=12,
            transmitted_packets=99999,
            mac_throughput_mbps=433,
            link_availability_pct_x100=9500,
            phy_rate_mbps=1300,
        ),
        TransmitterLinkEntry(
            local_interface_mac=MAC_B,
            neighbor_interface_mac=MAC_C,
            intf_type=0x0001,
            has_bridge=True,
            packet_errors=0,
            transmitted_packets=1,
            mac_throughput_mbps=1000,
            link_availability_pct_x100=10000,
            phy_rate_mbps=1000,
        ),
    ]
    tlv = TransmitterLinkMetric(responder_al_mac=MAC_A, neighbor_al_mac=MAC_C, links=entries)
    decoded = _rt(tlv)
    assert isinstance(decoded, TransmitterLinkMetric)
    assert decoded == tlv


# ---- 0x0A Receiver link metric -----------------------------------------------


def test_receiver_link_metric_round_trip() -> None:
    entries = [
        ReceiverLinkEntry(
            local_interface_mac=MAC_A,
            neighbor_interface_mac=MAC_B,
            intf_type=0x0100,
            packet_errors=7,
            packets_received=4242,
            rssi_db=85,
        )
    ]
    tlv = ReceiverLinkMetric(responder_al_mac=MAC_A, neighbor_al_mac=MAC_B, links=entries)
    decoded = _rt(tlv)
    assert isinstance(decoded, ReceiverLinkMetric)
    assert decoded == tlv


# ---- 0x11 WSC ----------------------------------------------------------------


def test_wsc_round_trip_with_arbitrary_payload() -> None:
    payload = bytes(range(256)) * 2
    tlv = WscFrame(wsc_payload=payload)
    decoded = _rt(tlv)
    assert isinstance(decoded, WscFrame)
    assert decoded.wsc_payload == payload


# ---- 0x12 Push button event notification -------------------------------------


def test_pbe_notification_round_trip() -> None:
    tlv = PushButtonEventNotification(
        media_types=[
            PbeMediaType(media_type=0x0100),
            PbeMediaType(media_type=0x0102, media_specific=b"\xde\xad"),
        ]
    )
    decoded = _rt(tlv)
    assert isinstance(decoded, PushButtonEventNotification)
    assert decoded == tlv


# ---- 0x13 Push button join notification --------------------------------------


def test_pbj_notification_round_trip() -> None:
    tlv = PushButtonJoinNotification(
        notifier_al_mac=MAC_A,
        notifier_mid=0xBEEF,
        transmitter_mac=MAC_B,
        joining_interface_mac=MAC_C,
    )
    decoded = _rt(tlv)
    assert isinstance(decoded, PushButtonJoinNotification)
    assert decoded == tlv


# ---- 0x14 Generic PHY device information -------------------------------------


def test_generic_phy_device_information_round_trip() -> None:
    tlv = GenericPhyDeviceInformation(
        al_mac=MAC_A,
        interfaces=[
            GenericPhyInterface(
                interface_mac=MAC_B,
                phy_oui=OUI_T,
                phy_variant_index=0,
                phy_variant_name="HomePNA 3.1",
                description_url=b"http://example.com/phy.xml",
                media_specific=b"\x01\x02",
            )
        ],
    )
    decoded = _rt(tlv)
    assert isinstance(decoded, GenericPhyDeviceInformation)
    assert decoded == tlv


# ---- 0x15 Device identification ----------------------------------------------


def test_device_identification_round_trip() -> None:
    tlv = DeviceIdentification(
        friendly_name="Test Bridge",
        manufacturer_name="ACME",
        manufacturer_model="X1",
    )
    decoded = _rt(tlv)
    assert isinstance(decoded, DeviceIdentification)
    assert decoded == tlv


def test_device_identification_field_too_long_rejected() -> None:
    try:
        DeviceIdentification(friendly_name="x" * 100, manufacturer_name="A", manufacturer_model="B")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- 0x16 Control URL --------------------------------------------------------


def test_control_url_round_trip() -> None:
    tlv = ControlUrl(url="http://192.0.2.1:1905/control")
    decoded = _rt(tlv)
    assert isinstance(decoded, ControlUrl)
    assert decoded == tlv


# ---- 0x17 IPv4 ---------------------------------------------------------------


def test_ipv4_round_trip() -> None:
    tlv = IPv4(
        entries=[
            Ipv4Entry(
                interface_mac=MAC_A,
                addresses=[
                    Ipv4Address(address_type=1, address="192.0.2.10", dhcp_server="192.0.2.1"),
                    Ipv4Address(address_type=2, address="10.0.0.5", dhcp_server="0.0.0.0"),
                ],
            ),
            Ipv4Entry(interface_mac=MAC_B, addresses=[]),
        ]
    )
    decoded = _rt(tlv)
    assert isinstance(decoded, IPv4)
    assert decoded == tlv


# ---- 0x18 IPv6 ---------------------------------------------------------------


def test_ipv6_round_trip() -> None:
    tlv = IPv6(
        entries=[
            Ipv6Entry(
                interface_mac=MAC_A,
                link_local="fe80::1",
                addresses=[
                    Ipv6Address(
                        address_type=2,
                        address="2001:db8::1",
                        origin="::",
                    ),
                ],
            )
        ]
    )
    decoded = _rt(tlv)
    assert isinstance(decoded, IPv6)
    assert decoded == tlv


# ---- 0x19 Generic PHY event notification -------------------------------------


def test_generic_phy_event_notification_round_trip() -> None:
    tlv = GenericPhyEventNotification(
        interfaces=[
            GenericPhyEventEntry(interface_mac=MAC_A, event_data=b"\xab\xcd"),
            GenericPhyEventEntry(interface_mac=MAC_B, event_data=b""),
        ]
    )
    decoded = _rt(tlv)
    assert isinstance(decoded, GenericPhyEventNotification)
    assert decoded == tlv


# ---- 0x1B Power off interface ------------------------------------------------


def test_power_off_interface_round_trip() -> None:
    tlv = PowerOffInterface(
        interfaces=[
            PowerOffInterfaceEntry(
                interface_mac=MAC_A,
                media_type=0x0100,
                phy_oui=b"\x00\x00\x00",
                phy_variant_index=0,
            ),
            PowerOffInterfaceEntry(
                interface_mac=MAC_B,
                media_type=0xFFFF,  # generic PHY
                phy_oui=OUI_T,
                phy_variant_index=2,
                media_specific=b"\x42",
            ),
        ]
    )
    decoded = _rt(tlv)
    assert isinstance(decoded, PowerOffInterface)
    assert decoded == tlv


# ---- 0x1C / 0x1D Interface power change information / status -----------------


def test_interface_power_change_information_round_trip() -> None:
    tlv = InterfacePowerChangeInformation(
        entries=[
            InterfacePowerChangeEntry(interface_mac=MAC_A, state=0),
            InterfacePowerChangeEntry(interface_mac=MAC_B, state=2),
        ]
    )
    decoded = _rt(tlv)
    assert isinstance(decoded, InterfacePowerChangeInformation)
    assert decoded == tlv


def test_interface_power_change_status_round_trip() -> None:
    tlv = InterfacePowerChangeStatus(
        entries=[InterfacePowerChangeEntry(interface_mac=MAC_C, state=1)]
    )
    decoded = _rt(tlv)
    assert isinstance(decoded, InterfacePowerChangeStatus)
    assert decoded == tlv


def test_interface_power_change_wrong_length_rejected() -> None:
    raw = RawTLV(tlv_type=0x1C, payload=b"\x01" + b"\x00" * 5)  # count says 1 entry (7 bytes), has 5
    try:
        decode_raw(raw)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- 0x1E L2 neighbor device -------------------------------------------------


def test_l2_neighbor_device_round_trip() -> None:
    tlv = L2NeighborDevice(
        local_interfaces=[
            L2LocalInterface(
                local_interface_mac=MAC_A,
                neighbors=[
                    L2Neighbor(neighbor_mac=MAC_B, behind_macs=[MAC_C]),
                    L2Neighbor(neighbor_mac=MAC_C, behind_macs=[]),
                ],
            ),
            L2LocalInterface(local_interface_mac=MAC_B, neighbors=[]),
        ]
    )
    decoded = _rt(tlv)
    assert isinstance(decoded, L2NeighborDevice)
    assert decoded == tlv


# --- Hypothesis property tests ------------------------------------------------


mac_strategy = st.binary(min_size=6, max_size=6)
oui_strategy = st.binary(min_size=3, max_size=3)


@st.composite
def _transmitter_entry(draw: st.DrawFn) -> TransmitterLinkEntry:
    return TransmitterLinkEntry(
        local_interface_mac=draw(mac_strategy),
        neighbor_interface_mac=draw(mac_strategy),
        intf_type=draw(st.integers(0, 0xFFFF)),
        has_bridge=draw(st.booleans()),
        packet_errors=draw(st.integers(0, 0xFFFFFFFF)),
        transmitted_packets=draw(st.integers(0, 0xFFFFFFFF)),
        mac_throughput_mbps=draw(st.integers(0, 0xFFFF)),
        link_availability_pct_x100=draw(st.integers(0, 0xFFFF)),
        phy_rate_mbps=draw(st.integers(0, 0xFFFF)),
    )


@given(
    responder=mac_strategy,
    neighbor=mac_strategy,
    links=st.lists(_transmitter_entry(), max_size=6),
)
@settings(max_examples=50)
def test_transmitter_link_metric_property(
    responder: bytes, neighbor: bytes, links: list[TransmitterLinkEntry]
) -> None:
    tlv = TransmitterLinkMetric(responder_al_mac=responder, neighbor_al_mac=neighbor, links=links)
    decoded = _rt(tlv)
    assert isinstance(decoded, TransmitterLinkMetric)
    assert decoded == tlv


ipv4_str_strategy = st.ip_addresses(v=4).map(str)


@st.composite
def _ipv4_entry(draw: st.DrawFn) -> Ipv4Entry:
    addrs = draw(
        st.lists(
            st.builds(
                Ipv4Address,
                address_type=st.integers(0, 3),
                address=ipv4_str_strategy,
                dhcp_server=ipv4_str_strategy,
            ),
            max_size=4,
        )
    )
    return Ipv4Entry(interface_mac=draw(mac_strategy), addresses=addrs)


@given(entries=st.lists(_ipv4_entry(), max_size=4))
@settings(max_examples=30)
def test_ipv4_property(entries: list[Ipv4Entry]) -> None:
    tlv = IPv4(entries=entries)
    decoded = _rt(tlv)
    assert isinstance(decoded, IPv4)
    assert decoded == tlv
