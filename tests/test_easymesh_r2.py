# SPDX-License-Identifier: GPL-2.0-or-later
"""EasyMesh R2 TLV tests."""

from __future__ import annotations

from pathlib import Path

from ieee1905.core import CMDU, TLVType
from ieee1905.core.tlv import decode_raw, encode_typed
from ieee1905.core.tlvs import BackhaulStaRadioCapabilities, ChannelScanNeighbor
from ieee1905.io import EthernetFrame
from ieee1905.io.backend import ETHERTYPE_IEEE1905, get_default_backend
from ieee1905.plugins import get_registry
from tests.fixtures.build_easymesh_r2_pcap import _r2_tlvs

FIXTURE = Path(__file__).parent / "fixtures" / "easymesh_r2.pcap"


def _rt(tlv: object) -> object:
    return decode_raw(encode_typed(tlv))  # type: ignore[arg-type]


def _iter_payloads() -> list[bytes]:
    backend = get_default_backend()
    out: list[bytes] = []
    for raw_frame, _ts in backend.open_offline(str(FIXTURE)):
        eth = EthernetFrame.parse(raw_frame)
        if eth.ethertype == ETHERTYPE_IEEE1905:
            out.append(eth.payload)
    return out


def test_every_r2_tlv_round_trips() -> None:
    for original in _r2_tlvs():
        decoded = _rt(original)
        assert type(decoded) is type(original), (
            f"{type(original).__name__}: decoded as {type(decoded).__name__}"
        )
        assert decoded == original, f"{type(original).__name__}: value mismatch"


def test_r2_fixture_exists() -> None:
    assert FIXTURE.exists(), (
        f"missing fixture: {FIXTURE} (regenerate with build_easymesh_r2_pcap)"
    )


def test_r2_fixture_frame_count() -> None:
    payloads = _iter_payloads()
    assert len(payloads) == len(_r2_tlvs())


def test_r2_fixture_wire_format_locked() -> None:
    payloads = _iter_payloads()
    for i, (payload, original) in enumerate(zip(payloads, _r2_tlvs(), strict=True)):
        cmdu = CMDU.from_bytes(payload)
        assert len(cmdu.tlvs) == 2, f"frame {i}: expected 2 TLVs, got {len(cmdu.tlvs)}"
        assert cmdu.tlvs[-1].tlv_type == TLVType.END_OF_MESSAGE.value
        assert cmdu.tlvs[0] == encode_typed(original), (  # type: ignore[arg-type]
            f"frame {i}: {type(original).__name__} wire bytes drifted"
        )


def test_r2_fixture_typed_decode_matches_original() -> None:
    payloads = _iter_payloads()
    for i, (payload, original) in enumerate(zip(payloads, _r2_tlvs(), strict=True)):
        cmdu = CMDU.from_bytes(payload)
        typed = list(cmdu.typed_tlvs())
        assert isinstance(typed[0], type(original)), (
            f"frame {i}: decoded as {type(typed[0]).__name__}, "
            f"expected {type(original).__name__}"
        )
        assert typed[0] == original, f"frame {i}: {type(original).__name__} mismatch"


def test_every_r2_tlv_type_has_a_handler() -> None:
    """Coverage gate: every R2 TLVType (0xA4-0xCC range) has a registered handler."""
    registry = get_registry()
    r2_range = range(0xA4, 0xCD)
    missing = [
        t.name
        for t in TLVType
        if t.value in r2_range and registry.lookup(t.value) is None
    ]
    assert not missing, f"R2 TLV types missing a handler: {missing}"


def test_channel_scan_neighbor_optional_bss_load() -> None:
    """BSS Load fields only serialize when flags bit 7 is set."""
    bssid = b"\xaa\xbb\xcc\xdd\xee\xff"
    # Without BSS Load
    n_no_load = ChannelScanNeighbor(
        bssid=bssid, ssid=b"test", signal_strength=200, channel_bandwidth="20"
    )
    encoded_no = n_no_load.to_bytes()

    # With BSS Load
    n_with_load = ChannelScanNeighbor(
        bssid=bssid,
        ssid=b"test",
        signal_strength=200,
        channel_bandwidth="20",
        flags=0x80,
        channel_utilization=60,
        station_count=10,
    )
    encoded_with = n_with_load.to_bytes()

    # The with-load encoding should be 3 bytes longer (1 byte utilization + 2 bytes count).
    assert len(encoded_with) == len(encoded_no) + 3


def test_backhaul_sta_radio_capabilities_optional_mac() -> None:
    """The backhaul STA MAC field is optional."""
    rid = b"\x00" * 6
    minimal = BackhaulStaRadioCapabilities(radio_id=rid, flags=0x00, backhaul_sta_mac=None)
    full = BackhaulStaRadioCapabilities(radio_id=rid, flags=0x80, backhaul_sta_mac=b"\x11" * 6)

    assert _rt(minimal) == minimal
    assert _rt(full) == full
    assert len(encode_typed(minimal).payload) == 7  # type: ignore[arg-type]
    assert len(encode_typed(full).payload) == 13  # type: ignore[arg-type]
