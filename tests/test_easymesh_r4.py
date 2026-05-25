# SPDX-License-Identifier: GPL-2.0-or-later
"""EasyMesh R4 (Wi-Fi 7 / EHT / MLD) TLV tests."""

from __future__ import annotations

from pathlib import Path

from ieee1905.core import CMDU, TLVType
from ieee1905.core.tlv import decode_raw, encode_typed
from ieee1905.io import EthernetFrame
from ieee1905.io.backend import ETHERTYPE_IEEE1905, get_default_backend
from ieee1905.plugins import get_registry
from tests.fixtures.build_easymesh_r4_pcap import _r4_tlvs

FIXTURE = Path(__file__).parent / "fixtures" / "easymesh_r4.pcap"


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


def test_every_r4_tlv_round_trips() -> None:
    for original in _r4_tlvs():
        decoded = _rt(original)
        assert type(decoded) is type(original), (
            f"{type(original).__name__}: decoded as {type(decoded).__name__}"
        )
        assert decoded == original, f"{type(original).__name__}: value mismatch"


def test_r4_fixture_exists_and_count() -> None:
    assert FIXTURE.exists()
    assert len(_iter_payloads()) == len(_r4_tlvs())


def test_r4_fixture_wire_format_locked() -> None:
    payloads = _iter_payloads()
    for i, (payload, original) in enumerate(zip(payloads, _r4_tlvs(), strict=True)):
        cmdu = CMDU.from_bytes(payload)
        assert len(cmdu.tlvs) == 2
        assert cmdu.tlvs[-1].tlv_type == TLVType.END_OF_MESSAGE.value
        assert cmdu.tlvs[0] == encode_typed(original), (  # type: ignore[arg-type]
            f"frame {i}: {type(original).__name__} wire bytes drifted"
        )


def test_r4_fixture_typed_decode_matches_original() -> None:
    payloads = _iter_payloads()
    for i, (payload, original) in enumerate(zip(payloads, _r4_tlvs(), strict=True)):
        cmdu = CMDU.from_bytes(payload)
        typed = list(cmdu.typed_tlvs())
        assert isinstance(typed[0], type(original)), (
            f"frame {i}: decoded as {type(typed[0]).__name__}, "
            f"expected {type(original).__name__}"
        )
        assert typed[0] == original, f"frame {i}: {type(original).__name__} mismatch"


def test_every_r4_tlv_type_has_a_handler() -> None:
    """Coverage gate: every R4 TLVType (0xE0-0xE8 + AP Wi-Fi 6 at 0xAA) is registered."""
    registry = get_registry()
    r4_types = set(range(0xE0, 0xE9)) | {0xAA}
    missing = [
        t.name
        for t in TLVType
        if t.value in r4_types and registry.lookup(t.value) is None
    ]
    assert not missing, f"R4 TLV types missing a handler: {missing}"


def test_every_tlv_type_in_enum_has_a_handler() -> None:
    """End-to-end coverage gate across the full TLVType enum."""
    registry = get_registry()
    missing = [t.name for t in TLVType if registry.lookup(t.value) is None]
    assert not missing, f"TLV types missing a handler: {missing}"
