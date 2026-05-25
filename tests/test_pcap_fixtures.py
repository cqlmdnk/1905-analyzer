# SPDX-License-Identifier: GPL-2.0-or-later
"""Regression tests for the committed baseline PCAP fixture.

Locks the wire format of every implemented 1905.1 TLV: if the fixture
parses differently after a code change, we know an encoder/decoder is
drifting. Re-generate the fixture intentionally with::

    python -m tests.fixtures.build_baseline_pcap
"""

from __future__ import annotations

from pathlib import Path

from ieee1905.core import CMDU, RawTLV, TLVType
from ieee1905.core.tlv import encode_typed
from ieee1905.io import EthernetFrame
from ieee1905.io.backend import ETHERTYPE_IEEE1905, get_default_backend
from ieee1905.plugins import get_registry
from tests.fixtures.build_baseline_pcap import _baseline_tlvs

FIXTURE = Path(__file__).parent / "fixtures" / "baseline_1905.pcap"


def _iter_1905_payloads() -> list[bytes]:
    """Yield CMDU payload bytes from every 1905 frame in the fixture."""
    backend = get_default_backend()
    payloads: list[bytes] = []
    for raw_frame, _ts in backend.open_offline(str(FIXTURE)):
        eth = EthernetFrame.parse(raw_frame)
        if eth.ethertype != ETHERTYPE_IEEE1905:
            continue
        payloads.append(eth.payload)
    return payloads


def test_fixture_exists() -> None:
    assert FIXTURE.exists(), f"missing fixture: {FIXTURE} (regenerate with build_baseline_pcap)"


def test_fixture_has_one_frame_per_baseline_tlv() -> None:
    payloads = _iter_1905_payloads()
    assert len(payloads) == len(_baseline_tlvs())


def test_fixture_round_trip_matches_generator() -> None:
    payloads = _iter_1905_payloads()
    expected = _baseline_tlvs()
    for i, (payload, original_tlv) in enumerate(zip(payloads, expected, strict=True)):
        cmdu = CMDU.from_bytes(payload)
        # Each fixture CMDU carries exactly one TLV + the auto-appended EoM.
        assert len(cmdu.tlvs) == 2, f"frame {i}: expected 2 TLVs, got {len(cmdu.tlvs)}"
        assert cmdu.tlvs[-1].tlv_type == TLVType.END_OF_MESSAGE.value
        # The first TLV should encode to the same wire bytes as the original.
        assert cmdu.tlvs[0] == encode_typed(original_tlv), (  # type: ignore[arg-type]
            f"frame {i}: wire bytes drifted from generator (tlv #{i})"
        )


def test_fixture_typed_tlvs_decode_into_original_classes() -> None:
    payloads = _iter_1905_payloads()
    expected = _baseline_tlvs()
    for i, (payload, original_tlv) in enumerate(zip(payloads, expected, strict=True)):
        cmdu = CMDU.from_bytes(payload)
        typed = list(cmdu.typed_tlvs())
        # Same shape: original TLV + EoM.
        assert len(typed) == 2
        assert isinstance(typed[0], type(original_tlv)), (
            f"frame {i}: decoded as {type(typed[0]).__name__}, "
            f"expected {type(original_tlv).__name__}"
        )
        assert typed[0] == original_tlv, f"frame {i}: typed mismatch"


def test_every_known_tlv_type_has_a_registered_handler() -> None:
    """Coverage gate: every value in TLVType must have a TLVRegistry entry.

    Catches the case where someone adds a constant to the enum but forgets
    to wire up the codec.
    """
    registry = get_registry()
    missing = [t.name for t in TLVType if registry.lookup(t.value) is None]
    assert not missing, (
        "TLV types declared in the TLVType enum but missing a registered "
        f"handler: {missing}"
    )


def test_unknown_tlv_in_fixture_would_decode_as_raw() -> None:
    """Sanity check on the Unknown-TLV path used by the analyzer UI."""
    payloads = _iter_1905_payloads()
    cmdu = CMDU.from_bytes(payloads[0])
    # Inject an unregistered TLV type into the parsed CMDU; round-trip and
    # ensure decode_raw leaves it as RawTLV (not a typed object).
    cmdu.tlvs.insert(0, RawTLV(tlv_type=0xEE, payload=b"unknown-payload"))
    rebuilt = CMDU.from_bytes(cmdu.to_bytes(append_end_of_message=False))
    typed = list(rebuilt.typed_tlvs())
    assert isinstance(typed[0], RawTLV)
    assert typed[0].payload == b"unknown-payload"
