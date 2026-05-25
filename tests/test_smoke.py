# SPDX-License-Identifier: GPL-2.0-or-later
"""Phase 0 smoke tests — package imports and skeleton wiring."""

from __future__ import annotations

import re

import ieee1905
from ieee1905.io import check_privileges
from ieee1905.io.backend import ETHERTYPE_IEEE1905, ScapyBackend, get_default_backend
from ieee1905.plugins import TLVDescriptor, get_registry


def test_version_is_pep440_ish() -> None:
    assert isinstance(ieee1905.__version__, str)
    assert re.match(r"^\d+\.\d+\.\d+", ieee1905.__version__)


def test_ethertype_constant() -> None:
    assert ETHERTYPE_IEEE1905 == 0x893A


def test_default_backend_is_scapy() -> None:
    backend = get_default_backend()
    assert isinstance(backend, ScapyBackend)
    assert backend.name == "scapy"


def test_privilege_check_returns_struct() -> None:
    pc = check_privileges()
    assert pc.platform in {"linux", "darwin", "windows", "unknown"} or pc.platform
    assert isinstance(pc.ok, bool)
    assert isinstance(pc.detail, str)


def test_registry_round_trip() -> None:
    class _Dummy:
        tlv_type = 0xFE
        name = "dummy"

        def decode(self, payload: bytes) -> dict[str, object]:
            return {"raw": payload}

        def encode(self, data: dict[str, object]) -> bytes:
            return bytes(data.get("raw", b""))  # type: ignore[arg-type]

    reg = get_registry()
    reg.register(
        TLVDescriptor(tlv_type=0xFE, name="dummy", handler=_Dummy(), source="builtin")
    )
    desc = reg.lookup(0xFE)
    assert desc is not None
    assert desc.name == "dummy"
    assert desc.handler.decode(b"\x01\x02") == {"raw": b"\x01\x02"}
