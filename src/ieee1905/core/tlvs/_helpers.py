# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared helpers for TLV implementations."""

from __future__ import annotations

from typing import Any

from ieee1905.plugins.registry import TLVDescriptor, get_registry

MAC_LEN = 6
OUI_LEN = 3


def parse_mac(payload: bytes, offset: int = 0) -> bytes:
    if offset + MAC_LEN > len(payload):
        raise ValueError(
            f"truncated MAC at offset {offset}: need {MAC_LEN} bytes, have {len(payload) - offset}"
        )
    return bytes(payload[offset : offset + MAC_LEN])


def format_mac(mac: bytes) -> str:
    if len(mac) != MAC_LEN:
        raise ValueError(f"MAC must be {MAC_LEN} bytes, got {len(mac)}")
    return ":".join(f"{b:02x}" for b in mac)


def parse_mac_str(s: str) -> bytes:
    parts = s.replace("-", ":").split(":")
    if len(parts) != MAC_LEN:
        raise ValueError(f"invalid MAC string: {s!r}")
    return bytes(int(p, 16) for p in parts)


def register_typed(cls: type[Any], *, spec_ref: str | None = None) -> type[Any]:
    """Register a typed TLV class with the global registry.

    The class itself acts as the registry handler — its ``from_payload``
    classmethod is what :func:`ieee1905.core.tlv.decode_raw` invokes.
    """
    get_registry().register(
        TLVDescriptor(
            tlv_type=cls.TLV_TYPE,
            name=cls.TLV_NAME,
            handler=cls,  # class object satisfies the from_payload contract
            spec_ref=spec_ref,
            source="builtin",
        )
    )
    return cls
