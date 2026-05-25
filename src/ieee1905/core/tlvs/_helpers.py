# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared helpers for TLV implementations."""

from __future__ import annotations

import ipaddress
from typing import Any

from ieee1905.plugins.registry import TLVDescriptor, get_registry

MAC_LEN = 6
OUI_LEN = 3
IPV4_LEN = 4
IPV6_LEN = 16


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


def parse_ipv4(payload: bytes, offset: int = 0) -> str:
    if offset + IPV4_LEN > len(payload):
        raise ValueError(
            f"truncated IPv4 at offset {offset}: need {IPV4_LEN}, have {len(payload) - offset}"
        )
    return str(ipaddress.IPv4Address(bytes(payload[offset : offset + IPV4_LEN])))


def encode_ipv4(addr: str) -> bytes:
    return ipaddress.IPv4Address(addr).packed


def parse_ipv6(payload: bytes, offset: int = 0) -> str:
    if offset + IPV6_LEN > len(payload):
        raise ValueError(
            f"truncated IPv6 at offset {offset}: need {IPV6_LEN}, have {len(payload) - offset}"
        )
    return str(ipaddress.IPv6Address(bytes(payload[offset : offset + IPV6_LEN])))


def encode_ipv6(addr: str) -> bytes:
    return ipaddress.IPv6Address(addr).packed


def parse_padded_ascii(payload: bytes, offset: int, length: int) -> str:
    """Read ``length`` bytes; treat NUL-padded ASCII (drop trailing NULs).

    Bytes outside printable ASCII are kept as Latin-1; callers can
    re-decode if they have a specific encoding contract.
    """
    if offset + length > len(payload):
        raise ValueError(
            f"truncated padded-ASCII at offset {offset}: need {length}, "
            f"have {len(payload) - offset}"
        )
    chunk = bytes(payload[offset : offset + length]).rstrip(b"\x00")
    return chunk.decode("latin-1")


def encode_padded_ascii(text: str, length: int) -> bytes:
    raw = text.encode("latin-1")
    if len(raw) > length:
        raise ValueError(f"string {text!r} exceeds {length}-byte field")
    return raw.ljust(length, b"\x00")


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
