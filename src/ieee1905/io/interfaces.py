# SPDX-License-Identifier: GPL-2.0-or-later
"""Cross-platform network interface enumeration."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Interface:
    name: str
    description: str | None
    mac: str | None
    is_loopback: bool
    is_up: bool


def list_interfaces() -> list[Interface]:
    """List available network interfaces using Scapy as a portable backend.

    Phase 0 uses Scapy for portability. Phase 4 will switch to direct
    libpcap/Npcap calls when bridge mode requires lower-level access.
    """
    from scapy.arch import get_if_hwaddr
    from scapy.interfaces import get_working_ifaces

    result: list[Interface] = []
    for iface in get_working_ifaces():
        try:
            mac = get_if_hwaddr(iface.name)
        except Exception:  # noqa: BLE001
            mac = None
        result.append(
            Interface(
                name=iface.name,
                description=getattr(iface, "description", None),
                mac=mac,
                is_loopback=iface.name in ("lo", "lo0", "Loopback"),
                is_up=bool(getattr(iface, "flags", 0)) or True,
            )
        )
    return result
