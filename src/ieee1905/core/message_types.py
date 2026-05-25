# SPDX-License-Identifier: GPL-2.0-or-later
"""IEEE 1905.1 CMDU message types.

Values per IEEE 1905.1-2013 §17.1 (Table 17-1) plus the amendments. The
EasyMesh additions (0x8000+) land in Phase 2.
"""

from __future__ import annotations

from enum import IntEnum


class MessageType(IntEnum):
    """CMDU message type identifiers."""

    TOPOLOGY_DISCOVERY = 0x0000
    TOPOLOGY_NOTIFICATION = 0x0001
    TOPOLOGY_QUERY = 0x0002
    TOPOLOGY_RESPONSE = 0x0003
    VENDOR_SPECIFIC = 0x0004
    LINK_METRIC_QUERY = 0x0005
    LINK_METRIC_RESPONSE = 0x0006
    AP_AUTOCONFIGURATION_SEARCH = 0x0007
    AP_AUTOCONFIGURATION_RESPONSE = 0x0008
    AP_AUTOCONFIGURATION_WSC = 0x0009
    AP_AUTOCONFIGURATION_RENEW = 0x000A
    PUSH_BUTTON_EVENT_NOTIFICATION = 0x000B
    PUSH_BUTTON_JOIN_NOTIFICATION = 0x000C
    HIGHER_LAYER_QUERY = 0x000D
    HIGHER_LAYER_RESPONSE = 0x000E
    INTERFACE_POWER_CHANGE_REQUEST = 0x000F
    INTERFACE_POWER_CHANGE_RESPONSE = 0x0010
    GENERIC_PHY_QUERY = 0x0011
    GENERIC_PHY_RESPONSE = 0x0012

    @classmethod
    def describe(cls, value: int) -> str:
        """Human-readable label, falling back to a hex code for unknowns."""
        try:
            return cls(value).name
        except ValueError:
            return f"Unknown(0x{value:04x})"
