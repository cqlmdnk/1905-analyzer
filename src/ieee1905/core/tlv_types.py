# SPDX-License-Identifier: GPL-2.0-or-later
"""IEEE 1905.1 TLV type identifiers.

Per IEEE 1905.1-2013 §17.2 (Table 17-2) and amendments. EasyMesh adds
many types in the 0x80+ range; those are introduced in Phase 2.
"""

from __future__ import annotations

from enum import IntEnum


class TLVType(IntEnum):
    """IEEE 1905.1 baseline TLV type identifiers."""

    END_OF_MESSAGE = 0x00
    AL_MAC_ADDRESS = 0x01
    MAC_ADDRESS = 0x02
    DEVICE_INFORMATION = 0x03
    DEVICE_BRIDGING_CAPABILITY = 0x04
    # 0x05 is reserved
    NON_1905_NEIGHBOR_DEVICE_LIST = 0x06
    NEIGHBOR_DEVICE = 0x07
    LINK_METRIC_QUERY = 0x08
    TRANSMITTER_LINK_METRIC = 0x09
    RECEIVER_LINK_METRIC = 0x0A
    VENDOR_SPECIFIC = 0x0B
    LINK_METRIC_RESULT_CODE = 0x0C
    SEARCHED_ROLE = 0x0D
    AUTOCONFIG_FREQ_BAND = 0x0E
    SUPPORTED_ROLE = 0x0F
    SUPPORTED_FREQ_BAND = 0x10
    WSC = 0x11
    PUSH_BUTTON_EVENT_NOTIFICATION = 0x12
    PUSH_BUTTON_JOIN_NOTIFICATION = 0x13
    GENERIC_PHY_DEVICE_INFORMATION = 0x14
    DEVICE_IDENTIFICATION = 0x15
    CONTROL_URL = 0x16
    IPV4 = 0x17
    IPV6 = 0x18
    GENERIC_PHY_EVENT_NOTIFICATION = 0x19
    PROFILE_VERSION = 0x1A
    POWER_OFF_INTERFACE = 0x1B
    INTERFACE_POWER_CHANGE_INFORMATION = 0x1C
    INTERFACE_POWER_CHANGE_STATUS = 0x1D
    L2_NEIGHBOR_DEVICE = 0x1E

    @classmethod
    def describe(cls, value: int) -> str:
        try:
            return cls(value).name
        except ValueError:
            return f"Unknown(0x{value:02x})"
