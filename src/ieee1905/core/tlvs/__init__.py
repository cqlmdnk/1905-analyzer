# SPDX-License-Identifier: GPL-2.0-or-later
"""Built-in IEEE 1905.1 TLV implementations.

Importing this package registers every concrete TLV class with the
global :class:`~ieee1905.plugins.registry.TLVRegistry`, so the rest of
the codebase can decode wire TLVs into typed objects via
:func:`ieee1905.core.tlv.decode_raw`.
"""

from ieee1905.core.tlvs.ieee1905_1 import (
    AlMacAddress,
    AutoconfigFreqBand,
    DeviceInformation,
    EndOfMessage,
    LinkMetricResultCode,
    LocalInterface,
    MacAddress,
    NeighborDevice,
    NeighborEntry,
    ProfileVersion,
    SearchedRole,
    SupportedFreqBand,
    SupportedRole,
    VendorSpecific,
)

__all__ = [
    "AlMacAddress",
    "AutoconfigFreqBand",
    "DeviceInformation",
    "EndOfMessage",
    "LinkMetricResultCode",
    "LocalInterface",
    "MacAddress",
    "NeighborDevice",
    "NeighborEntry",
    "ProfileVersion",
    "SearchedRole",
    "SupportedFreqBand",
    "SupportedRole",
    "VendorSpecific",
]
