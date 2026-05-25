# SPDX-License-Identifier: GPL-2.0-or-later
"""User-extensible TLV plugin system.

Two registration paths:
- YAML declarative — for fixed-layout TLVs.
- Python ``@register_tlv`` — for complex / conditional parsing.
"""

from ieee1905.plugins.registry import (
    TLVDescriptor,
    TLVPlugin,
    TLVRegistry,
    get_registry,
    register_tlv,
)

__all__ = [
    "TLVDescriptor",
    "TLVPlugin",
    "TLVRegistry",
    "get_registry",
    "register_tlv",
]
