# SPDX-License-Identifier: GPL-2.0-or-later
"""TLV registry skeleton.

The registry maps integer TLV types to handlers that know how to decode and
encode their payload. Vendor-specific TLVs (type ``0x0B``) are dispatched
through a secondary OUI table once the wrapping TLV has been decoded.

Concrete TLV implementations (built-in 1905.1 / EasyMesh types as well as
user-supplied plugins) plug in via :func:`register_tlv` or by being loaded
from YAML descriptors. Phase 0 only provides the registry skeleton; payload
parsing arrives in Phase 1.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar, Protocol

logger = logging.getLogger(__name__)


class TLVPlugin(Protocol):
    """Protocol satisfied by every TLV handler."""

    tlv_type: ClassVar[int]
    name: ClassVar[str]

    def decode(self, payload: bytes) -> dict[str, Any]:
        ...

    def encode(self, data: dict[str, Any]) -> bytes:
        ...


@dataclass(slots=True)
class TLVDescriptor:
    """Metadata + handler for a single TLV type."""

    tlv_type: int
    name: str
    # The handler may be either an instance of a class with decode/encode
    # methods (TLVPlugin protocol) or a class object with from_payload /
    # to_payload (the typed-TLV style used by built-ins). Both are dispatched
    # structurally by ieee1905.core.tlv.decode_raw.
    handler: Any
    spec_ref: str | None = None  # e.g. "IEEE 1905.1 §17.2.4"
    source: str = "builtin"  # "builtin" | "yaml" | "python"


@dataclass(slots=True)
class TLVRegistry:
    by_type: dict[int, TLVDescriptor] = field(default_factory=dict)
    # vendor-specific (0x0B) -> OUI(3 bytes) -> sub-descriptor
    vendor_by_oui: dict[bytes, TLVDescriptor] = field(default_factory=dict)

    def register(self, descriptor: TLVDescriptor) -> None:
        existing = self.by_type.get(descriptor.tlv_type)
        if existing is not None and existing.source == "builtin" and descriptor.source != "builtin":
            logger.info(
                "overriding builtin TLV 0x%02x (%s) with %s plugin %s",
                descriptor.tlv_type,
                existing.name,
                descriptor.source,
                descriptor.name,
            )
        self.by_type[descriptor.tlv_type] = descriptor

    def register_vendor(self, oui: bytes, descriptor: TLVDescriptor) -> None:
        if len(oui) != 3:
            raise ValueError(f"OUI must be 3 bytes, got {len(oui)}")
        self.vendor_by_oui[oui] = descriptor

    def lookup(self, tlv_type: int) -> TLVDescriptor | None:
        return self.by_type.get(tlv_type)


_registry: TLVRegistry | None = None


def get_registry() -> TLVRegistry:
    global _registry
    if _registry is None:
        _registry = TLVRegistry()
    return _registry


def register_tlv(
    *,
    tlv_type: int,
    name: str,
    spec_ref: str | None = None,
) -> Callable[[type[TLVPlugin]], type[TLVPlugin]]:
    """Decorator for Python-defined TLV handlers."""

    def _wrap(cls: type[TLVPlugin]) -> type[TLVPlugin]:
        get_registry().register(
            TLVDescriptor(
                tlv_type=tlv_type,
                name=name,
                handler=cls(),
                spec_ref=spec_ref,
                source="python",
            )
        )
        return cls

    return _wrap
