# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared helpers for the DUT emulators."""

from __future__ import annotations

import itertools
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ieee1905.core import CMDU, CMDUHeader, MessageType
from ieee1905.core.cmdu import CMDUParseError
from ieee1905.core.tlv import encode_typed
from ieee1905.io.backend import ETHERTYPE_IEEE1905, get_default_backend
from ieee1905.io.ethernet import EthernetFrame, EthernetParseError

#: Standard IEEE 1905 multicast destination.
DST_MULTICAST = bytes.fromhex("0180c2000013")

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class EmulatorContext:
    """Per-instance state for a running emulator."""

    interface: str
    al_mac: bytes
    radio_id: bytes
    bssid: bytes
    ssid: bytes = b"emulator-mesh"
    stop_event: threading.Event = field(default_factory=threading.Event)
    _mid_counter: Any = field(default_factory=lambda: itertools.count(1))

    def next_mid(self) -> int:
        value: int = next(self._mid_counter)
        return value & 0xFFFF


def build_cmdu(
    *,
    message_type: int,
    message_id: int,
    typed_tlvs: list[object],
) -> bytes:
    """Build CMDU bytes for the given message-type and list of typed TLVs."""
    cmdu = CMDU(
        header=CMDUHeader(message_type=message_type, message_id=message_id),
        tlvs=[encode_typed(t) for t in typed_tlvs],  # type: ignore[arg-type]
    )
    return cmdu.to_bytes()


def send_frame(
    ctx: EmulatorContext,
    cmdu_bytes: bytes,
    *,
    dst: bytes = DST_MULTICAST,
) -> None:
    """Wrap ``cmdu_bytes`` in an Ethernet II frame and inject it on the wire."""
    frame = EthernetFrame(
        dst=dst,
        src=ctx.al_mac,
        ethertype=ETHERTYPE_IEEE1905,
        payload=cmdu_bytes,
    ).to_bytes()
    backend = get_default_backend()
    with backend.open_live(ctx.interface, bpf_filter=None, promiscuous=False) as live:
        live.inject(frame)


def run_sniff_loop(
    ctx: EmulatorContext,
    on_cmdu: Callable[[bytes, CMDU], None],
) -> None:
    """Blocking sniff loop: hand each well-formed CMDU to ``on_cmdu``.

    Frames whose Ethernet header fails to parse, frames with a non-1905
    EtherType, and CMDUs that fail to decode are silently skipped (with
    a debug-level log line so they don't disappear entirely).
    """
    backend = get_default_backend()

    def _on_frame(raw: bytes, _ts: float) -> None:
        if ctx.stop_event.is_set():
            return
        try:
            eth = EthernetFrame.parse(raw)
        except EthernetParseError:
            return
        if eth.ethertype != ETHERTYPE_IEEE1905:
            return
        if eth.src == ctx.al_mac:
            # Ignore our own injected frames echoed back on the loopback / hub.
            return
        try:
            cmdu = CMDU.from_bytes(eth.payload)
        except CMDUParseError as exc:
            logger.debug("dropped malformed CMDU from %s: %s", eth.src.hex(":"), exc)
            return
        on_cmdu(eth.src, cmdu)

    with backend.open_live(ctx.interface, promiscuous=True) as live:
        live.sniff(_on_frame, stop_event=ctx.stop_event)


def describe_message(message_type: int) -> str:
    return MessageType.describe(message_type)
