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
    """Per-instance state for a running emulator.

    Owns a long-lived transmit session — opening a new L2 socket for
    every emitted frame is both slow on macOS BPF and noisy in logs
    (each ``open_live`` prints an INFO line). The session is created
    lazily on the first ``send_frame()`` call and closed via
    :meth:`close_tx_session` from the emulator's ``stop()``.
    """

    interface: str
    al_mac: bytes
    radio_id: bytes
    bssid: bytes
    ssid: bytes = b"emulator-mesh"
    stop_event: threading.Event = field(default_factory=threading.Event)
    _mid_counter: Any = field(default_factory=lambda: itertools.count(1))
    _tx_live: Any = None
    _tx_cm: Any = None

    def next_mid(self) -> int:
        value: int = next(self._mid_counter)
        return value & 0xFFFF

    def open_tx_session(self) -> Any:
        """Open (if needed) and return the cached transmit session."""
        if self._tx_live is None:
            backend = get_default_backend()
            cm = backend.open_live(self.interface, bpf_filter=None, promiscuous=False)
            self._tx_cm = cm
            self._tx_live = cm.__enter__()
        return self._tx_live

    def close_tx_session(self) -> None:
        if self._tx_cm is not None:
            try:
                self._tx_cm.__exit__(None, None, None)
            except Exception as exc:  # noqa: BLE001
                logger.debug("error closing tx session: %s", exc)
            finally:
                self._tx_cm = None
                self._tx_live = None


# IEEE 1905.1-2013 §6.2.2 + Table 6-3: these CMDU types are sent as
# relay-multicast and must have the relay_indicator bit set in the header.
# Strict header validators reject frames whose relay bit does not match
# the spec for the given message type.
# Topology Discovery (0x0000) is 1-hop only (§6.3.1) and must NOT have
# the relay bit set, even though its destination is the multicast AL MAC.
_RELAY_MULTICAST_TYPES: frozenset[int] = frozenset({
    0x0001,  # TOPOLOGY_NOTIFICATION
    0x0007,  # AP_AUTOCONFIGURATION_SEARCH
    0x000A,  # AP_AUTOCONFIGURATION_RENEW
})


def build_cmdu(
    *,
    message_type: int,
    message_id: int,
    typed_tlvs: list[object],
    relay: bool | None = None,
) -> bytes:
    """Build CMDU bytes for the given message-type and list of typed TLVs.

    ``relay`` defaults to True for IEEE 1905.1 relay-multicast message types
    and False otherwise. Pass an explicit value to override.
    """
    if relay is None:
        relay = message_type in _RELAY_MULTICAST_TYPES
    cmdu = CMDU(
        header=CMDUHeader(
            message_type=message_type,
            message_id=message_id,
            relay_indicator=relay,
        ),
        tlvs=[encode_typed(t) for t in typed_tlvs],  # type: ignore[arg-type]
    )
    return cmdu.to_bytes()


def send_frame(
    ctx: EmulatorContext,
    cmdu_bytes: bytes,
    *,
    dst: bytes = DST_MULTICAST,
) -> None:
    """Wrap ``cmdu_bytes`` in an Ethernet II frame and inject it on the wire.

    Uses ``ctx``'s cached transmit session (opens it on the first call).
    The session lives until the emulator's ``stop()`` closes it via
    :meth:`EmulatorContext.close_tx_session`.
    """
    frame = EthernetFrame(
        dst=dst,
        src=ctx.al_mac,
        ethertype=ETHERTYPE_IEEE1905,
        payload=cmdu_bytes,
    ).to_bytes()
    live = ctx.open_tx_session()
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
