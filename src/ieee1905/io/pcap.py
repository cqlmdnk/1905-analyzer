# SPDX-License-Identifier: GPL-2.0-or-later
"""PCAP read / write helpers built on the Scapy backend.

These are thin convenience wrappers — the underlying logic is in
:mod:`ieee1905.io.backend`. They exist so callers don't need to know
which backend is active just to load a file.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from ieee1905.core import CMDU
from ieee1905.core.cmdu import CMDUParseError
from ieee1905.io.backend import ETHERTYPE_IEEE1905, get_default_backend
from ieee1905.io.ethernet import EthernetFrame, EthernetParseError


@dataclass(slots=True)
class CapturedFrame:
    """One frame from a capture / PCAP file."""

    timestamp: float
    raw: bytes
    src_mac: bytes
    dst_mac: bytes
    ethertype: int
    cmdu: CMDU | None  # populated only for IEEE 1905 frames that parsed cleanly
    decode_error: str | None  # human-readable reason when cmdu is None


def iter_pcap(path: str, *, ieee1905_only: bool = True) -> Iterator[CapturedFrame]:
    """Yield :class:`CapturedFrame` records for every frame in ``path``.

    ``ieee1905_only=True`` (default) skips non-1905 traffic; non-1905
    frames in PCAPs are common (e.g. bridged ARP, mDNS) and usually
    aren't what the analyzer wants to show.
    """
    backend = get_default_backend()
    for raw, ts in backend.open_offline(path):
        try:
            eth = EthernetFrame.parse(raw)
        except EthernetParseError as exc:
            if ieee1905_only:
                continue
            yield CapturedFrame(
                timestamp=ts,
                raw=raw,
                src_mac=b"",
                dst_mac=b"",
                ethertype=0,
                cmdu=None,
                decode_error=f"ethernet parse: {exc}",
            )
            continue

        if ieee1905_only and eth.ethertype != ETHERTYPE_IEEE1905:
            continue

        cmdu: CMDU | None = None
        err: str | None = None
        if eth.ethertype == ETHERTYPE_IEEE1905:
            try:
                cmdu = CMDU.from_bytes(eth.payload)
            except CMDUParseError as exc:
                err = f"cmdu parse: {exc}"

        yield CapturedFrame(
            timestamp=ts,
            raw=raw,
            src_mac=eth.src,
            dst_mac=eth.dst,
            ethertype=eth.ethertype,
            cmdu=cmdu,
            decode_error=err,
        )


def summarize_pcap(path: str) -> dict[str, int]:
    """Return a tiny histogram: count of frames per message type label."""
    from ieee1905.core import MessageType

    counts: dict[str, int] = {}
    for frame in iter_pcap(path):
        if frame.cmdu is None:
            counts["<malformed>"] = counts.get("<malformed>", 0) + 1
            continue
        label = MessageType.describe(frame.cmdu.header.message_type)
        counts[label] = counts.get(label, 0) + 1
    return counts


@dataclass(slots=True)
class ReplayStats:
    """Counters returned from a replay session."""

    total_frames: int = 0
    injected: int = 0
    skipped_non_1905: int = 0
    skipped_malformed: int = 0
    duration_s: float = 0.0


def replay_pcap(
    path: str,
    interface: str,
    *,
    speed: float = 1.0,
    loop: bool = False,
    ieee1905_only: bool = True,
    stop_event: threading.Event | None = None,
    on_frame: Callable[[bytes, float], None] | None = None,
) -> ReplayStats:
    """Replay frames from ``path`` onto ``interface``.

    ``speed`` scales the inter-frame delay derived from the original
    timestamps:

    - ``speed > 0`` preserves timing scaled by ``1/speed`` (e.g. ``2.0``
      = twice as fast, ``0.5`` = half-speed).
    - ``speed = 0`` (or negative) sends frames back-to-back with no
      sleep (as fast as the wire / kernel allows).

    When ``loop`` is True, the PCAP is replayed indefinitely until
    ``stop_event`` is set. ``ieee1905_only`` filters out non-1905 traffic
    before injecting. ``on_frame(raw, ts)`` is invoked for every
    *injected* frame, useful for live progress reporting.

    Requires raw socket privileges on ``interface`` — see ``ieee1905
    privileges`` for the per-platform notes.
    """
    backend = get_default_backend()
    stats = ReplayStats()
    started = time.monotonic()

    with backend.open_live(interface, bpf_filter=None, promiscuous=False) as live:
        while True:
            prev_ts: float | None = None
            for raw, ts in backend.open_offline(path):
                if stop_event is not None and stop_event.is_set():
                    stats.duration_s = time.monotonic() - started
                    return stats

                stats.total_frames += 1

                if ieee1905_only:
                    try:
                        eth = EthernetFrame.parse(raw)
                    except EthernetParseError:
                        stats.skipped_malformed += 1
                        prev_ts = ts
                        continue
                    if eth.ethertype != ETHERTYPE_IEEE1905:
                        stats.skipped_non_1905 += 1
                        prev_ts = ts
                        continue

                if prev_ts is not None and speed > 0:
                    delta = (ts - prev_ts) / speed
                    if delta > 0:
                        if stop_event is not None:
                            stop_event.wait(timeout=delta)
                            if stop_event.is_set():
                                stats.duration_s = time.monotonic() - started
                                return stats
                        else:
                            time.sleep(delta)

                live.inject(raw)
                stats.injected += 1
                if on_frame is not None:
                    on_frame(raw, ts)
                prev_ts = ts

            if not loop:
                break

    stats.duration_s = time.monotonic() - started
    return stats
