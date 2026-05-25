# SPDX-License-Identifier: GPL-2.0-or-later
"""PCAP read / write helpers built on the Scapy backend.

These are thin convenience wrappers — the underlying logic is in
:mod:`ieee1905.io.backend`. They exist so callers don't need to know
which backend is active just to load a file.
"""

from __future__ import annotations

from collections.abc import Iterator
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
