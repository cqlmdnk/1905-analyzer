# SPDX-License-Identifier: GPL-2.0-or-later
"""Capture/inject backend abstraction.

Phase 0: single Scapy-backed implementation that works on Linux,
macOS, and Windows (with Npcap). Phase 4 will add a libpcap-direct
backend for higher throughput in bridge mode.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from scapy.supersocket import SuperSocket

logger = logging.getLogger(__name__)

#: IEEE 1905.1 EtherType.
ETHERTYPE_IEEE1905 = 0x893A

#: Default BPF filter — capture only 1905 frames.
DEFAULT_FILTER_1905_ONLY = f"ether proto 0x{ETHERTYPE_IEEE1905:04x}"


FrameCallback = Callable[[bytes, float], None]
"""Callback invoked per captured frame: ``(raw_bytes, epoch_timestamp)``."""


class CaptureBackend(Protocol):
    """Minimal capture/inject API expected from any backend implementation."""

    name: str

    def open_live(
        self,
        interface: str,
        *,
        bpf_filter: str | None = None,
        promiscuous: bool = True,
        snaplen: int = 65535,
        timeout_ms: int = 100,
    ) -> AbstractContextManager[LiveHandle]:
        ...

    def open_offline(self, path: str) -> Iterator[tuple[bytes, float]]:
        ...


class LiveHandle(Protocol):
    """Active capture/inject session."""

    def sniff(self, on_frame: FrameCallback, *, stop_event: object | None = None) -> None:
        ...

    def inject(self, frame: bytes) -> None:
        ...

    def close(self) -> None:
        ...


class ScapyBackend:
    """Scapy-based implementation. Cross-platform but slower than raw libpcap."""

    name = "scapy"

    def open_live(
        self,
        interface: str,
        *,
        bpf_filter: str | None = None,
        promiscuous: bool = True,
        snaplen: int = 65535,
        timeout_ms: int = 100,
    ) -> AbstractContextManager[LiveHandle]:
        return _ScapyLiveSession(
            interface=interface,
            bpf_filter=bpf_filter,
            promiscuous=promiscuous,
            snaplen=snaplen,
            timeout_ms=timeout_ms,
        )

    def open_offline(self, path: str) -> Iterator[tuple[bytes, float]]:
        from scapy.utils import PcapReader

        with PcapReader(path) as reader:
            for pkt in reader:
                yield bytes(pkt), float(pkt.time)


class _ScapyLiveSession(AbstractContextManager["_ScapyLiveSession"]):
    def __init__(
        self,
        *,
        interface: str,
        bpf_filter: str | None,
        promiscuous: bool,
        snaplen: int,
        timeout_ms: int,
    ) -> None:
        self._interface = interface
        self._bpf_filter = bpf_filter
        self._promiscuous = promiscuous
        self._snaplen = snaplen
        self._timeout_ms = timeout_ms
        self._socket: SuperSocket | None = None

    def __enter__(self) -> _ScapyLiveSession:
        from scapy.config import conf

        l2_socket_cls: Any = conf.L2socket
        self._socket = l2_socket_cls(
            iface=self._interface,
            filter=self._bpf_filter,
            promisc=self._promiscuous,
        )
        logger.info("opened live capture on %s", self._interface)
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def sniff(self, on_frame: FrameCallback, *, stop_event: object | None = None) -> None:
        assert self._socket is not None, "session not opened"
        try:
            while True:
                if stop_event is not None and getattr(stop_event, "is_set", lambda: False)():
                    break
                pkt = self._socket.recv()
                if pkt is None:
                    continue
                on_frame(bytes(pkt), float(getattr(pkt, "time", 0.0) or 0.0))
        except KeyboardInterrupt:
            logger.info("capture interrupted by user")

    def inject(self, frame: bytes) -> None:
        from scapy.packet import Raw

        assert self._socket is not None, "session not opened"
        self._socket.send(Raw(load=frame))

    def close(self) -> None:
        if self._socket is not None:
            try:
                self._socket.close()
            finally:
                self._socket = None


_default_backend: CaptureBackend | None = None


def get_default_backend() -> CaptureBackend:
    """Return the active backend instance (singleton)."""
    global _default_backend
    if _default_backend is None:
        _default_backend = ScapyBackend()
    return _default_backend
