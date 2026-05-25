# SPDX-License-Identifier: GPL-2.0-or-later
"""Minimal Multi-AP **controller** emulator.

Behavior:

- Sends Topology Discovery every ``topology_interval_s`` (default 5 s).
- Replies to inbound AP-Autoconfig Search messages with an AP-Autoconfig
  Response carrying SupportedRole=Registrar, SupportedFreqBand mirroring
  the agent's request, and SupportedService = Multi-AP Controller.
- Replies to inbound Topology Notification by issuing a Topology Query
  back to the originator (chains the inventory step).
- Replies to inbound AP Capability Report with a (no-op) ACK.

State machine is intentionally tiny: the goal is to give a real agent
*something to talk to* during local interop testing.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

from ieee1905.core import CMDU, MessageType
from ieee1905.core.tlvs import (
    AlMacAddress,
    AutoconfigFreqBand,
    MacAddress,
    SupportedFreqBand,
    SupportedRole,
    SupportedService,
)
from ieee1905.emulator._common import (
    EmulatorContext,
    build_cmdu,
    run_sniff_loop,
    send_frame,
)

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class FakeController:
    """A minimal EasyMesh controller that talks on ``interface``."""

    interface: str
    al_mac: bytes
    radio_id: bytes
    bssid: bytes
    ssid: bytes = b"emulator-mesh"
    topology_interval_s: float = 5.0

    _ctx: EmulatorContext | None = None
    _sniff_thread: threading.Thread | None = None
    _heartbeat_thread: threading.Thread | None = None

    def start(self) -> None:
        self._ctx = EmulatorContext(
            interface=self.interface,
            al_mac=self.al_mac,
            radio_id=self.radio_id,
            bssid=self.bssid,
            ssid=self.ssid,
        )
        self._sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._sniff_thread.start()
        self._heartbeat_thread.start()
        logger.info(
            "FakeController started on %s (AL=%s)", self.interface, self.al_mac.hex(":")
        )

    def stop(self) -> None:
        if self._ctx is not None:
            self._ctx.stop_event.set()
        for t in (self._sniff_thread, self._heartbeat_thread):
            if t is not None:
                t.join(timeout=2.0)
        if self._ctx is not None:
            self._ctx.close_tx_session()
        logger.info("FakeController stopped")

    def _heartbeat_loop(self) -> None:
        assert self._ctx is not None
        next_send = time.monotonic()
        while not self._ctx.stop_event.is_set():
            now = time.monotonic()
            if now >= next_send:
                self._send_topology_discovery()
                next_send = now + self.topology_interval_s
            self._ctx.stop_event.wait(timeout=0.5)

    def _send_topology_discovery(self) -> None:
        assert self._ctx is not None
        # IEEE 1905.1 §6.3.1: Topology Discovery requires AL MAC + the MAC
        # of the interface the frame is leaving. SupportedService is a
        # Multi-AP R1+ extension carried on the same message so the peer
        # learns we're a controller in one round-trip.
        cmdu_bytes = build_cmdu(
            message_type=MessageType.TOPOLOGY_DISCOVERY.value,
            message_id=self._ctx.next_mid(),
            typed_tlvs=[
                AlMacAddress(al_mac=self.al_mac),
                MacAddress(mac=self.radio_id),
                SupportedService(services=[0x00]),  # Multi-AP Controller
            ],
        )
        try:
            send_frame(self._ctx, cmdu_bytes)
        except Exception as exc:  # noqa: BLE001
            logger.warning("controller topology discovery send failed: %s", exc)

    def _sniff_loop(self) -> None:
        assert self._ctx is not None
        run_sniff_loop(self._ctx, self._on_cmdu)

    def _on_cmdu(self, src: bytes, cmdu: CMDU) -> None:
        mtype = cmdu.header.message_type
        if mtype == MessageType.AP_AUTOCONFIGURATION_SEARCH.value:
            self._reply_autoconfig_response(src, cmdu)
        elif mtype == MessageType.TOPOLOGY_NOTIFICATION.value:
            # Follow up by asking the source for the full topology.
            self._send_topology_query(src)
        elif mtype == MessageType.EM_AP_CAPABILITY_REPORT.value:
            self._send_ack(src, cmdu)

    def _reply_autoconfig_response(self, dst: bytes, query: CMDU) -> None:
        assert self._ctx is not None
        requested_band = 0x01
        for raw in query.tlvs:
            if raw.tlv_type == AutoconfigFreqBand.TLV_TYPE and raw.payload:
                requested_band = raw.payload[0]
                break

        cmdu_bytes = build_cmdu(
            message_type=MessageType.AP_AUTOCONFIGURATION_RESPONSE.value,
            message_id=query.header.message_id,
            typed_tlvs=[
                SupportedRole(role=0x00),  # Registrar
                SupportedFreqBand(band=requested_band),
                SupportedService(services=[0x00]),  # Multi-AP Controller
            ],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    def _send_topology_query(self, dst: bytes) -> None:
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.TOPOLOGY_QUERY.value,
            message_id=self._ctx.next_mid(),
            typed_tlvs=[],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    def _send_ack(self, dst: bytes, original: CMDU) -> None:
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.EM_ACK.value,
            message_id=original.header.message_id,
            typed_tlvs=[],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)
