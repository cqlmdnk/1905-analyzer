# SPDX-License-Identifier: GPL-2.0-or-later
"""Minimal Multi-AP **agent** emulator.

Behavior:

- Sends a Topology Discovery (1905.1) every ``topology_interval_s`` (default 5 s).
- Sends an AP-Autoconfig Search every ``autoconfig_interval_s`` (default
  30 s) until a Response with a matching frequency band is observed.
- Replies to inbound Topology Query, AP-Autoconfig Renew, AP Capability
  Query and AP Metrics Query messages with appropriate canned content.

The state machine here is intentionally minimal — interop testing needs a
peer that *responds*, not full controller-style mesh management.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

from ieee1905.core import CMDU, MessageType
from ieee1905.core.tlvs import (
    AlMacAddress,
    ApCapability,
    ApMetrics,
    ApOperationalBss,
    ApRadioBasicCapabilities,
    AutoconfigFreqBand,
    DeviceInformation,
    LocalInterface,
    OperatingClassCapability,
    OperationalBss,
    OperationalBssRadio,
    SearchedRole,
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
class FakeAgent:
    """A minimal EasyMesh agent that talks on ``interface``."""

    interface: str
    al_mac: bytes
    radio_id: bytes
    bssid: bytes
    ssid: bytes = b"emulator-mesh"
    topology_interval_s: float = 5.0
    autoconfig_interval_s: float = 30.0
    freq_band: int = 0x01  # 0=2.4GHz, 1=5GHz, 2=60GHz

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
        logger.info("FakeAgent started on %s (AL=%s)", self.interface, self.al_mac.hex(":"))

    def stop(self) -> None:
        if self._ctx is not None:
            self._ctx.stop_event.set()
        for t in (self._sniff_thread, self._heartbeat_thread):
            if t is not None:
                t.join(timeout=2.0)
        logger.info("FakeAgent stopped")

    # ---- periodic emissions -------------------------------------------------

    def _heartbeat_loop(self) -> None:
        assert self._ctx is not None
        next_topology = time.monotonic()
        next_autoconfig = time.monotonic()
        while not self._ctx.stop_event.is_set():
            now = time.monotonic()
            if now >= next_topology:
                self._send_topology_discovery()
                next_topology = now + self.topology_interval_s
            if now >= next_autoconfig:
                self._send_autoconfig_search()
                next_autoconfig = now + self.autoconfig_interval_s
            self._ctx.stop_event.wait(timeout=0.5)

    def _send_topology_discovery(self) -> None:
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.TOPOLOGY_DISCOVERY.value,
            message_id=self._ctx.next_mid(),
            typed_tlvs=[
                AlMacAddress(al_mac=self.al_mac),
            ],
        )
        try:
            send_frame(self._ctx, cmdu_bytes)
        except Exception as exc:  # noqa: BLE001
            logger.warning("topology discovery send failed: %s", exc)

    def _send_autoconfig_search(self) -> None:
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.AP_AUTOCONFIGURATION_SEARCH.value,
            message_id=self._ctx.next_mid(),
            typed_tlvs=[
                AlMacAddress(al_mac=self.al_mac),
                SearchedRole(role=0x00),
                AutoconfigFreqBand(band=self.freq_band),
                SupportedService(services=[0x01]),  # Multi-AP Agent
            ],
        )
        try:
            send_frame(self._ctx, cmdu_bytes)
        except Exception as exc:  # noqa: BLE001
            logger.warning("autoconfig search send failed: %s", exc)

    # ---- inbound message handling ------------------------------------------

    def _sniff_loop(self) -> None:
        assert self._ctx is not None
        run_sniff_loop(self._ctx, self._on_cmdu)

    def _on_cmdu(self, src: bytes, cmdu: CMDU) -> None:
        mtype = cmdu.header.message_type
        if mtype == MessageType.TOPOLOGY_QUERY.value:
            self._reply_topology_response(src, cmdu)
        elif mtype == MessageType.AP_AUTOCONFIGURATION_RENEW.value:
            # Re-trigger our autoconfig search.
            self._send_autoconfig_search()
        elif mtype == MessageType.EM_AP_CAPABILITY_QUERY.value:
            self._reply_ap_capability_report(src, cmdu)
        elif mtype == MessageType.EM_AP_METRICS_QUERY.value:
            self._reply_ap_metrics_response(src, cmdu)

    def _reply_topology_response(self, dst: bytes, query: CMDU) -> None:
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.TOPOLOGY_RESPONSE.value,
            message_id=query.header.message_id,
            typed_tlvs=[
                AlMacAddress(al_mac=self.al_mac),
                DeviceInformation(
                    al_mac=self.al_mac,
                    interfaces=[LocalInterface(mac=self.radio_id, media_type=0x0100)],
                ),
            ],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    def _reply_ap_capability_report(self, dst: bytes, query: CMDU) -> None:
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.EM_AP_CAPABILITY_REPORT.value,
            message_id=query.header.message_id,
            typed_tlvs=[
                ApCapability(flags=0xC0),
                ApRadioBasicCapabilities(
                    radio_id=self.radio_id,
                    max_bsses_supported=4,
                    operating_classes=[
                        OperatingClassCapability(
                            op_class=81, max_tx_eirp_dbm=23, non_operable_channels=[]
                        ),
                    ],
                ),
                ApOperationalBss(
                    radios=[
                        OperationalBssRadio(
                            radio_id=self.radio_id,
                            bsses=[OperationalBss(bssid=self.bssid, ssid=self.ssid)],
                        )
                    ]
                ),
                SupportedFreqBand(band=self.freq_band),
                SupportedRole(role=0x00),
            ],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)

    def _reply_ap_metrics_response(self, dst: bytes, query: CMDU) -> None:
        assert self._ctx is not None
        cmdu_bytes = build_cmdu(
            message_type=MessageType.EM_AP_METRICS_RESPONSE.value,
            message_id=query.header.message_id,
            typed_tlvs=[
                ApMetrics(
                    bssid=self.bssid,
                    channel_utilization=20,
                    num_associated_stas=0,
                    esp_info=b"\x80\x00\x10\x20",
                ),
            ],
        )
        send_frame(self._ctx, cmdu_bytes, dst=dst)
