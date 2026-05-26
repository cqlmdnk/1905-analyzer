# SPDX-License-Identifier: GPL-2.0-or-later
"""In-process live test: FakeController <-> FakeAgent full handshake.

Runs both emulators in their own threads with their real periodic
heartbeats firing. ``send_frame`` on each side is patched to shuttle
the on-wire bytes straight into the other side's ``_on_cmdu``, and
every shuttled frame is also written to a pcap so the run can be
inspected after the fact.

Usage::

    python scripts/live_handshake.py [seconds] [pcap-path]

Defaults: 6 seconds, /tmp/live_handshake.pcap.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from ieee1905.core import CMDU, MessageType
from ieee1905.core.cmdu import CMDUParseError
from ieee1905.emulator._common import EmulatorContext
from ieee1905.emulator.agent import FakeAgent
from ieee1905.emulator.controller import FakeController

AGENT_MAC = b"\x02\x00\xde\xad\xbe\xef"
AGENT_RADIO = b"\x02\x00\xde\xad\xbe\x01"
AGENT_BSSID = b"\x02\x00\xde\xad\xbe\x02"
CTL_MAC = b"\x02\x00\xcc\xcc\xcc\x01"
CTL_RADIO = b"\x02\x00\xcc\xcc\xcc\x02"
CTL_BSSID = b"\x02\x00\xcc\xcc\xcc\x03"
ETH_BROADCAST_AL = b"\x01\x80\xc2\x00\x00\x13"


def main(duration: float, pcap_path: Path) -> int:
    agent = FakeAgent(
        interface="lo0",
        al_mac=AGENT_MAC,
        radio_id=AGENT_RADIO,
        bssid=AGENT_BSSID,
        topology_interval_s=1.0,
        autoconfig_interval_s=2.0,
        metrics_interval_s=3.0,
    )
    ctl = FakeController(
        interface="lo0",
        al_mac=CTL_MAC,
        radio_id=CTL_RADIO,
        bssid=CTL_BSSID,
        ssid=b"live-mesh",
        network_key=b"live-mesh-psk-9482",
        topology_interval_s=1.0,
        topology_query_interval_s=2.0,
        metrics_interval_s=2.0,
        link_metric_interval_s=3.0,
    )

    # Both agents share a context that the heartbeat loop uses as its
    # stop_event source and MID counter, but we never open a real socket.
    agent._ctx = EmulatorContext(
        interface="lo0",
        al_mac=AGENT_MAC,
        radio_id=AGENT_RADIO,
        bssid=AGENT_BSSID,
        ssid=agent.ssid,
    )
    ctl._ctx = EmulatorContext(
        interface="lo0",
        al_mac=CTL_MAC,
        radio_id=CTL_RADIO,
        bssid=CTL_BSSID,
        ssid=ctl.ssid,
    )

    frames: list[Ether] = []
    lock = threading.Lock()
    counts: dict[str, int] = {"agent_tx": 0, "ctl_tx": 0, "parse_errors": 0}
    start = time.time()

    def shuttle_factory(label: str, src_mac: bytes, target: object):
        def _send(ctx, cmdu_bytes, *, dst=None):  # type: ignore[no-untyped-def]
            del ctx
            wire_dst = dst or ETH_BROADCAST_AL
            now = time.time() - start
            with lock:
                counts[f"{label}_tx"] += 1
                eth = Ether(src=src_mac, dst=wire_dst, type=0x893A) / Raw(load=cmdu_bytes)
                eth.time = now
                frames.append(eth)
            try:
                cmdu = CMDU.from_bytes(cmdu_bytes)
            except CMDUParseError:
                with lock:
                    counts["parse_errors"] += 1
                return
            # Broadcast (relay) frames are seen by every peer; unicast
            # only by the addressed one.
            if wire_dst in (ETH_BROADCAST_AL, target_mac(target)):
                target._on_cmdu(src_mac, cmdu)  # type: ignore[attr-defined]
        return _send

    def target_mac(target: object) -> bytes:
        return target._ctx.al_mac  # type: ignore[attr-defined]

    with patch(
        "ieee1905.emulator.agent.send_frame",
        side_effect=shuttle_factory("agent", AGENT_MAC, ctl),
    ), patch(
        "ieee1905.emulator.controller.send_frame",
        side_effect=shuttle_factory("ctl", CTL_MAC, agent),
    ):
        agent_thread = threading.Thread(target=agent._heartbeat_loop, daemon=True)
        ctl_thread = threading.Thread(target=ctl._heartbeat_loop, daemon=True)
        agent_thread.start()
        ctl_thread.start()

        time.sleep(duration)

        agent._ctx.stop_event.set()
        ctl._ctx.stop_event.set()
        agent_thread.join(timeout=2.0)
        ctl_thread.join(timeout=2.0)

    # Dump pcap and a per-message-type summary.
    wrpcap(str(pcap_path), frames)
    summary: dict[int, int] = {}
    for fr in frames:
        payload = bytes(fr.payload)
        if len(payload) < 4:
            continue
        mtype = int.from_bytes(payload[2:4], "big")
        summary[mtype] = summary.get(mtype, 0) + 1

    print(f"== Live handshake ({duration:.1f}s) ==")
    print(f"  Frames captured       : {len(frames)}")
    print(f"  Agent TX              : {counts['agent_tx']}")
    print(f"  Controller TX         : {counts['ctl_tx']}")
    print(f"  CMDU parse errors     : {counts['parse_errors']}")
    print(f"  Pcap written          : {pcap_path}")
    print()
    print("== CMDU type breakdown ==")
    for mtype, n in sorted(summary.items()):
        name = MessageType.describe(mtype)
        print(f"  0x{mtype:04x}  {name:48s}  {n}")
    print()
    print("== Agent state ==")
    print(f"  onboarded             : {agent._onboarded}")
    print(f"  bss credentials       : {len(agent._bss_credentials)}")
    for cred in agent._bss_credentials:
        print(
            f"    ssid={cred.ssid!r}  auth=0x{cred.auth_type:04x}"
            f"  encr=0x{cred.encr_type:04x}  bssid={cred.mac_address.hex(':')}"
        )
    print()
    print("== Controller view ==")
    for mac, st in ctl._agents.items():
        radio = st.radio_id.hex(":") if st.radio_id else "?"
        print(
            f"  agent={mac.hex(':')}  onboarded={st.onboarded}  radio={radio}"
            f"  rf_band={st.rf_band}"
        )

    return 0 if agent._onboarded else 2


if __name__ == "__main__":
    secs = float(sys.argv[1]) if len(sys.argv) > 1 else 6.0
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("/tmp/live_handshake.pcap")
    raise SystemExit(main(secs, out))
