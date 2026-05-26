# SPDX-License-Identifier: GPL-2.0-or-later
"""DUT emulators: a minimal fake Multi-AP controller and fake agent.

These are not full implementations of the EasyMesh state machines.
They cover the baseline message exchanges (Topology Discovery,
AP-Autoconfig search/response, AP-Autoconfig WSC envelope, AP
Capability query/report) so the rest of the suite has a peer to
exchange frames with during interop testing — even when no real
hardware is on the bench.

Run them via the CLI::

    ieee1905 emulator agent      <iface>
    ieee1905 emulator controller <iface>
"""

from ieee1905.emulator.agent import FakeAgent, RadioConfig
from ieee1905.emulator.controller import FakeController

__all__ = ["FakeAgent", "FakeController", "RadioConfig"]
