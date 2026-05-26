# SPDX-License-Identifier: GPL-2.0-or-later
"""Declarative conformance scenarios for the Multi-AP DUT emulators.

A scenario is a YAML document describing:

- the target emulator (``agent`` or ``controller``) and its setup,
- a sequence of ``steps`` that either inject a CMDU into the target or
  invoke a public API method on it,
- one or more ``expect`` blocks asserting which CMDUs the target
  emitted, the headers of those CMDUs (message_type, message_id), the
  TLV types they contain, and the target's post-step internal state.

The runner is intentionally tiny — it's a thin shim over the
existing ``send_frame`` mock pattern used in ``tests/test_emulator.py``.
Authoring a new scenario is one YAML file plus zero Python code, which
keeps the conformance corpus readable and PR-reviewable.

See ``tests/scenarios/`` for the bundled scenario library and
``tests/test_conformance.py`` for the parametrised pytest harness.
"""

from ieee1905.conformance.runner import (
    ScenarioFailure,
    ScenarioResult,
    load_scenario,
    run_scenario,
)

__all__ = ["ScenarioFailure", "ScenarioResult", "load_scenario", "run_scenario"]
