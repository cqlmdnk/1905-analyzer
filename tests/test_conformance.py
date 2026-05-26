# SPDX-License-Identifier: GPL-2.0-or-later
"""Parametrised pytest harness that runs every scenario in tests/scenarios/.

The scenarios live as YAML next to this file so adding a new conformance
check is just dropping a ``.yaml`` next to the existing ones — no
Python edit required.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ieee1905.conformance import load_scenario, run_scenario

SCENARIOS_DIR = Path(__file__).parent / "scenarios"


def _scenario_ids() -> list[str]:
    return sorted(p.name for p in SCENARIOS_DIR.glob("*.yaml"))


@pytest.mark.parametrize("scenario_file", _scenario_ids())
def test_conformance_scenario(scenario_file: str) -> None:
    path = SCENARIOS_DIR / scenario_file
    doc = load_scenario(path)
    result = run_scenario(doc)
    assert result.name == doc["name"]
    assert result.steps_run == len(doc["steps"])
