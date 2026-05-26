# SPDX-License-Identifier: GPL-2.0-or-later
"""Conformance scenario loader + executor.

YAML scenario schema (all fields except ``name`` / ``steps`` optional)::

    name: agent_topology_query_response
    description: free-form text
    target: agent | controller            # default: agent
    setup:
      al_mac:  02:00:de:ad:be:ef
      radio_id: 02:00:de:ad:be:01
      bssid:   02:00:de:ad:be:02
      ssid: emulator-mesh                 # str, decoded as utf-8
      freq_band: 0                        # 0=2.4G / 1=5G / 2=60G (agent only)
      network_key: emulator-mesh-psk      # controller only
    steps:
      - inject:                           # send a CMDU into the target
          src_mac: 02:00:cc:cc:cc:01
          cmdu_hex: "0000000200420080000000"
      - call:                             # invoke a public method
          method: associate_client
          args: [aabbccddeeff]
      - set_state:                        # poke an internal field
          _onboarded: true
      - expect:                           # assert what happened
          emit_count: 1                   # # of frames since last expect
          emits:
            - message_type: TOPOLOGY_RESPONSE
              message_id: 0x0042          # optional
              tlv_types: [0x03, 0x80]     # subset assertion
              not_tlv_types: [0x01]       # negative subset
          state:
            _onboarded: true              # equality check on attribute

The runner does not synthesise WSC handshakes — the cryptographic
state machine is exercised in ``tests/test_wsc.py`` and the
in-process end-to-end tests in ``tests/test_emulator.py``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import patch

import yaml

from ieee1905.core import CMDU, MessageType
from ieee1905.core.cmdu import CMDUParseError
from ieee1905.emulator._common import EmulatorContext
from ieee1905.emulator.agent import FakeAgent
from ieee1905.emulator.controller import FakeController


class ScenarioFailure(AssertionError):  # noqa: N818  intentional: this is the spec-name shape
    """One of a scenario's expectations did not hold."""


@dataclass(slots=True)
class ScenarioResult:
    name: str
    target_role: str
    steps_run: int
    frames_emitted: list[bytes] = field(default_factory=list)


_HEX_PAIR = re.compile(r"[0-9a-fA-F]{2}")


def _mac(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    # Accept "aabbccddeeff" or "aa:bb:cc:dd:ee:ff" or "aa-bb-..." forms.
    clean = value.replace(":", "").replace("-", "").replace(" ", "")
    if len(clean) != 12 or not _HEX_PAIR.findall(clean):
        raise ValueError(f"invalid MAC string: {value!r}")
    return bytes.fromhex(clean)


def _hex(value: str) -> bytes:
    return bytes.fromhex(value.replace(" ", "").replace(":", ""))


def _resolve_msg_type(value: int | str) -> int:
    """Accept either a hex int (``0x0002``) or a ``MessageType`` enum name."""
    if isinstance(value, int):
        return value
    try:
        return int(MessageType[value])
    except KeyError as exc:
        raise ValueError(f"unknown MessageType: {value}") from exc


def load_scenario(path: str | Path) -> dict[str, Any]:
    """Parse a scenario YAML and return its dict form (no semantic validation)."""
    with open(path, encoding="utf-8") as fp:
        doc = yaml.safe_load(fp)
    if not isinstance(doc, dict) or "name" not in doc or "steps" not in doc:
        raise ValueError(f"{path}: scenario must have at least 'name' and 'steps'")
    return doc


def _build_target(doc: dict[str, Any]) -> FakeAgent | FakeController:
    role = doc.get("target", "agent")
    setup = doc.get("setup", {})
    al_mac = _mac(setup.get("al_mac", "02:00:de:ad:be:ef"))
    radio_id = _mac(setup.get("radio_id", "02:00:de:ad:be:01"))
    bssid = _mac(setup.get("bssid", "02:00:de:ad:be:02"))
    ssid = setup.get("ssid", "emulator-mesh").encode("utf-8")
    if role == "agent":
        target = FakeAgent(
            interface="lo0",
            al_mac=al_mac,
            radio_id=radio_id,
            bssid=bssid,
            ssid=ssid,
            freq_band=int(setup.get("freq_band", 0x01)),
        )
    elif role == "controller":
        target = FakeController(
            interface="lo0",
            al_mac=al_mac,
            radio_id=radio_id,
            bssid=bssid,
            ssid=ssid,
            network_key=setup.get("network_key", "controller-mesh-psk").encode("utf-8"),
        )
    else:
        raise ValueError(f"target must be 'agent' or 'controller', got {role!r}")
    target._ctx = EmulatorContext(
        interface="lo0", al_mac=al_mac, radio_id=radio_id, bssid=bssid, ssid=ssid
    )
    return target


def _check_emits(emitted: list[CMDU], expectations: list[dict[str, Any]]) -> None:
    """Walk the expectation list and assert each one against the matching emit."""
    if len(emitted) < len(expectations):
        raise ScenarioFailure(
            f"expected at least {len(expectations)} emits, got {len(emitted)}"
        )
    for idx, want in enumerate(expectations):
        got = emitted[idx]
        if "message_type" in want:
            want_mt = _resolve_msg_type(want["message_type"])
            if got.header.message_type != want_mt:
                raise ScenarioFailure(
                    f"emit[{idx}] message_type=0x{got.header.message_type:04x} "
                    f"!= expected 0x{want_mt:04x}"
                )
        if "message_id" in want and got.header.message_id != int(want["message_id"]):
            raise ScenarioFailure(
                f"emit[{idx}] message_id=0x{got.header.message_id:04x} "
                f"!= expected 0x{int(want['message_id']):04x}"
            )
        seen = {t.tlv_type for t in got.tlvs}
        for needed in want.get("tlv_types", []):
            if int(needed) not in seen:
                raise ScenarioFailure(
                    f"emit[{idx}] missing TLV 0x{int(needed):02x} (seen: "
                    f"{sorted(f'0x{t:02x}' for t in seen)})"
                )
        for forbidden in want.get("not_tlv_types", []):
            if int(forbidden) in seen:
                raise ScenarioFailure(
                    f"emit[{idx}] should not contain TLV 0x{int(forbidden):02x}"
                )


def _check_state(target: Any, state: dict[str, Any]) -> None:
    for key, want in state.items():
        if not hasattr(target, key):
            raise ScenarioFailure(f"target has no attribute {key!r}")
        got = getattr(target, key)
        if got != want:
            raise ScenarioFailure(f"state.{key} = {got!r} != expected {want!r}")


def run_scenario(scenario: dict[str, Any] | str | Path) -> ScenarioResult:
    """Execute ``scenario`` (a dict or a path to a YAML file)."""
    if isinstance(scenario, (str, Path)):
        scenario = load_scenario(scenario)
    target = _build_target(scenario)
    role = scenario.get("target", "agent")
    captured: list[bytes] = []

    def fake_send(ctx, cmdu_bytes, *, dst=None):  # type: ignore[no-untyped-def]
        del ctx, dst
        captured.append(cmdu_bytes)

    patch_path = f"ieee1905.emulator.{role}.send_frame"
    steps = scenario["steps"]
    steps_run = 0
    with patch(patch_path, side_effect=fake_send):
        for step in steps:
            steps_run += 1
            if "inject" in step:
                inj = step["inject"]
                src = _mac(inj.get("src_mac", "02:00:cc:cc:cc:01"))
                try:
                    cmdu = CMDU.from_bytes(_hex(inj["cmdu_hex"]))
                except CMDUParseError as exc:
                    raise ScenarioFailure(
                        f"step {steps_run}: cmdu_hex did not parse: {exc}"
                    ) from exc
                target._on_cmdu(src, cmdu)
            elif "call" in step:
                method = step["call"]["method"]
                raw_args = step["call"].get("args", [])
                args = [_mac(a) if _looks_like_mac(a) else a for a in raw_args]
                getattr(target, method)(*args)
            elif "set_state" in step:
                for k, v in step["set_state"].items():
                    setattr(target, k, v)
            elif "expect" in step:
                exp = step["expect"]
                if "emit_count" in exp and len(captured) != int(exp["emit_count"]):
                    raise ScenarioFailure(
                        f"emit_count: got {len(captured)} != expected "
                        f"{int(exp['emit_count'])}"
                    )
                if "emits" in exp:
                    cmdus = [CMDU.from_bytes(c) for c in captured]
                    _check_emits(cmdus, exp["emits"])
                if "state" in exp:
                    _check_state(target, exp["state"])
                # Drain the captured buffer so subsequent emits don't
                # pile on top of already-asserted ones.
                captured.clear()
            else:
                raise ScenarioFailure(
                    f"step {steps_run}: unknown step type "
                    f"(expected one of inject/call/set_state/expect)"
                )

    return ScenarioResult(
        name=scenario["name"],
        target_role=role,
        steps_run=steps_run,
        frames_emitted=captured,
    )


def _looks_like_mac(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    clean = value.replace(":", "").replace("-", "").replace(" ", "")
    return len(clean) == 12 and bool(_HEX_PAIR.fullmatch(clean[:2]))
