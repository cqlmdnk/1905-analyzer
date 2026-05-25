# SPDX-License-Identifier: GPL-2.0-or-later
"""PCAP replay tests.

Live wire I/O is mocked — the test verifies the iteration / counting
logic, not the actual ``inject()`` call.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner
from fastapi.testclient import TestClient

from ieee1905.api.app import create_app
from ieee1905.api.auth import current_token
from ieee1905.cli.main import cli
from ieee1905.io.backend import ScapyBackend
from ieee1905.io.pcap import ReplayStats, replay_pcap

FIXTURE_R1 = Path(__file__).parent / "fixtures" / "easymesh_r1.pcap"


class _FakeLive:
    def __init__(self) -> None:
        self.injected: list[bytes] = []

    def __enter__(self) -> _FakeLive:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def inject(self, frame: bytes) -> None:
        self.injected.append(frame)


def _patch_backend() -> MagicMock:
    fake_live = _FakeLive()
    mock_backend = MagicMock()
    mock_backend.open_live.return_value = fake_live
    # Delegate open_offline to the real backend so we still iterate the PCAP.
    real = ScapyBackend()
    mock_backend.open_offline.side_effect = real.open_offline
    mock_backend._fake_live = fake_live  # keep a handle for assertions
    return mock_backend


def test_replay_injects_every_1905_frame() -> None:
    backend = _patch_backend()
    with patch("ieee1905.io.pcap.get_default_backend", return_value=backend):
        stats = replay_pcap(str(FIXTURE_R1), "lo0", speed=0)
    assert isinstance(stats, ReplayStats)
    assert stats.total_frames == 36  # R1 fixture has one CMDU per TLV (36)
    assert stats.injected == 36
    assert stats.skipped_non_1905 == 0
    assert len(backend._fake_live.injected) == 36


def test_replay_speed_zero_is_back_to_back_and_fast() -> None:
    backend = _patch_backend()
    started = time.monotonic()
    with patch("ieee1905.io.pcap.get_default_backend", return_value=backend):
        replay_pcap(str(FIXTURE_R1), "lo0", speed=0)
    # 36 frames with speed=0 should comfortably finish under 100 ms.
    assert time.monotonic() - started < 0.5


def test_replay_stop_event_aborts_early() -> None:
    backend = _patch_backend()
    stop = threading.Event()

    on_frame_calls = {"n": 0}

    def _on_frame(_raw: bytes, _ts: float) -> None:
        on_frame_calls["n"] += 1
        if on_frame_calls["n"] == 3:
            stop.set()

    with patch("ieee1905.io.pcap.get_default_backend", return_value=backend):
        stats = replay_pcap(
            str(FIXTURE_R1), "lo0", speed=0, stop_event=stop, on_frame=_on_frame
        )
    assert stats.injected == 3
    assert len(backend._fake_live.injected) == 3


def test_replay_callback_fires_per_injected_frame() -> None:
    backend = _patch_backend()
    seen: list[float] = []
    with patch("ieee1905.io.pcap.get_default_backend", return_value=backend):
        replay_pcap(
            str(FIXTURE_R1),
            "lo0",
            speed=0,
            on_frame=lambda _raw, ts: seen.append(ts),
        )
    assert len(seen) == 36


def test_cli_replay_runs() -> None:
    backend = _patch_backend()
    runner = CliRunner()
    with patch("ieee1905.io.pcap.get_default_backend", return_value=backend):
        result = runner.invoke(cli, ["replay", str(FIXTURE_R1), "lo0", "--speed", "0"])
    assert result.exit_code == 0, result.output
    assert "injected=36" in result.output


def test_api_replay_validates_path() -> None:
    client = TestClient(create_app())
    resp = client.post(
        "/api/pcap/replay",
        json={"interface": "lo0", "pcap_path": "/no/such/file.pcap"},
        headers={"X-API-Token": current_token()},
    )
    assert resp.status_code == 404


def test_api_replay_happy_path() -> None:
    backend = _patch_backend()
    client = TestClient(create_app())
    with patch("ieee1905.io.pcap.get_default_backend", return_value=backend):
        resp = client.post(
            "/api/pcap/replay",
            json={
                "interface": "lo0",
                "pcap_path": str(FIXTURE_R1),
                "speed": 0.0,
                "loop": False,
                "ieee1905_only": True,
            },
            headers={"X-API-Token": current_token()},
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["injected"] == 36
    assert body["skipped_non_1905"] == 0
