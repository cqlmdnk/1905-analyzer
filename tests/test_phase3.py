# SPDX-License-Identifier: GPL-2.0-or-later
"""Phase 3 tests: PCAP decode CLI / REST + inject request shape."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner
from fastapi.testclient import TestClient

from ieee1905.api.app import create_app
from ieee1905.api.auth import current_token
from ieee1905.cli.main import cli
from ieee1905.io.pcap import iter_pcap, summarize_pcap

FIXTURE_R1 = Path(__file__).parent / "fixtures" / "easymesh_r1.pcap"
FIXTURE_R3 = Path(__file__).parent / "fixtures" / "easymesh_r3.pcap"


def test_iter_pcap_returns_one_cmdu_per_frame() -> None:
    frames = list(iter_pcap(str(FIXTURE_R1)))
    assert len(frames) > 0
    for f in frames:
        assert f.cmdu is not None
        # Two TLVs per frame in our fixture: one R1 TLV + EoM.
        assert len(f.cmdu.tlvs) == 2


def test_summarize_pcap_returns_label_histogram() -> None:
    counts = summarize_pcap(str(FIXTURE_R1))
    assert sum(counts.values()) > 0
    # Every frame in the R1 fixture uses the AP Capability Report carrier.
    assert any("AP_CAPABILITY_REPORT" in label for label in counts)


def test_cli_read_summary_runs() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["read", str(FIXTURE_R1), "--summary"])
    assert result.exit_code == 0, result.output
    assert "EM_AP_CAPABILITY_REPORT" in result.output


def test_cli_read_table_runs() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["read", str(FIXTURE_R1)])
    assert result.exit_code == 0, result.output
    assert "Frames in" in result.output


def test_cli_inspect_runs_on_known_frame() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["inspect", str(FIXTURE_R1), "0"])
    assert result.exit_code == 0, result.output
    assert "Frame 0" in result.output


def test_cli_inspect_rejects_bad_index() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["inspect", str(FIXTURE_R1), "99999"])
    assert result.exit_code != 0


def test_api_pcap_decode_returns_frames() -> None:
    client = TestClient(create_app())
    with open(FIXTURE_R3, "rb") as fh:
        resp = client.post(
            "/api/pcap/decode",
            files={"file": ("easymesh_r3.pcap", fh, "application/vnd.tcpdump.pcap")},
            headers={"X-API-Token": current_token()},
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["frame_count"] > 0
    # First frame's TLV should decode to a typed Encap1905Dpp (class name).
    first_tlvs = body["frames"][0]["cmdu"]["tlvs"]
    assert any(t.get("class") == "Encap1905Dpp" for t in first_tlvs)


def test_api_pcap_decode_requires_token() -> None:
    client = TestClient(create_app())
    with open(FIXTURE_R1, "rb") as fh:
        resp = client.post(
            "/api/pcap/decode",
            files={"file": ("easymesh_r1.pcap", fh, "application/octet-stream")},
        )
    assert resp.status_code == 401


def test_api_inject_validates_input() -> None:
    client = TestClient(create_app())
    # Bad hex should 400.
    resp = client.post(
        "/api/inject",
        json={"interface": "lo0", "frame_hex": "not-hex"},
        headers={"X-API-Token": current_token()},
    )
    assert resp.status_code == 400
    # Bad MAC should 400.
    resp = client.post(
        "/api/inject",
        json={
            "interface": "lo0",
            "frame_hex": "00",
            "dst_mac": "zz:zz:zz:zz:zz:zz",
            "src_mac": "00:11:22:33:44:55",
        },
        headers={"X-API-Token": current_token()},
    )
    assert resp.status_code == 400
