# SPDX-License-Identifier: GPL-2.0-or-later
"""YAML template loader + CLI + REST tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient

from ieee1905.api.app import create_app
from ieee1905.api.auth import current_token
from ieee1905.cli.main import cli
from ieee1905.core import CMDU, MessageType
from ieee1905.core.tlv import decode_raw
from ieee1905.core.tlvs import AlMacAddress, AutoconfigFreqBand, MacAddress, SupportedService
from ieee1905.templates import (
    TemplateError,
    builtin_templates,
    builtin_templates_dir,
    load_template,
)


def test_builtin_templates_dir_exists_and_has_entries() -> None:
    bdir = builtin_templates_dir()
    assert bdir.is_dir(), f"missing builtin templates dir: {bdir}"
    assert list(bdir.glob("*.yaml"))


def test_builtin_templates_load_without_error() -> None:
    templates = builtin_templates()
    assert {"topology_discovery", "topology_query", "ap_autoconfig_search", "ap_capability_query"} <= set(templates)


def test_topology_discovery_round_trip() -> None:
    tpl = builtin_templates()["topology_discovery"]
    assert tpl.required_variables() == {"al_mac", "interface_mac"}

    cmdu = tpl.build(
        {"al_mac": "02:aa:bb:cc:dd:01", "interface_mac": "02:aa:bb:cc:ee:01"},
        message_id=0x1234,
    )
    assert cmdu.header.message_type == MessageType.TOPOLOGY_DISCOVERY.value
    assert cmdu.header.message_id == 0x1234
    typed = list(cmdu.typed_tlvs())
    assert len(typed) == 2
    assert isinstance(typed[0], AlMacAddress)
    assert isinstance(typed[1], MacAddress)
    assert typed[0].al_mac == bytes.fromhex("02aabbccdd01")
    assert typed[1].mac == bytes.fromhex("02aabbccee01")


def test_ap_autoconfig_search_uses_typed_list_and_int_variables() -> None:
    tpl = builtin_templates()["ap_autoconfig_search"]
    cmdu = tpl.build({"al_mac": "02:00:00:00:00:01", "freq_band": 1})
    typed = list(cmdu.typed_tlvs())
    # Order: AlMac, SearchedRole, AutoconfigFreqBand, SupportedService.
    assert isinstance(typed[0], AlMacAddress)
    assert isinstance(typed[2], AutoconfigFreqBand)
    assert isinstance(typed[3], SupportedService)
    assert typed[2].band == 1
    assert typed[3].services == [1]


def test_empty_template_round_trips_with_no_variables() -> None:
    tpl = builtin_templates()["topology_query"]
    assert tpl.required_variables() == set()
    cmdu = tpl.build({}, message_id=5)
    assert cmdu.header.message_type == MessageType.TOPOLOGY_QUERY.value
    assert cmdu.tlvs == []


def test_template_build_rejects_missing_variables() -> None:
    tpl = builtin_templates()["topology_discovery"]
    with pytest.raises(TemplateError) as excinfo:
        tpl.build({"al_mac": "02:00:00:00:00:01"})
    assert "interface_mac" in str(excinfo.value)


def test_template_loader_rejects_unknown_class(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "name: bad\nmessage_type: 0\ntlvs:\n  - class: TotallyUnknownClass\n    foo: 1\n"
    )
    tpl = load_template(bad)
    with pytest.raises(TemplateError) as excinfo:
        tpl.build({})
    assert "unknown TLV class" in str(excinfo.value)


def test_template_loader_rejects_non_mapping_root(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("- just a list\n")
    with pytest.raises(TemplateError):
        load_template(bad)


def test_cli_templates_lists_builtins() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["templates"])
    assert result.exit_code == 0, result.output
    # Rich may truncate / wrap the names; settle for substrings.
    out = result.output.lower()
    assert "topology" in out
    assert "ap_autoconfig" in out or "ap autoconfig" in out or "autoconfig" in out


def test_api_list_templates_requires_token() -> None:
    client = TestClient(create_app())
    assert client.get("/api/templates").status_code == 401
    resp = client.get("/api/templates", headers={"X-API-Token": current_token()})
    assert resp.status_code == 200
    names = {item["name"] for item in resp.json()}
    assert "topology_discovery" in names


def test_api_inject_template_validates_inputs() -> None:
    client = TestClient(create_app())
    # Unknown template → 404.
    resp = client.post(
        "/api/inject/template",
        json={"interface": "lo0", "template": "no_such_template"},
        headers={"X-API-Token": current_token()},
    )
    assert resp.status_code == 404
    # Missing variables → 400.
    resp = client.post(
        "/api/inject/template",
        json={"interface": "lo0", "template": "topology_discovery"},
        headers={"X-API-Token": current_token()},
    )
    assert resp.status_code == 400


def test_api_inject_template_happy_path() -> None:
    """With mocked backend, full inject path produces a decodable CMDU."""

    class _FakeLive:
        def __init__(self) -> None:
            self.injected: list[bytes] = []

        def __enter__(self) -> _FakeLive:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def inject(self, frame: bytes) -> None:
            self.injected.append(frame)

    fake_live = _FakeLive()
    mock_backend = MagicMock()
    mock_backend.open_live.return_value = fake_live

    client = TestClient(create_app())
    # Patch at the source module because the API endpoint imports
    # get_default_backend lazily inside the handler.
    with patch("ieee1905.io.backend.get_default_backend", return_value=mock_backend):
        resp = client.post(
            "/api/inject/template",
            json={
                "interface": "lo0",
                "template": "topology_discovery",
                "variables": {
                    "al_mac": "02:aa:bb:cc:dd:01",
                    "interface_mac": "02:aa:bb:cc:ee:01",
                },
                "src_mac": "02:aa:bb:cc:ee:01",
            },
            headers={"X-API-Token": current_token()},
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["template"] == "topology_discovery"
    assert body["message_type"] == MessageType.TOPOLOGY_DISCOVERY.value

    # The frame we "injected" should decode back to the same template output.
    assert len(fake_live.injected) == 1
    frame = fake_live.injected[0]
    # Strip ethernet header (14 bytes).
    cmdu = CMDU.from_bytes(frame[14:])
    typed = list(cmdu.typed_tlvs())
    assert isinstance(decode_raw(cmdu.tlvs[0]), AlMacAddress)
    assert isinstance(typed[1], MacAddress)
