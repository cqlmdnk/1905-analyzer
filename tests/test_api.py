# SPDX-License-Identifier: GPL-2.0-or-later
"""FastAPI endpoint smoke tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from ieee1905 import __version__
from ieee1905.api.app import create_app
from ieee1905.api.auth import current_token


def test_version_endpoint_is_public() -> None:
    client = TestClient(create_app())
    resp = client.get("/api/version")
    assert resp.status_code == 200
    assert resp.json() == {"version": __version__}


def test_privileges_endpoint_requires_token() -> None:
    client = TestClient(create_app())
    assert client.get("/api/privileges").status_code == 401
    resp = client.get(
        "/api/privileges",
        headers={"X-API-Token": current_token()},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "ok" in body and "platform" in body
