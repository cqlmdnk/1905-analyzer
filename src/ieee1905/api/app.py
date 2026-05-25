# SPDX-License-Identifier: GPL-2.0-or-later
"""FastAPI backend skeleton.

Phase 0 only exposes meta endpoints (``/api/version``, ``/api/interfaces``,
``/api/privileges``). Capture, inject, bridge, plugin, and conformance
endpoints arrive in later phases.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ieee1905 import __version__
from ieee1905.api.auth import current_token, require_token
from ieee1905.io import check_privileges, list_interfaces
from ieee1905.logging_setup import configure as configure_logging

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    app = FastAPI(
        title="ieee1905-suite",
        version=__version__,
        description="IEEE 1905.1 + EasyMesh analyzer/injector/bridge suite (Phase 0 skeleton).",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["X-API-Token", "Content-Type"],
    )

    @app.get("/api/version")
    def version() -> dict[str, str]:
        return {"version": __version__}

    @app.get("/api/privileges", dependencies=[Depends(require_token)])
    def privileges() -> dict[str, Any]:
        pc = check_privileges()
        return {
            "ok": pc.ok,
            "platform": pc.platform,
            "detail": pc.detail,
            "hint": pc.hint,
        }

    @app.get("/api/interfaces", dependencies=[Depends(require_token)])
    def interfaces() -> list[dict[str, Any]]:
        return [
            {
                "name": i.name,
                "mac": i.mac,
                "description": i.description,
                "is_loopback": i.is_loopback,
                "is_up": i.is_up,
            }
            for i in list_interfaces()
        ]

    return app


def run(host: str = "127.0.0.1", port: int = 8519, reload: bool = False) -> None:
    import uvicorn

    configure_logging()
    token = current_token()
    logger.info("API token: %s", token)
    logger.info("Bind: http://%s:%d/api/version", host, port)
    uvicorn.run(
        "ieee1905.api.app:create_app",
        host=host,
        port=port,
        reload=reload,
        factory=True,
        log_config=None,
    )
