# SPDX-License-Identifier: GPL-2.0-or-later
"""Token-based authentication for the local FastAPI backend."""

from __future__ import annotations

import contextlib
import hmac
import logging
import secrets

from fastapi import Header, HTTPException, status

from ieee1905.config import PATHS

logger = logging.getLogger(__name__)


def _generate_token() -> str:
    return secrets.token_urlsafe(32)


def ensure_token() -> str:
    """Read the persisted API token, generating one on first run."""
    PATHS.ensure()
    if PATHS.token_file.exists():
        token = PATHS.token_file.read_text(encoding="ascii").strip()
        if token:
            return token
    token = _generate_token()
    PATHS.token_file.write_text(token + "\n", encoding="ascii")
    with contextlib.suppress(OSError):
        PATHS.token_file.chmod(0o600)
    logger.info("generated new API token at %s", PATHS.token_file)
    return token


_TOKEN: str | None = None


def current_token() -> str:
    global _TOKEN
    if _TOKEN is None:
        _TOKEN = ensure_token()
    return _TOKEN


def require_token(x_api_token: str = Header(default="", alias="X-API-Token")) -> None:
    if not hmac.compare_digest(x_api_token, current_token()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing X-API-Token",
        )
