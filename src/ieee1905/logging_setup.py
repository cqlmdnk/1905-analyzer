# SPDX-License-Identifier: GPL-2.0-or-later
"""Logging configuration.

Two output styles:
- ``human``: rich-formatted, color, for interactive shells.
- ``json``:  one JSON object per line, for CI and log shipping.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Literal

from rich.logging import RichHandler

LogFormat = Literal["human", "json"]


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        for key, value in record.__dict__.items():
            if key in _STDLIB_RECORD_KEYS or key.startswith("_"):
                continue
            payload[key] = value
        return json.dumps(payload, default=str)


_STDLIB_RECORD_KEYS = frozenset(logging.LogRecord(
    name="", level=0, pathname="", lineno=0, msg="", args=(), exc_info=None,
).__dict__)


def configure(level: str = "INFO", fmt: LogFormat | None = None) -> None:
    if fmt is None:
        fmt = "json" if os.environ.get("IEEE1905_LOG_FORMAT") == "json" else "human"

    root = logging.getLogger()
    root.setLevel(level.upper())
    for h in list(root.handlers):
        root.removeHandler(h)

    handler: logging.Handler
    if fmt == "json":
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(_JsonFormatter())
    else:
        handler = RichHandler(rich_tracebacks=True, show_path=False, show_time=True)
    root.addHandler(handler)
