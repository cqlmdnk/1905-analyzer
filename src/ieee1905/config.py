# SPDX-License-Identifier: GPL-2.0-or-later
"""Configuration and platform-aware directory layout."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from platformdirs import PlatformDirs

_dirs = PlatformDirs(appname="ieee1905-suite", appauthor=False, roaming=False)


@dataclass(frozen=True, slots=True)
class Paths:
    """Resolved on-disk paths used across the suite."""

    config_dir: Path = field(default_factory=lambda: Path(_dirs.user_config_dir))
    data_dir: Path = field(default_factory=lambda: Path(_dirs.user_data_dir))
    cache_dir: Path = field(default_factory=lambda: Path(_dirs.user_cache_dir))
    log_dir: Path = field(default_factory=lambda: Path(_dirs.user_log_dir))

    @property
    def tlv_plugins_dir(self) -> Path:
        return self.config_dir / "tlv_plugins"

    @property
    def rules_dir(self) -> Path:
        return self.config_dir / "rules"

    @property
    def token_file(self) -> Path:
        return self.config_dir / "api_token"

    def ensure(self) -> None:
        for p in (
            self.config_dir,
            self.data_dir,
            self.cache_dir,
            self.log_dir,
            self.tlv_plugins_dir,
            self.rules_dir,
        ):
            p.mkdir(parents=True, exist_ok=True)


PATHS = Paths()
