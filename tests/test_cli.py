# SPDX-License-Identifier: GPL-2.0-or-later
"""CLI smoke tests."""

from __future__ import annotations

from click.testing import CliRunner

from ieee1905 import __version__
from ieee1905.cli.main import cli


def test_cli_version() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_cli_help_lists_subcommands() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    for sub in ("interfaces", "privileges", "serve"):
        assert sub in result.output
