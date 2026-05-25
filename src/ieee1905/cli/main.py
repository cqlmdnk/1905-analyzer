# SPDX-License-Identifier: GPL-2.0-or-later
"""``ieee1905`` command-line entry point."""

from __future__ import annotations

import sys

import click
from rich.console import Console
from rich.table import Table

from ieee1905 import __version__
from ieee1905.logging_setup import configure as configure_logging

console = Console()


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="ieee1905")
@click.option(
    "--log-level",
    default="INFO",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    show_default=True,
)
@click.option(
    "--log-format",
    type=click.Choice(["human", "json"], case_sensitive=False),
    default=None,
    help="Override log format. Falls back to IEEE1905_LOG_FORMAT env var.",
)
def cli(log_level: str, log_format: str | None) -> None:
    """IEEE 1905.1 + EasyMesh analyzer/injector/bridge suite."""
    configure_logging(level=log_level, fmt=log_format)  # type: ignore[arg-type]


@cli.command("interfaces")
def list_interfaces_cmd() -> None:
    """List network interfaces visible to the suite."""
    from ieee1905.io import list_interfaces

    ifaces = list_interfaces()
    table = Table(title="Network interfaces")
    table.add_column("Name", style="cyan")
    table.add_column("MAC")
    table.add_column("Description")
    table.add_column("Loopback")
    for iface in ifaces:
        table.add_row(
            iface.name,
            iface.mac or "-",
            iface.description or "-",
            "yes" if iface.is_loopback else "no",
        )
    console.print(table)


@cli.command("privileges")
def privileges_cmd() -> None:
    """Show whether the current process can capture/inject raw frames."""
    from ieee1905.io import check_privileges

    pc = check_privileges()
    color = "green" if pc.ok else "yellow"
    console.print(f"[{color}]platform[/]: {pc.platform}")
    console.print(f"[{color}]capable[/]: {pc.ok}")
    console.print(f"[{color}]detail[/]:  {pc.detail}")
    if pc.hint:
        console.print(f"[bold]hint[/]:    {pc.hint}")
    sys.exit(0 if pc.ok else 1)


@cli.command("serve")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8519, type=int, show_default=True)
@click.option("--reload", is_flag=True, help="Auto-reload on source changes (dev).")
def serve_cmd(host: str, port: int, reload: bool) -> None:
    """Run the FastAPI backend (serves the web UI)."""
    from ieee1905.api.app import run

    run(host=host, port=port, reload=reload)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
