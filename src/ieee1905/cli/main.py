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


@cli.command("read")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--all-traffic",
    is_flag=True,
    help="Include non-1905 frames in the listing (default: 1905 only).",
)
@click.option(
    "--summary",
    is_flag=True,
    help="Print only a per-message-type histogram instead of one row per frame.",
)
def read_cmd(path: str, all_traffic: bool, summary: bool) -> None:
    """Decode a PCAP / PCAPNG and list the IEEE 1905 frames it contains."""
    from ieee1905.core import MessageType
    from ieee1905.io.pcap import iter_pcap, summarize_pcap

    if summary:
        for label, count in sorted(summarize_pcap(path).items(), key=lambda x: -x[1]):
            console.print(f"  {count:>6}  {label}")
        return

    table = Table(title=f"Frames in {path}")
    table.add_column("#", justify="right")
    table.add_column("ts", justify="right")
    table.add_column("src", style="cyan")
    table.add_column("dst")
    table.add_column("type")
    table.add_column("message")
    table.add_column("tlvs", justify="right")
    table.add_column("note")
    for i, frame in enumerate(iter_pcap(path, ieee1905_only=not all_traffic)):
        if frame.cmdu is not None:
            msg = MessageType.describe(frame.cmdu.header.message_type)
            tlv_n = len(frame.cmdu.tlvs)
            note = ""
        else:
            msg = "-"
            tlv_n = 0
            note = frame.decode_error or "-"
        table.add_row(
            str(i),
            f"{frame.timestamp:.3f}",
            frame.src_mac.hex(":") if frame.src_mac else "-",
            frame.dst_mac.hex(":") if frame.dst_mac else "-",
            f"0x{frame.ethertype:04x}",
            msg,
            str(tlv_n),
            note,
        )
    console.print(table)


@cli.command("inspect")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.argument("index", type=int)
def inspect_cmd(path: str, index: int) -> None:
    """Show the typed TLV tree for a single frame in a PCAP."""
    from dataclasses import asdict, is_dataclass

    from ieee1905.core import MessageType
    from ieee1905.io.pcap import iter_pcap

    target = None
    for i, frame in enumerate(iter_pcap(path, ieee1905_only=True)):
        if i == index:
            target = frame
            break
    if target is None:
        console.print(f"[red]no frame at index {index}[/]")
        raise SystemExit(1)
    if target.cmdu is None:
        console.print(f"[red]frame {index} failed to decode: {target.decode_error}[/]")
        raise SystemExit(1)

    hdr = target.cmdu.header
    console.print(
        f"[bold]Frame {index}[/]  ts={target.timestamp:.3f}  "
        f"{target.src_mac.hex(':')} → {target.dst_mac.hex(':')}"
    )
    console.print(
        f"  message_type = {MessageType.describe(hdr.message_type)} (0x{hdr.message_type:04x})"
    )
    console.print(
        f"  mid={hdr.message_id}  fragment={hdr.fragment_id}  "
        f"last={hdr.last_fragment}  relay={hdr.relay_indicator}"
    )
    for j, typed in enumerate(target.cmdu.typed_tlvs()):
        if is_dataclass(typed) and not isinstance(typed, type):
            label = type(typed).__name__
            console.print(f"  [{j}] [cyan]{label}[/]: {asdict(typed)}")
        else:
            console.print(f"  [{j}] {typed!r}")


@cli.command("inject")
@click.argument("interface")
@click.option("--frame-hex", help="Raw 1905 frame body as a hex string.")
@click.option(
    "--repeat",
    default=1,
    type=int,
    show_default=True,
    help="Send N copies (>=1).",
)
@click.option(
    "--dst-mac",
    default="01:80:c2:00:00:13",
    show_default=True,
    help="Destination MAC address (IEEE 1905 multicast by default).",
)
@click.option("--src-mac", help="Source MAC. Defaults to the interface MAC.")
def inject_cmd(
    interface: str,
    frame_hex: str | None,
    repeat: int,
    dst_mac: str,
    src_mac: str | None,
) -> None:
    """Inject a 1905 frame onto INTERFACE. Requires raw socket privileges.

    For now, the simplest path is to supply the CMDU bytes via --frame-hex
    (built via `python -m ieee1905.core ...`). Template-based injection
    arrives next.
    """
    from ieee1905.core.tlvs._helpers import parse_mac_str
    from ieee1905.io.backend import ETHERTYPE_IEEE1905, get_default_backend
    from ieee1905.io.ethernet import EthernetFrame
    from ieee1905.io.interfaces import list_interfaces

    if frame_hex is None:
        console.print("[red]--frame-hex is required for now[/]")
        raise SystemExit(2)
    if repeat < 1:
        raise SystemExit("repeat must be >= 1")

    payload = bytes.fromhex(frame_hex)
    dst = parse_mac_str(dst_mac)
    if src_mac is None:
        src = None
        for iface in list_interfaces():
            if iface.name == interface and iface.mac:
                src = parse_mac_str(iface.mac)
                break
        if src is None:
            console.print(
                f"[red]could not determine source MAC for {interface}; "
                "pass --src-mac explicitly[/]"
            )
            raise SystemExit(1)
    else:
        src = parse_mac_str(src_mac)

    frame = EthernetFrame(
        dst=dst, src=src, ethertype=ETHERTYPE_IEEE1905, payload=payload
    ).to_bytes()

    backend = get_default_backend()
    with backend.open_live(interface, bpf_filter=None, promiscuous=False) as live:
        for _ in range(repeat):
            live.inject(frame)
    console.print(f"[green]injected {repeat} frame(s) on {interface}[/]")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
