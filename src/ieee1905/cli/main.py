# SPDX-License-Identifier: GPL-2.0-or-later
"""``ieee1905`` command-line entry point."""

from __future__ import annotations

import sys
from pathlib import Path

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


@cli.command("templates")
@click.option(
    "--dir",
    "extra_dir",
    type=click.Path(exists=True, file_okay=False),
    help="Also list templates from a user directory.",
)
def list_templates_cmd(extra_dir: str | None) -> None:
    """List available CMDU templates (built-in + optional user dir)."""
    from ieee1905.templates import builtin_templates, load_template

    table = Table(title="Available templates")
    table.add_column("name", style="cyan")
    table.add_column("message_type")
    table.add_column("variables")
    table.add_column("description")
    for tpl in builtin_templates().values():
        table.add_row(
            tpl.name,
            f"0x{tpl.message_type:04x}",
            ", ".join(sorted(tpl.required_variables())) or "-",
            tpl.description.strip().splitlines()[0] if tpl.description else "",
        )
    if extra_dir:
        for path in sorted(Path(extra_dir).glob("*.yaml")):
            tpl = load_template(path)
            table.add_row(
                tpl.name,
                f"0x{tpl.message_type:04x}",
                ", ".join(sorted(tpl.required_variables())) or "-",
                tpl.description.strip().splitlines()[0] if tpl.description else "",
            )
    console.print(table)


@cli.command("inject-template")
@click.argument("template_name")
@click.argument("interface")
@click.option(
    "--var",
    "variables",
    multiple=True,
    metavar="KEY=VALUE",
    help="Template variable (repeat for several).",
)
@click.option(
    "--template-file",
    type=click.Path(exists=True, dir_okay=False),
    help="Use a YAML template from this path instead of the built-in named one.",
)
@click.option("--dst-mac", default="01:80:c2:00:00:13", show_default=True)
@click.option("--src-mac", help="Source MAC. Defaults to the interface MAC.")
@click.option("--profile", type=int, default=1, show_default=True, help="1 or 2 (Profile-2 framing).")
def inject_template_cmd(
    template_name: str,
    interface: str,
    variables: tuple[str, ...],
    template_file: str | None,
    dst_mac: str,
    src_mac: str | None,
    profile: int,
) -> None:
    """Build a CMDU from a template and inject it on INTERFACE."""
    from ieee1905.core.tlvs._helpers import parse_mac_str
    from ieee1905.io.backend import ETHERTYPE_IEEE1905, get_default_backend
    from ieee1905.io.ethernet import EthernetFrame
    from ieee1905.io.interfaces import list_interfaces
    from ieee1905.templates import builtin_templates, load_template

    vars_dict: dict[str, str] = {}
    for kv in variables:
        if "=" not in kv:
            console.print(f"[red]invalid --var {kv!r} (expected key=value)[/]")
            raise SystemExit(2)
        k, v = kv.split("=", 1)
        vars_dict[k.strip()] = v.strip()

    if template_file is not None:
        tpl = load_template(template_file)
    else:
        builtins = builtin_templates()
        if template_name not in builtins:
            console.print(
                f"[red]unknown template {template_name!r}; "
                f"available: {', '.join(builtins)}[/]"
            )
            raise SystemExit(2)
        tpl = builtins[template_name]

    cmdu = tpl.build(vars_dict)
    payload = cmdu.to_bytes(profile=profile if profile >= 2 else None)

    if src_mac is None:
        resolved_src: bytes | None = None
        for iface in list_interfaces():
            if iface.name == interface and iface.mac:
                resolved_src = parse_mac_str(iface.mac)
                break
        if resolved_src is None:
            console.print(
                f"[red]could not determine source MAC for {interface}; "
                "pass --src-mac[/]"
            )
            raise SystemExit(1)
        src = resolved_src
    else:
        src = parse_mac_str(src_mac)

    frame = EthernetFrame(
        dst=parse_mac_str(dst_mac), src=src, ethertype=ETHERTYPE_IEEE1905, payload=payload
    ).to_bytes()
    backend = get_default_backend()
    with backend.open_live(interface, bpf_filter=None, promiscuous=False) as live:
        live.inject(frame)
    console.print(f"[green]injected template {tpl.name!r} on {interface}[/]")


@cli.command("replay")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.argument("interface")
@click.option(
    "--speed",
    type=float,
    default=1.0,
    show_default=True,
    help="Timing multiplier. 1.0 = original speed, 2.0 = 2x faster, 0 = no delay.",
)
@click.option("--loop", is_flag=True, help="Replay indefinitely until Ctrl-C.")
@click.option(
    "--all-traffic",
    is_flag=True,
    help="Inject non-1905 frames too (default: only ether proto 0x893a).",
)
def replay_cmd(path: str, interface: str, speed: float, loop: bool, all_traffic: bool) -> None:
    """Re-inject frames from a PCAP file onto INTERFACE.

    Original frame timing is preserved by default; use --speed to scale or
    0 to fire as fast as possible. Requires raw socket privileges.
    """
    import threading

    from ieee1905.io.pcap import replay_pcap

    stop = threading.Event()
    console.print(
        f"[green]Replaying {path} → {interface}[/] (speed={speed}, loop={loop}). "
        "Ctrl-C to stop."
    )
    try:
        stats = replay_pcap(
            path,
            interface,
            speed=speed,
            loop=loop,
            ieee1905_only=not all_traffic,
            stop_event=stop,
        )
    except KeyboardInterrupt:
        stop.set()
        console.print("[yellow]interrupted[/]")
        return
    console.print(
        f"[green]done[/]: injected={stats.injected} skipped_non_1905={stats.skipped_non_1905} "
        f"skipped_malformed={stats.skipped_malformed} duration={stats.duration_s:.2f}s"
    )


@cli.group("emulator")
def emulator_group() -> None:
    """Run a minimal DUT emulator (fake agent or fake controller)."""


@emulator_group.command("agent")
@click.argument("interface")
@click.option(
    "--al-mac",
    default="02:aa:bb:cc:dd:01",
    show_default=True,
    help="AL MAC address the fake agent will advertise.",
)
@click.option(
    "--radio-id",
    default="02:aa:bb:cc:ee:01",
    show_default=True,
    help="Radio unique identifier (BSSID-shaped 6 bytes).",
)
@click.option(
    "--bssid",
    default="02:aa:bb:cc:ff:01",
    show_default=True,
    help="BSSID exposed in operational BSS / capability reports.",
)
@click.option("--ssid", default="emulator-mesh", show_default=True)
@click.option("--freq-band", type=int, default=1, show_default=True, help="0=2.4 GHz, 1=5 GHz, 2=60 GHz")
def emulator_agent_cmd(
    interface: str, al_mac: str, radio_id: str, bssid: str, ssid: str, freq_band: int
) -> None:
    """Start the fake agent. Press Ctrl-C to stop."""
    from ieee1905.core.tlvs._helpers import parse_mac_str
    from ieee1905.emulator import FakeAgent

    agent = FakeAgent(
        interface=interface,
        al_mac=parse_mac_str(al_mac),
        radio_id=parse_mac_str(radio_id),
        bssid=parse_mac_str(bssid),
        ssid=ssid.encode("utf-8"),
        freq_band=freq_band,
    )
    agent.start()
    console.print(f"[green]Fake agent running on {interface}. Ctrl-C to stop.[/]")
    try:
        import signal

        if hasattr(signal, "pause"):
            signal.pause()  # type: ignore[attr-defined,unused-ignore]
        else:
            # Windows: poll for Ctrl-C.
            import time

            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        agent.stop()


@emulator_group.command("controller")
@click.argument("interface")
@click.option(
    "--al-mac",
    default="02:00:00:00:00:01",
    show_default=True,
    help="AL MAC address the fake controller will advertise.",
)
@click.option(
    "--radio-id",
    default="02:00:00:00:01:01",
    show_default=True,
)
@click.option(
    "--bssid",
    default="02:00:00:00:02:01",
    show_default=True,
)
@click.option("--ssid", default="emulator-mesh", show_default=True)
def emulator_controller_cmd(
    interface: str, al_mac: str, radio_id: str, bssid: str, ssid: str
) -> None:
    """Start the fake controller. Press Ctrl-C to stop."""
    from ieee1905.core.tlvs._helpers import parse_mac_str
    from ieee1905.emulator import FakeController

    ctl = FakeController(
        interface=interface,
        al_mac=parse_mac_str(al_mac),
        radio_id=parse_mac_str(radio_id),
        bssid=parse_mac_str(bssid),
        ssid=ssid.encode("utf-8"),
    )
    ctl.start()
    console.print(f"[green]Fake controller running on {interface}. Ctrl-C to stop.[/]")
    try:
        import signal

        if hasattr(signal, "pause"):
            signal.pause()  # type: ignore[attr-defined,unused-ignore]
        else:
            import time

            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        ctl.stop()


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
