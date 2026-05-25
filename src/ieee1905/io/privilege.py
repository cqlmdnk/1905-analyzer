# SPDX-License-Identifier: GPL-2.0-or-later
"""Privilege detection and platform-specific guidance for raw socket access."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PrivilegeCheck:
    ok: bool
    platform: str
    detail: str
    hint: str | None


def _linux_has_cap_net_raw() -> bool:
    """Best-effort check for CAP_NET_RAW in the effective set."""
    try:
        with open(f"/proc/{os.getpid()}/status", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    cap = int(line.split()[1], 16)
                    return bool(cap & (1 << 13))  # CAP_NET_RAW=13
    except OSError:
        pass
    return False


def _check_linux() -> PrivilegeCheck:
    if os.geteuid() == 0:  # type: ignore[attr-defined,unused-ignore]
        return PrivilegeCheck(True, "linux", "running as root", None)
    if _linux_has_cap_net_raw():
        return PrivilegeCheck(True, "linux", "CAP_NET_RAW present", None)
    return PrivilegeCheck(
        False,
        "linux",
        "no root and no CAP_NET_RAW",
        "Run with sudo, or grant capabilities: "
        f"sudo setcap cap_net_raw,cap_net_admin+eip {sys.executable}",
    )


def _check_darwin() -> PrivilegeCheck:
    if os.geteuid() == 0:  # type: ignore[attr-defined,unused-ignore]
        return PrivilegeCheck(True, "darwin", "running as root", None)
    return PrivilegeCheck(
        False,
        "darwin",
        "BPF devices require elevated access",
        "Either run with sudo, or install Wireshark's ChmodBPF helper "
        "so /dev/bpf* is readable by your user.",
    )


def _check_windows() -> PrivilegeCheck:
    is_admin = False
    try:
        import ctypes

        # ctypes.windll only exists on Windows; the ignore is unused
        # on Windows itself, so we silence unused-ignore too.
        is_admin = bool(
            ctypes.windll.shell32.IsUserAnAdmin()  # type: ignore[attr-defined,unused-ignore]
        )
    except Exception:  # noqa: BLE001
        is_admin = False
    if is_admin:
        return PrivilegeCheck(True, "windows", "running as administrator", None)
    return PrivilegeCheck(
        False,
        "windows",
        "Npcap raw I/O typically requires administrator",
        "Install Npcap (https://npcap.com) and run this terminal as Administrator.",
    )


def check_privileges() -> PrivilegeCheck:
    """Detect whether the current process can perform raw socket I/O."""
    if sys.platform.startswith("linux"):
        return _check_linux()
    if sys.platform == "darwin":
        return _check_darwin()
    if sys.platform == "win32":
        return _check_windows()
    return PrivilegeCheck(False, sys.platform, "unsupported platform", None)
