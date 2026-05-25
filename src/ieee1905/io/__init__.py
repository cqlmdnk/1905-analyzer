# SPDX-License-Identifier: GPL-2.0-or-later
"""Packet I/O — interface discovery, live capture, injection, PCAP I/O."""

from ieee1905.io.backend import CaptureBackend, get_default_backend
from ieee1905.io.ethernet import EthernetFrame, EthernetParseError
from ieee1905.io.interfaces import Interface, list_interfaces
from ieee1905.io.privilege import PrivilegeCheck, check_privileges

__all__ = [
    "CaptureBackend",
    "EthernetFrame",
    "EthernetParseError",
    "Interface",
    "PrivilegeCheck",
    "check_privileges",
    "get_default_backend",
    "list_interfaces",
]
