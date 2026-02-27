from __future__ import annotations

import ipaddress
import re
import socket
import struct
import subprocess
from datetime import UTC, datetime
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

SIOCGIFFLAGS = 0x8913
SIOCGIFADDR = 0x8915
SIOCGIFBRDADDR = 0x8919
SIOCGIFNETMASK = 0x891B

IFF_UP = 0x1
IFF_LOOPBACK = 0x8


def _ioctl_ipv4(if_name: str, command: int) -> str | None:
    if fcntl is None:
        return None
    ifreq = struct.pack("256s", if_name.encode("utf-8")[:15])
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            result = fcntl.ioctl(sock.fileno(), command, ifreq)
    except OSError:
        return None
    return socket.inet_ntoa(result[20:24])


def _ioctl_flags(if_name: str) -> int | None:
    if fcntl is None:
        return None
    ifreq = struct.pack("256s", if_name.encode("utf-8")[:15])
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            result = fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, ifreq)
    except OSError:
        return None
    return int(struct.unpack("H", result[16:18])[0])


def _hex_netmask_to_dotted(value: str) -> str | None:
    if not value.startswith("0x"):
        return value
    try:
        number = int(value, 16)
    except ValueError:
        return None
    return ".".join(str((number >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def _discover_interfaces_from_ifconfig() -> list[dict[str, Any]]:
    try:
        result = subprocess.run(
            ["ifconfig"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return []
    if result.returncode != 0 or not result.stdout.strip():
        return []

    interfaces: dict[str, dict[str, Any]] = {}
    current: dict[str, Any] | None = None
    for raw_line in result.stdout.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        if not raw_line.startswith((" ", "\t")):
            match = re.match(r"^([A-Za-z0-9_.:-]+):\s+flags=.*<([^>]*)>", line)
            if match:
                name = match.group(1)
                flags = {part.strip().upper() for part in match.group(2).split(",") if part.strip()}
            else:
                name = line.split(":", maxsplit=1)[0]
                flags = set()
            current = {
                "name": name,
                "is_up": "UP" in flags,
                "is_loopback": "LOOPBACK" in flags or name.startswith("lo"),
                "ipv4": None,
                "netmask": None,
                "broadcast": None,
                "network_cidr": None,
            }
            interfaces[name] = current
            continue
        if current is None:
            continue
        stripped = line.strip()
        if not stripped.startswith("inet "):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        ipv4 = parts[1]
        if ":" in ipv4:
            continue
        netmask = None
        broadcast = None
        if "netmask" in parts:
            idx = parts.index("netmask")
            if idx + 1 < len(parts):
                netmask = _hex_netmask_to_dotted(parts[idx + 1])
        if "broadcast" in parts:
            idx = parts.index("broadcast")
            if idx + 1 < len(parts):
                broadcast = parts[idx + 1]
        network_cidr = None
        if netmask:
            try:
                network_cidr = str(ipaddress.IPv4Network(f"{ipv4}/{netmask}", strict=False))
            except ValueError:
                network_cidr = None
        current["ipv4"] = ipv4
        current["netmask"] = netmask
        current["broadcast"] = broadcast
        current["network_cidr"] = network_cidr

    return [interfaces[name] for name in sorted(interfaces.keys())]


def discover_network_interfaces() -> list[dict[str, Any]]:
    interfaces: list[dict[str, Any]] = []
    for _, if_name in sorted(socket.if_nameindex(), key=lambda item: item[1]):
        flags = _ioctl_flags(if_name)
        ipv4 = _ioctl_ipv4(if_name, SIOCGIFADDR)
        netmask = _ioctl_ipv4(if_name, SIOCGIFNETMASK)
        broadcast = _ioctl_ipv4(if_name, SIOCGIFBRDADDR)
        network_cidr: str | None = None
        if ipv4 and netmask:
            try:
                network_cidr = str(ipaddress.IPv4Network(f"{ipv4}/{netmask}", strict=False))
            except ValueError:
                network_cidr = None
        is_up = bool(flags & IFF_UP) if flags is not None else bool(ipv4)
        is_loopback = bool(flags & IFF_LOOPBACK) if flags is not None else (if_name.startswith("lo") or ipv4 == "127.0.0.1")
        interfaces.append(
            {
                "name": if_name,
                "is_up": is_up,
                "is_loopback": is_loopback,
                "ipv4": ipv4,
                "netmask": netmask,
                "broadcast": broadcast,
                "network_cidr": network_cidr,
            }
        )
    if interfaces and any(row["ipv4"] for row in interfaces):
        return interfaces
    discovered = _discover_interfaces_from_ifconfig()
    if discovered:
        return discovered
    return interfaces


def build_network_diagnostics_snapshot() -> dict[str, Any]:
    interfaces = discover_network_interfaces()
    active_ipv4 = [row for row in interfaces if row["is_up"] and not row["is_loopback"] and row["ipv4"]]
    networks = sorted({str(row["network_cidr"]) for row in active_ipv4 if row["network_cidr"]})
    return {
        "discovered_at": datetime.now(UTC).isoformat(),
        "interface_count": len(interfaces),
        "active_ipv4_interface_count": len(active_ipv4),
        "active_ipv4_interfaces": [str(row["name"]) for row in active_ipv4],
        "detected_ipv4_networks": networks,
        "has_multiple_active_networks": len(networks) > 1,
        "interfaces": interfaces,
    }
