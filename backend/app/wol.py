from __future__ import annotations

import ipaddress
import re
import socket
from typing import Optional

MAC_RE = re.compile(r"^[0-9a-fA-F]{12}$")


def normalize_mac(mac: str) -> str:
    cleaned = mac.replace(":", "").replace("-", "").replace(".", "").strip()
    if not MAC_RE.match(cleaned):
        raise ValueError("Invalid MAC address")
    return cleaned.lower()


def build_magic_packet(mac: str) -> bytes:
    mac_hex = normalize_mac(mac)
    mac_bytes = bytes.fromhex(mac_hex)
    return b"\xff" * 6 + mac_bytes * 16


def resolve_target(broadcast: Optional[str], subnet_cidr: Optional[str]) -> str:
    if broadcast:
        return broadcast
    if subnet_cidr:
        network = ipaddress.ip_network(subnet_cidr, strict=False)
        return str(network.broadcast_address)
    return "255.255.255.255"


def send_magic_packet(
    mac: str,
    target_ip: str,
    udp_port: int = 9,
    interface: Optional[str] = None,
    source_ip: Optional[str] = None,
) -> None:
    packet = build_magic_packet(mac)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if source_ip:
            parsed = ipaddress.ip_address(source_ip.strip())
            if parsed.version != 4:
                raise ValueError("source_ip must be an IPv4 address")
            sock.bind((str(parsed), 0))
        if interface and hasattr(socket, "SO_BINDTODEVICE"):
            interface_name = interface.strip()
            if interface_name:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface_name.encode() + b"\x00")
                except PermissionError as exc:
                    raise OSError(
                        "Binding to interface failed (permission denied). "
                        "In containers, prefer source_ip or grant NET_RAW capability."
                    ) from exc
        sock.sendto(packet, (target_ip, udp_port))
    finally:
        sock.close()
