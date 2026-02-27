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


def send_magic_packet(mac: str, target_ip: str, udp_port: int = 9, interface: Optional[str] = None) -> None:
    packet = build_magic_packet(mac)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if interface and hasattr(socket, "SO_BINDTODEVICE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\x00")
        sock.sendto(packet, (target_ip, udp_port))
    finally:
        sock.close()
