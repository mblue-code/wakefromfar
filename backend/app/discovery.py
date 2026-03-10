from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from typing import Any

from .network import build_network_diagnostics_snapshot
from .wol import normalize_mac

_IP_NEIGH_RE = re.compile(
    r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+dev\s+(?P<dev>[A-Za-z0-9_.:-]+)(?:\s+lladdr\s+(?P<mac>[0-9A-Fa-f:.-]+))?"
)
_ARP_RE = re.compile(
    r".*\((?P<ip>\d+\.\d+\.\d+\.\d+)\)\s+at\s+(?P<mac>[0-9A-Fa-f:.-]+)\s+on\s+(?P<dev>[A-Za-z0-9_.:-]+).*"
)


def _derive_broadcast(network_cidr: str | None, fallback: str | None) -> str | None:
    if fallback:
        return fallback
    if not network_cidr:
        return None
    try:
        net = ipaddress.ip_network(network_cidr, strict=False)
    except ValueError:
        return None
    if isinstance(net, ipaddress.IPv4Network):
        return str(net.broadcast_address)
    return None


def discover_sender_bindings() -> list[dict[str, str | None]]:
    snapshot = build_network_diagnostics_snapshot()
    bindings: list[dict[str, str | None]] = []
    for row in snapshot.get("interfaces", []):
        if not row.get("is_up") or row.get("is_loopback"):
            continue
        ipv4 = str(row.get("ipv4") or "").strip()
        network_cidr = str(row.get("network_cidr") or "").strip()
        if not ipv4 or not network_cidr:
            continue
        bindings.append(
            {
                "network_cidr": network_cidr,
                "source_ip": ipv4,
                "interface": str(row.get("name") or "").strip() or None,
                "broadcast_ip": _derive_broadcast(network_cidr, str(row.get("broadcast") or "").strip() or None),
            }
        )
    return bindings


def normalize_source_bindings(
    source_bindings: list[dict[str, Any]] | None,
    fallback_bindings: list[dict[str, str | None]] | None = None,
) -> list[dict[str, str | None]]:
    base = source_bindings or fallback_bindings or discover_sender_bindings()
    result: list[dict[str, str | None]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in base:
        network_cidr = str(row.get("network_cidr") or "").strip()
        source_ip = str(row.get("source_ip") or "").strip()
        interface = str(row.get("interface") or "").strip() or None
        if not network_cidr or not source_ip:
            continue
        key = (network_cidr, source_ip, interface or "")
        if key in seen:
            continue
        seen.add(key)
        result.append(
            {
                "network_cidr": network_cidr,
                "source_ip": source_ip,
                "interface": interface,
                "broadcast_ip": _derive_broadcast(
                    network_cidr=network_cidr,
                    fallback=str(row.get("broadcast_ip") or "").strip() or None,
                ),
            }
        )
    return result


def _ip_in_network(ip_text: str, network_cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip_text) in ipaddress.ip_network(network_cidr, strict=False)
    except ValueError:
        return False


def _safe_hostname(ip_text: str) -> str | None:
    try:
        name, _, _ = socket.gethostbyaddr(ip_text)
        if name:
            return name
    except Exception:
        return None
    return None


def _collect_neighbors_ip_neigh() -> list[dict[str, str]]:
    try:
        res = subprocess.run(["ip", "neigh", "show"], check=False, capture_output=True, text=True)
    except OSError:
        return []
    if res.returncode != 0:
        return []
    entries: list[dict[str, str]] = []
    for line in res.stdout.splitlines():
        raw = line.strip()
        if not raw:
            continue
        match = _IP_NEIGH_RE.match(raw)
        if not match:
            continue
        ip_text = match.group("ip")
        dev = match.group("dev")
        mac = (match.group("mac") or "").strip()
        entries.append({"ip": ip_text, "interface": dev, "mac": mac})
    return entries


def _collect_neighbors_arp() -> list[dict[str, str]]:
    try:
        res = subprocess.run(["arp", "-an"], check=False, capture_output=True, text=True)
    except OSError:
        return []
    if res.returncode != 0:
        return []
    entries: list[dict[str, str]] = []
    for line in res.stdout.splitlines():
        match = _ARP_RE.match(line.strip())
        if not match:
            continue
        entries.append(
            {
                "ip": match.group("ip"),
                "interface": match.group("dev"),
                "mac": match.group("mac"),
            }
        )
    return entries


def _first_open_port(ip_text: str, ports: list[int], timeout_ms: int) -> int | None:
    timeout = max(timeout_ms, 50) / 1000.0
    for port in ports:
        try:
            with socket.create_connection((ip_text, port), timeout=timeout):
                return port
        except OSError:
            continue
    return None


def _host_probe_ips(network_cidr: str, max_hosts: int) -> list[str]:
    if max_hosts <= 0:
        return []
    try:
        net = ipaddress.ip_network(network_cidr, strict=False)
    except ValueError:
        return []
    if not isinstance(net, ipaddress.IPv4Network):
        return []
    limit = min(max_hosts, max(net.num_addresses - 2, 0))
    if limit <= 0:
        return []
    result: list[str] = []
    for idx, host_ip in enumerate(net.hosts()):
        if idx >= limit:
            break
        result.append(str(host_ip))
    return result


def _build_confidence(mac: str | None, source_ip: str | None, broadcast_ip: str | None, ip_text: str | None) -> str:
    if mac and source_ip and broadcast_ip:
        return "high"
    if mac:
        return "medium"
    if ip_text:
        return "low"
    return "unknown"


def collect_discovery_candidates(
    source_bindings: list[dict[str, str | None]],
    host_probe_enabled: bool,
    host_probe_timeout_ms: int,
    max_hosts_per_network: int,
    power_probe_ports: list[int],
    power_probe_timeout_ms: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    warnings: list[str] = []
    if not source_bindings:
        return [], ["no_source_bindings"]

    by_network: dict[str, dict[str, str | None]] = {
        str(row["network_cidr"]): row for row in source_bindings if row.get("network_cidr")
    }
    by_interface: dict[str, dict[str, str | None]] = {
        str(row["interface"]): row for row in source_bindings if row.get("interface")
    }

    raw_neighbors = _collect_neighbors_ip_neigh()
    if not raw_neighbors:
        raw_neighbors = _collect_neighbors_arp()
        if not raw_neighbors:
            warnings.append("neighbor_cache_empty")

    candidates: list[dict[str, Any]] = []
    dedupe: set[tuple[str, str, str]] = set()

    for entry in raw_neighbors:
        ip_text = entry.get("ip", "")
        if not ip_text:
            continue
        binding = by_interface.get(entry.get("interface", ""))
        if binding is None:
            for network_cidr, row in by_network.items():
                if _ip_in_network(ip_text, network_cidr):
                    binding = row
                    break
        if binding is None:
            continue
        normalized_mac: str | None = None
        raw_mac = (entry.get("mac") or "").strip()
        if raw_mac and raw_mac.lower() != "(incomplete)":
            try:
                normalized_mac = normalize_mac(raw_mac)
            except ValueError:
                normalized_mac = None
        key = (
            str(binding.get("network_cidr") or ""),
            normalized_mac or "",
            ip_text,
        )
        if key in dedupe:
            continue
        dedupe.add(key)
        candidates.append(
            {
                "hostname": _safe_hostname(ip_text),
                "mac": normalized_mac,
                "ip": ip_text,
                "source_interface": binding.get("interface"),
                "source_ip": binding.get("source_ip"),
                "source_network_cidr": binding.get("network_cidr"),
                "broadcast_ip": binding.get("broadcast_ip"),
                "power_data_source": "inferred",
                "notes_json": {"seen_via": "neighbor_cache"},
            }
        )

    if host_probe_enabled:
        for binding in source_bindings:
            network_cidr = str(binding.get("network_cidr") or "")
            if not network_cidr:
                continue
            for ip_text in _host_probe_ips(network_cidr, max_hosts=max_hosts_per_network):
                if any(row.get("ip") == ip_text and row.get("source_network_cidr") == network_cidr for row in candidates):
                    continue
                open_port = _first_open_port(ip_text, power_probe_ports[:2] or [22, 80], timeout_ms=host_probe_timeout_ms)
                if open_port is None:
                    continue
                candidates.append(
                    {
                        "hostname": _safe_hostname(ip_text),
                        "mac": None,
                        "ip": ip_text,
                        "source_interface": binding.get("interface"),
                        "source_ip": binding.get("source_ip"),
                        "source_network_cidr": binding.get("network_cidr"),
                        "broadcast_ip": binding.get("broadcast_ip"),
                        "power_data_source": "inferred",
                        "power_check_method": "tcp",
                        "power_check_target": ip_text,
                        "power_check_port": open_port,
                        "notes_json": {"seen_via": "host_probe"},
                    }
                )

    for row in candidates:
        if row.get("ip") and not row.get("power_check_port"):
            probe_port = _first_open_port(
                ip_text=str(row["ip"]),
                ports=power_probe_ports,
                timeout_ms=power_probe_timeout_ms,
            )
            if probe_port is not None:
                row["power_check_method"] = "tcp"
                row["power_check_target"] = str(row["ip"])
                row["power_check_port"] = int(probe_port)
            else:
                row["power_check_method"] = None
                row["power_check_target"] = None
                row["power_check_port"] = None
        row["wol_confidence"] = _build_confidence(
            mac=row.get("mac"),
            source_ip=row.get("source_ip"),
            broadcast_ip=row.get("broadcast_ip"),
            ip_text=row.get("ip"),
        )

    return candidates, warnings


def summarize_candidates(candidates: list[dict[str, Any]], warnings: list[str]) -> dict[str, Any]:
    imported = sum(1 for row in candidates if row.get("imported_host_id"))
    return {
        "candidate_count": len(candidates),
        "with_mac_count": sum(1 for row in candidates if row.get("mac")),
        "wol_high_confidence_count": sum(1 for row in candidates if row.get("wol_confidence") == "high"),
        "imported_count": imported,
        "warnings": warnings,
    }
