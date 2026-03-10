from __future__ import annotations

from datetime import UTC, datetime


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def device_diagnostic_hints(host: dict, stale_after_seconds: int = 60) -> list[str]:
    hints: list[str] = []
    check_method = host.get("check_method") or "tcp"

    if check_method == "tcp":
        if not host.get("check_target"):
            hints.append("Power check target is missing (set check_target).")
        if host.get("check_port") is None:
            hints.append("Power check TCP port is missing (set check_port).")
    elif check_method == "icmp":
        hints.append("ICMP checks may require additional OS/network privileges.")
    else:
        hints.append("Power check method is invalid; use 'tcp' or 'icmp'.")

    if not host.get("broadcast") and not host.get("subnet_cidr"):
        hints.append("WoL target uses global broadcast; set broadcast/subnet for reliability.")
    if host.get("broadcast") and not host.get("source_ip") and not host.get("interface"):
        hints.append("Set source_ip or interface for deterministic routing on multi-NIC senders.")

    if (host.get("last_power_state") or "unknown") == "unknown":
        hints.append("Last power state is unknown; verify check target, port, and routing.")

    checked_at = _parse_iso(host.get("last_power_checked_at"))
    if checked_at is None:
        hints.append("Power state has not been checked yet.")
    else:
        age = (datetime.now(UTC) - checked_at).total_seconds()
        if age > stale_after_seconds:
            hints.append("Power state data is stale; run a manual power-check test.")

    return hints
