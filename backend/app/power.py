from __future__ import annotations

import errno
import socket
import time
from dataclasses import dataclass


@dataclass
class PowerCheckResult:
    method: str
    result: str
    detail: str
    latency_ms: int | None


def _run_tcp_check(target: str | None, port: int | None, timeout_seconds: float) -> PowerCheckResult:
    if not target:
        return PowerCheckResult(method="tcp", result="unknown", detail="missing_check_target", latency_ms=None)
    if port is None:
        return PowerCheckResult(method="tcp", result="unknown", detail="missing_check_port", latency_ms=None)

    started = time.perf_counter()
    try:
        with socket.create_connection((target, port), timeout=timeout_seconds):
            latency_ms = int((time.perf_counter() - started) * 1000)
            return PowerCheckResult(method="tcp", result="on", detail="connected", latency_ms=latency_ms)
    except (socket.timeout, TimeoutError):
        latency_ms = int((time.perf_counter() - started) * 1000)
        return PowerCheckResult(method="tcp", result="off", detail="timeout", latency_ms=latency_ms)
    except ConnectionRefusedError:
        latency_ms = int((time.perf_counter() - started) * 1000)
        return PowerCheckResult(method="tcp", result="off", detail="connection_refused", latency_ms=latency_ms)
    except socket.gaierror:
        return PowerCheckResult(method="tcp", result="unknown", detail="dns_resolution_failed", latency_ms=None)
    except OSError as exc:
        latency_ms = int((time.perf_counter() - started) * 1000)
        if exc.errno in {errno.ECONNREFUSED, errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH}:
            return PowerCheckResult(
                method="tcp",
                result="off",
                detail=f"os_error_off:{exc.errno}",
                latency_ms=latency_ms,
            )
        return PowerCheckResult(
            method="tcp",
            result="unknown",
            detail=f"os_error_unknown:{exc.errno or exc.__class__.__name__}",
            latency_ms=latency_ms,
        )


def run_power_check(method: str, target: str | None, port: int | None, timeout_seconds: float = 1.5) -> PowerCheckResult:
    if method == "tcp":
        return _run_tcp_check(target=target, port=port, timeout_seconds=timeout_seconds)
    if method == "icmp":
        return PowerCheckResult(method="icmp", result="unknown", detail="icmp_not_implemented", latency_ms=None)
    return PowerCheckResult(method=method, result="unknown", detail="invalid_method", latency_ms=None)
