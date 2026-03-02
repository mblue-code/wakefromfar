from __future__ import annotations

import hashlib
import ipaddress
import json
import secrets
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .admin_ui import router as admin_ui_router
from .config import get_settings
from .diagnostics import device_diagnostic_hints
from .db import (
    assign_device_to_user,
    claim_invite,
    count_admin_users,
    create_invite_token,
    create_host,
    create_discovery_candidate,
    create_discovery_run,
    create_user,
    delete_host,
    delete_user,
    fail_discovery_run,
    get_assigned_host_by_id,
    get_discovery_candidate,
    get_discovery_run,
    get_host_by_mac,
    get_host_by_id,
    get_invite_by_hash,
    get_user_by_id,
    get_user_by_username,
    init_db,
    list_admin_audit_logs,
    list_assignments,
    list_claimed_invites,
    list_discovery_candidates,
    list_discovery_events,
    list_discovery_runs,
    list_hosts,
    list_invite_tokens,
    list_power_check_logs,
    list_successful_wakes,
    list_users,
    list_wake_logs,
    list_assigned_hosts,
    log_admin_action,
    log_discovery_event,
    log_power_check,
    log_wake,
    mark_discovery_candidate_imported,
    mark_discovery_run_running,
    remove_assignment,
    revoke_invite,
    complete_discovery_run,
    update_host,
    update_host_power_state,
    update_user_password,
    update_user_password_by_id,
    update_user_role,
    upsert_admin,
)
from .discovery import (
    collect_discovery_candidates,
    discover_sender_bindings,
    normalize_source_bindings,
    summarize_candidates,
)
from .network import build_network_diagnostics_snapshot
from .power import PowerCheckResult, run_power_check
from .rate_limit import configure_rate_limiter, get_rate_limiter
from .schemas import (
    AdminDeviceCreate,
    AdminDeviceOut,
    AdminDeviceUpdate,
    AdminUserCreate,
    AdminUserOut,
    AdminUserUpdate,
    AssignmentCreate,
    AssignmentOut,
    DiscoveryCandidateOut,
    DiscoveryBulkImportRequest,
    DiscoveryBulkImportResponse,
    DiscoveryImportRequest,
    DiscoveryImportResponse,
    DiscoveryRunCreate,
    DiscoveryRunOut,
    DiscoveryValidateResponse,
    HostOut,
    InviteCreate,
    InviteCreateResponse,
    InviteOut,
    LoginRequest,
    LoginResponse,
    MeWakeResponse,
    MyDeviceOut,
    OnboardingClaimRequest,
    OnboardingClaimResponse,
    PowerCheckResponse,
    WakeResponse,
)
from .security import create_token, decode_token, hash_password, verify_password
from .telemetry import get_counters, increment_counter, structured_log
from .wol import normalize_mac, resolve_target, send_magic_packet

auth_scheme = HTTPBearer(auto_error=True)
_NETWORK_DIAGNOSTICS: dict[str, object] = {}
_UNSAFE_APP_SECRETS = {"change-me", "replace-with-a-random-long-secret"}
_UNSAFE_ADMIN_PASSWORDS = {"change-me-admin-password", "replace-with-strong-password"}


def _init_bootstrap() -> None:
    settings = get_settings()
    if settings.app_secret in _UNSAFE_APP_SECRETS:
        raise RuntimeError(
            "APP_SECRET uses an unsafe placeholder value. Set APP_SECRET to a random secret before startup."
        )
    if len(settings.app_secret) < 16:
        raise RuntimeError("APP_SECRET is too short. Use at least 16 characters.")
    if settings.admin_pass and settings.admin_pass in _UNSAFE_ADMIN_PASSWORDS:
        raise RuntimeError(
            "ADMIN_PASS uses an unsafe placeholder value. Set ADMIN_PASS to a unique password before startup."
        )
    if settings.admin_pass and len(settings.admin_pass) < 6:
        raise RuntimeError("ADMIN_PASS is too short. Use at least 6 characters.")
    configure_rate_limiter(settings)
    init_db()
    if settings.admin_user and settings.admin_pass:
        upsert_admin(settings.admin_user, hash_password(settings.admin_pass))


def _refresh_network_diagnostics() -> None:
    global _NETWORK_DIAGNOSTICS
    try:
        snapshot = build_network_diagnostics_snapshot()
        _NETWORK_DIAGNOSTICS = snapshot
        structured_log(
            "network.discovery.completed",
            interface_count=snapshot["interface_count"],
            active_ipv4_interface_count=snapshot["active_ipv4_interface_count"],
            detected_ipv4_networks=snapshot["detected_ipv4_networks"],
            has_multiple_active_networks=snapshot["has_multiple_active_networks"],
        )
    except Exception as exc:  # pragma: no cover
        _NETWORK_DIAGNOSTICS = {
            "discovered_at": datetime.now(UTC).isoformat(),
            "interface_count": 0,
            "active_ipv4_interface_count": 0,
            "active_ipv4_interfaces": [],
            "detected_ipv4_networks": [],
            "has_multiple_active_networks": False,
            "interfaces": [],
            "error": str(exc),
        }
        structured_log("network.discovery.failed", error=str(exc))


def on_startup() -> None:
    _init_bootstrap()
    _refresh_network_diagnostics()


@asynccontextmanager
async def app_lifespan(_app: FastAPI):
    on_startup()
    yield


app = FastAPI(title="WoL Relay", version="0.1.0", lifespan=app_lifespan)
app.include_router(admin_ui_router)


@app.get("/favicon.ico", include_in_schema=False)
def favicon_ico() -> RedirectResponse:
    return RedirectResponse(url="/admin/ui/favicon.png", status_code=307)


def _parse_ip(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not value:
        return None
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _extract_forwarded_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        first = forwarded_for.split(",")[0].strip()
        if _parse_ip(first):
            return first
    real_ip = request.headers.get("x-real-ip")
    if real_ip and _parse_ip(real_ip):
        return real_ip.strip()
    return None


def _is_in_networks(ip_text: str, cidrs: list[str]) -> bool:
    ip_obj = _parse_ip(ip_text)
    if not ip_obj:
        return False
    for cidr in cidrs:
        try:
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def _get_request_ip(request: Request) -> str | None:
    settings = get_settings()
    peer_ip = request.client.host if request.client else None
    if settings.trust_proxy_headers and peer_ip and _is_in_networks(peer_ip, settings.trusted_proxy_cidrs_list):
        forwarded_ip = _extract_forwarded_ip(request)
        if forwarded_ip:
            return forwarded_ip
    if peer_ip and _parse_ip(peer_ip):
        return peer_ip
    return None


@app.middleware("http")
async def allowlist_middleware(request: Request, call_next):
    settings = get_settings()
    if not settings.enforce_ip_allowlist:
        return await call_next(request)

    client_ip = _get_request_ip(request)
    if not client_ip:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing client IP")

    allowed = _is_in_networks(client_ip, settings.allowed_cidrs)

    if not allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Client IP not allowed")

    return await call_next(request)


def _enforce_rate_limit(
    scope: str,
    key: str,
    limit: int,
    detail: str,
) -> None:
    blocked = get_rate_limiter().check_and_record(
        scope=scope,
        key=key,
        limit=limit,
        window_seconds=60,
    )
    if blocked:
        increment_counter("rate_limit.blocked")
        structured_log("rate_limit.blocked", scope=scope, key=key, detail=detail, limit=limit)
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=detail)


@app.get("/health")
def health() -> dict[str, str]:
    return {"ok": "true"}


def get_current_user(
    creds: Annotated[HTTPAuthorizationCredentials, Depends(auth_scheme)],
) -> dict:
    payload = decode_token(creds.credentials)
    username = payload.get("sub", "")
    user = get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown user")
    return {"id": user["id"], "username": user["username"], "role": user["role"]}


def require_admin(current_user: Annotated[dict, Depends(get_current_user)]) -> dict:
    if current_user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return current_user


def _host_to_legacy_out(row: dict, is_stale: bool | None = None) -> HostOut:
    return HostOut(
        id=row["id"],
        name=row["name"],
        mac=row["mac"],
        group_name=row["group_name"],
        broadcast=row["broadcast"],
        subnet_cidr=row["subnet_cidr"],
        udp_port=row["udp_port"],
        source_ip=row["source_ip"],
        display_name=row["display_name"],
        last_power_state=row["last_power_state"] or "unknown",
        last_power_checked_at=row["last_power_checked_at"],
        is_stale=is_stale,
    )


def _host_to_admin_out(row: dict) -> AdminDeviceOut:
    return AdminDeviceOut(
        id=row["id"],
        name=row["name"],
        display_name=row["display_name"],
        mac=row["mac"],
        group_name=row["group_name"],
        broadcast=row["broadcast"],
        subnet_cidr=row["subnet_cidr"],
        udp_port=row["udp_port"],
        interface=row["interface"],
        source_ip=row["source_ip"],
        source_network_cidr=row["source_network_cidr"],
        check_method=row["check_method"] or "tcp",
        check_target=row["check_target"],
        check_port=row["check_port"],
        last_power_state=row["last_power_state"] or "unknown",
        last_power_checked_at=row["last_power_checked_at"],
        provisioning_source=row["provisioning_source"] or "manual",
        discovery_confidence=row["discovery_confidence"],
        last_discovered_at=row["last_discovered_at"],
    )


def _host_to_my_device_out(row: dict, is_stale: bool) -> MyDeviceOut:
    return MyDeviceOut(
        id=row["id"],
        name=row["name"],
        display_name=row["display_name"],
        mac=row["mac"],
        group_name=row["group_name"],
        last_power_state=row["last_power_state"] or "unknown",
        last_power_checked_at=row["last_power_checked_at"],
        is_stale=is_stale,
    )


def _is_stale(last_power_checked_at: str | None) -> bool:
    settings = get_settings()
    if not last_power_checked_at:
        return True
    try:
        checked_at = datetime.fromisoformat(last_power_checked_at)
    except ValueError:
        return True
    if checked_at.tzinfo is None:
        checked_at = checked_at.replace(tzinfo=UTC)
    age_seconds = (datetime.now(UTC) - checked_at).total_seconds()
    return age_seconds > settings.power_state_stale_seconds


def _get_authorized_host(current_user: dict, host_id: str):
    if current_user["role"] == "admin":
        host = get_host_by_id(host_id)
    else:
        host = get_assigned_host_by_id(current_user["id"], host_id)
    if not host:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host not found")
    return host


def _run_and_persist_power_check(host_row: dict) -> PowerCheckResponse:
    settings = get_settings()
    check_result: PowerCheckResult = run_power_check(
        method=host_row["check_method"] or "tcp",
        target=host_row["check_target"],
        port=host_row["check_port"],
        timeout_seconds=settings.power_check_timeout_seconds,
    )
    checked_at = datetime.now(UTC)
    update_host_power_state(host_row["id"], check_result.result, checked_at.isoformat())
    log_power_check(
        device_id=host_row["id"],
        method=check_result.method,
        result=check_result.result,
        detail=check_result.detail,
        latency_ms=check_result.latency_ms,
    )
    increment_counter(f"power_check.{check_result.result}")
    structured_log(
        "power_check.completed",
        device_id=host_row["id"],
        method=check_result.method,
        result=check_result.result,
        detail=check_result.detail,
        latency_ms=check_result.latency_ms,
    )
    return PowerCheckResponse(
        device_id=host_row["id"],
        method=check_result.method,
        result=check_result.result,
        detail=check_result.detail,
        latency_ms=check_result.latency_ms,
        checked_at=checked_at,
    )


def _send_magic_packet_with_retry(
    mac: str,
    target_ip: str,
    udp_port: int,
    interface: str | None,
    source_ip: str | None,
) -> tuple[bool, str | None]:
    settings = get_settings()
    max_attempts = max(1, settings.wake_send_max_attempts)
    last_error: str | None = None
    for attempt in range(max_attempts):
        try:
            send_magic_packet(
                mac=mac,
                target_ip=target_ip,
                udp_port=udp_port,
                interface=interface,
                source_ip=source_ip,
            )
            if attempt > 0:
                increment_counter("wake.retry.success")
            return True, None
        except (ValueError, OSError) as exc:
            last_error = str(exc)
            increment_counter("wake.retry.attempt_failed")
            structured_log(
                "wake.retry.attempt_failed",
                attempt=attempt + 1,
                max_attempts=max_attempts,
                error=last_error,
                target=f"{target_ip}:{udp_port}",
            )
            if attempt + 1 < max_attempts:
                sleep_seconds = (settings.wake_send_backoff_ms / 1000.0) * (2**attempt)
                time.sleep(sleep_seconds)
    return False, last_error


def _run_background_power_check(host_id: str) -> None:
    host = get_host_by_id(host_id)
    if not host:
        return
    try:
        _run_and_persist_power_check(host)
    except Exception:
        return


def _parse_json_dict(text: str | None) -> dict:
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return {}
    if isinstance(parsed, dict):
        return parsed
    return {}


def _discovery_run_to_out(row: dict) -> DiscoveryRunOut:
    return DiscoveryRunOut(
        id=row["id"],
        requested_by=row["requested_by"],
        status=row["status"],
        options=_parse_json_dict(row["options_json"]),
        summary=_parse_json_dict(row["summary_json"]) if row["summary_json"] else None,
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        created_at=row["created_at"],
    )


def _discovery_candidate_to_out(row: dict) -> DiscoveryCandidateOut:
    return DiscoveryCandidateOut(
        id=row["id"],
        run_id=row["run_id"],
        hostname=row["hostname"],
        mac=row["mac"],
        ip=row["ip"],
        source_interface=row["source_interface"],
        source_ip=row["source_ip"],
        source_network_cidr=row["source_network_cidr"],
        broadcast_ip=row["broadcast_ip"],
        wol_confidence=row["wol_confidence"],
        power_check_method=row["power_check_method"],
        power_check_target=row["power_check_target"],
        power_check_port=row["power_check_port"],
        power_data_source=row["power_data_source"] or "inferred",
        imported_host_id=row["imported_host_id"],
        suggested_host_id=None,
        suggested_host_name=None,
        notes=_parse_json_dict(row["notes_json"]) if row["notes_json"] else None,
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _candidate_default_name(candidate: dict, prefix: str | None = None) -> str:
    base = (candidate.get("hostname") or "").strip()
    if base:
        return base
    ip_text = (candidate.get("ip") or "").strip().replace(".", "-")
    if ip_text:
        return f"{prefix or 'discovered'}-{ip_text}"
    return f"{prefix or 'discovered'}-{str(candidate.get('id') or '')[:8]}"


def _import_discovery_candidate(
    candidate: dict,
    *,
    mode: str,
    name: str | None,
    display_name: str | None,
    target_host_id: str | None,
    apply_power_settings: bool,
    group_name: str | None,
    name_prefix: str | None = None,
) -> tuple[str, str]:
    now_iso = datetime.now(UTC).isoformat()
    requested_mode = mode
    existing_by_mac = get_host_by_mac(candidate["mac"]) if candidate.get("mac") else None
    effective_mode = requested_mode
    resolved_target = target_host_id
    if requested_mode == "auto_merge_by_mac":
        if existing_by_mac:
            effective_mode = "update_existing"
            resolved_target = existing_by_mac["id"]
        else:
            effective_mode = "create_new"

    if effective_mode == "create_new":
        if not candidate.get("mac"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Candidate has no MAC")
        resolved_name = (name or "").strip() or _candidate_default_name(candidate, prefix=name_prefix)
        host_id = create_host(
            name=resolved_name,
            display_name=display_name,
            mac=candidate["mac"],
            group_name=group_name,
            broadcast=candidate.get("broadcast_ip"),
            subnet_cidr=candidate.get("source_network_cidr"),
            udp_port=9,
            interface=candidate.get("source_interface"),
            source_ip=candidate.get("source_ip"),
            source_network_cidr=candidate.get("source_network_cidr"),
            check_method="tcp",
            check_target=candidate.get("power_check_target") if apply_power_settings else None,
            check_port=candidate.get("power_check_port") if apply_power_settings else None,
            provisioning_source="discovery",
            discovery_confidence=candidate.get("wol_confidence"),
            last_discovered_at=now_iso,
        )
        return host_id, effective_mode

    if effective_mode != "update_existing":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid import mode")
    if not resolved_target:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="target_host_id is required")
    existing = get_host_by_id(resolved_target)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target host not found")
    updates: dict[str, object | None] = {
        "broadcast": candidate.get("broadcast_ip") or existing["broadcast"],
        "source_ip": candidate.get("source_ip") or existing["source_ip"],
        "interface": candidate.get("source_interface") or existing["interface"],
        "source_network_cidr": candidate.get("source_network_cidr") or existing["source_network_cidr"],
        "provisioning_source": "discovery",
        "discovery_confidence": candidate.get("wol_confidence"),
        "last_discovered_at": now_iso,
    }
    if candidate.get("mac"):
        updates["mac"] = candidate["mac"]
    if name:
        updates["name"] = name
    if display_name is not None:
        updates["display_name"] = display_name
    if group_name is not None:
        updates["group_name"] = group_name
    if apply_power_settings:
        updates["check_method"] = "tcp"
        updates["check_target"] = candidate.get("power_check_target")
        updates["check_port"] = candidate.get("power_check_port")
    update_host(resolved_target, updates)
    return resolved_target, effective_mode


def _execute_discovery_run(run_id: str) -> None:
    run = get_discovery_run(run_id)
    if not run:
        return
    mark_discovery_run_running(run_id)
    options = _parse_json_dict(run["options_json"])
    try:
        bindings = normalize_source_bindings(
            options.get("source_bindings") if isinstance(options.get("source_bindings"), list) else [],
            fallback_bindings=discover_sender_bindings(),
        )
        selected_networks = {
            str(item).strip()
            for item in (options.get("network_cidrs") or [])
            if str(item).strip()
        }
        if selected_networks:
            bindings = [row for row in bindings if row.get("network_cidr") in selected_networks]

        host_probe = options.get("host_probe") or {}
        power_probe = options.get("power_probe") or {}
        candidates, warnings = collect_discovery_candidates(
            source_bindings=bindings,
            host_probe_enabled=bool(host_probe.get("enabled", False)),
            host_probe_timeout_ms=int(host_probe.get("timeout_ms", 200)),
            max_hosts_per_network=int(host_probe.get("max_hosts_per_network", 256)),
            power_probe_ports=[int(p) for p in power_probe.get("ports", []) if isinstance(p, int) and 1 <= p <= 65535]
            or [22, 80, 443, 445],
            power_probe_timeout_ms=int(power_probe.get("timeout_ms", 200)),
        )
        for candidate in candidates:
            candidate_id = create_discovery_candidate(
                run_id=run_id,
                hostname=candidate.get("hostname"),
                mac=candidate.get("mac"),
                ip=candidate.get("ip"),
                source_interface=candidate.get("source_interface"),
                source_ip=candidate.get("source_ip"),
                source_network_cidr=candidate.get("source_network_cidr"),
                broadcast_ip=candidate.get("broadcast_ip"),
                wol_confidence=candidate.get("wol_confidence") or "unknown",
                power_check_method=candidate.get("power_check_method"),
                power_check_target=candidate.get("power_check_target"),
                power_check_port=candidate.get("power_check_port"),
                power_data_source=candidate.get("power_data_source") or "inferred",
                notes_json=json.dumps(candidate.get("notes_json") or {}),
            )
            log_discovery_event(
                run_id=run_id,
                candidate_id=candidate_id,
                event_type="probe",
                detail=f"discovered ip={candidate.get('ip')} mac={candidate.get('mac')}",
            )

        summary = summarize_candidates(candidates=candidates, warnings=warnings)
        complete_discovery_run(run_id, json.dumps(summary))
        log_discovery_event(run_id=run_id, event_type="probe", detail=f"completed candidates={len(candidates)}")
    except Exception as exc:
        fail_summary = {"error": str(exc)}
        fail_discovery_run(run_id, json.dumps(fail_summary))
        log_discovery_event(run_id=run_id, event_type="error", detail=str(exc))


@app.post("/auth/login", response_model=LoginResponse)
def login(body: LoginRequest, request: Request) -> LoginResponse:
    settings = get_settings()
    ip = _get_request_ip(request) or "unknown"

    if get_rate_limiter().is_limited(
        scope="login",
        key=ip,
        limit=settings.login_rate_limit_per_minute,
        window_seconds=60,
    ):
        increment_counter("login.rate_limited")
        structured_log("login.rate_limited", ip=ip)
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many login attempts")

    user = get_user_by_username(body.username)
    if not user or not verify_password(body.password, user["password_hash"]):
        get_rate_limiter().record_attempt(scope="login", key=ip, window_seconds=60)
        increment_counter("login.failed")
        structured_log("login.failed", ip=ip, username=body.username)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token, expires_in = create_token(username=user["username"], role=user["role"])
    increment_counter("login.success")
    structured_log("login.success", ip=ip, username=user["username"], role=user["role"])
    return LoginResponse(token=token, expires_in=expires_in)


@app.post("/onboarding/claim", response_model=OnboardingClaimResponse)
def onboarding_claim(body: OnboardingClaimRequest, request: Request) -> OnboardingClaimResponse:
    settings = get_settings()
    ip = _get_request_ip(request) or "unknown"
    _enforce_rate_limit(
        "onboarding",
        ip,
        settings.onboarding_rate_limit_per_minute,
        "Too many onboarding attempts",
    )
    token_hash = hashlib.sha256(body.token.encode("utf-8")).hexdigest()
    invite = get_invite_by_hash(token_hash)
    if not invite:
        increment_counter("onboarding.failed")
        structured_log("onboarding.failed", ip=ip, reason="invite_not_found")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invite token not found")
    if invite["claimed_at"]:
        increment_counter("onboarding.failed")
        structured_log("onboarding.failed", ip=ip, reason="invite_already_claimed")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Invite token already claimed")

    now = datetime.now(UTC)
    expires_at = datetime.fromisoformat(invite["expires_at"])
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if now > expires_at:
        increment_counter("onboarding.failed")
        structured_log("onboarding.failed", ip=ip, reason="invite_expired")
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Invite token expired")

    user = get_user_by_username(invite["username"])
    if not user:
        increment_counter("onboarding.failed")
        structured_log("onboarding.failed", ip=ip, reason="invite_user_not_found")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invite user not found")

    claimed = claim_invite(invite_id=invite["id"], claimed_at=now.isoformat())
    if not claimed:
        increment_counter("onboarding.failed")
        structured_log("onboarding.failed", ip=ip, reason="claim_race", username=user["username"])
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Invite token already claimed")
    updated = update_user_password(username=user["username"], password_hash=hash_password(body.password))
    if not updated:
        increment_counter("onboarding.failed")
        structured_log(
            "onboarding.failed",
            ip=ip,
            reason="password_update_failed_after_claim",
            username=user["username"],
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not set password")

    token, expires_in = create_token(username=user["username"], role=user["role"])
    increment_counter("onboarding.success")
    structured_log("onboarding.success", ip=ip, username=user["username"])
    return OnboardingClaimResponse(
        token=token,
        expires_in=expires_in,
        username=user["username"],
        role=user["role"],
        backend_url_hint=invite["backend_url_hint"],
    )


@app.get("/hosts", response_model=list[HostOut], deprecated=True)
def get_hosts(current_user: Annotated[dict, Depends(get_current_user)]) -> list[HostOut]:
    rows = list_hosts() if current_user["role"] == "admin" else list_assigned_hosts(current_user["id"])
    return [_host_to_legacy_out(row=row, is_stale=_is_stale(row["last_power_checked_at"])) for row in rows]


@app.post("/hosts/{host_id}/wake", response_model=WakeResponse, deprecated=True)
def wake_host_legacy(host_id: str, current_user: Annotated[dict, Depends(get_current_user)]) -> WakeResponse:
    row = _get_authorized_host(current_user=current_user, host_id=host_id)

    target_ip = resolve_target(broadcast=row["broadcast"], subnet_cidr=row["subnet_cidr"])
    udp_port = row["udp_port"] or 9
    sent_ok, send_error = _send_magic_packet_with_retry(
        mac=row["mac"],
        target_ip=target_ip,
        udp_port=udp_port,
        interface=row["interface"],
        source_ip=row["source_ip"],
    )
    if not sent_ok:
        log_wake(
            host_id=host_id,
            actor_username=current_user["username"],
            sent_to=f"{target_ip}:{udp_port}",
            result="failed",
            error_detail=send_error,
            precheck_state="unknown",
        )
        increment_counter("wake.failed")
        structured_log("wake.failed", actor=current_user["username"], device_id=host_id, error=send_error)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"WoL send failed: {send_error}")

    sent_to = f"{target_ip}:{udp_port}"
    log_wake(
        host_id=host_id,
        actor_username=current_user["username"],
        sent_to=sent_to,
        result="sent",
        precheck_state="unknown",
    )
    increment_counter("wake.sent")
    structured_log("wake.sent", actor=current_user["username"], device_id=host_id, legacy=True)
    return WakeResponse(ok=True, sent_to=sent_to, timestamp=datetime.now(UTC), result="sent")


@app.get("/me/devices", response_model=list[MyDeviceOut])
def me_devices(
    background_tasks: BackgroundTasks,
    current_user: Annotated[dict, Depends(get_current_user)],
) -> list[MyDeviceOut]:
    rows = list_hosts() if current_user["role"] == "admin" else list_assigned_hosts(current_user["id"])
    result: list[MyDeviceOut] = []
    for row in rows:
        stale = _is_stale(row["last_power_checked_at"])
        if stale:
            background_tasks.add_task(_run_background_power_check, row["id"])
        result.append(_host_to_my_device_out(row=row, is_stale=stale))
    return result


@app.post("/me/devices/{host_id}/power-check", response_model=PowerCheckResponse)
def me_power_check(host_id: str, current_user: Annotated[dict, Depends(get_current_user)]) -> PowerCheckResponse:
    host = _get_authorized_host(current_user=current_user, host_id=host_id)
    return _run_and_persist_power_check(host)


@app.post("/me/devices/{host_id}/wake", response_model=MeWakeResponse)
def me_wake(host_id: str, request: Request, current_user: Annotated[dict, Depends(get_current_user)]) -> MeWakeResponse:
    settings = get_settings()
    ip = _get_request_ip(request) or "unknown"
    rate_key = f"{current_user['username']}@{ip}"
    _enforce_rate_limit(
        "wake",
        rate_key,
        settings.wake_rate_limit_per_minute,
        "Too many wake attempts",
    )
    host = _get_authorized_host(current_user=current_user, host_id=host_id)
    precheck = _run_and_persist_power_check(host)
    now = datetime.now(UTC)

    if precheck.result == "on":
        log_wake(
            host_id=host_id,
            actor_username=current_user["username"],
            sent_to="",
            result="already_on",
            precheck_state="on",
        )
        increment_counter("wake.already_on")
        structured_log("wake.already_on", actor=current_user["username"], device_id=host_id, ip=ip)
        return MeWakeResponse(
            device_id=host_id,
            result="already_on",
            message="Device is already on",
            precheck_state="on",
            sent_to=None,
            timestamp=now,
        )

    target_ip = resolve_target(broadcast=host["broadcast"], subnet_cidr=host["subnet_cidr"])
    udp_port = host["udp_port"] or 9
    sent_to = f"{target_ip}:{udp_port}"
    sent_ok, send_error = _send_magic_packet_with_retry(
        mac=host["mac"],
        target_ip=target_ip,
        udp_port=udp_port,
        interface=host["interface"],
        source_ip=host["source_ip"],
    )
    if not sent_ok:
        log_wake(
            host_id=host_id,
            actor_username=current_user["username"],
            sent_to=sent_to,
            result="failed",
            error_detail=send_error,
            precheck_state=precheck.result,
        )
        increment_counter("wake.failed")
        structured_log(
            "wake.failed",
            actor=current_user["username"],
            device_id=host_id,
            ip=ip,
            precheck_state=precheck.result,
            error=send_error,
        )
        return MeWakeResponse(
            device_id=host_id,
            result="failed",
            message="Wake failed",
            precheck_state=precheck.result,
            sent_to=sent_to,
            timestamp=now,
            error_detail=send_error,
        )

    is_misconfigured_precheck = precheck.result == "unknown" and (
        precheck.detail.startswith("missing_check_") or precheck.detail == "invalid_method"
    )
    wake_message = "Magic packet sent"
    if is_misconfigured_precheck:
        wake_message = "Magic packet sent (power-check misconfigured; verify check settings)"

    log_wake(
        host_id=host_id,
        actor_username=current_user["username"],
        sent_to=sent_to,
        result="sent",
        precheck_state=precheck.result,
    )
    increment_counter("wake.sent")
    structured_log(
        "wake.sent",
        actor=current_user["username"],
        device_id=host_id,
        ip=ip,
        precheck_state=precheck.result,
        precheck_detail=precheck.detail,
    )
    return MeWakeResponse(
        device_id=host_id,
        result="sent",
        message=wake_message,
        precheck_state=precheck.result,
        sent_to=sent_to,
        timestamp=now,
    )


@app.get("/admin/users", response_model=list[AdminUserOut])
def admin_list_users(_: Annotated[dict, Depends(require_admin)]) -> list[AdminUserOut]:
    return [
        AdminUserOut(
            id=row["id"],
            username=row["username"],
            role=row["role"],
            created_at=row["created_at"],
        )
        for row in list_users()
    ]


@app.post("/admin/users", status_code=status.HTTP_201_CREATED, response_model=AdminUserOut)
def admin_create_user(
    body: AdminUserCreate,
    current_user: Annotated[dict, Depends(require_admin)],
) -> AdminUserOut:
    if get_user_by_username(body.username):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")

    created_id = create_user(
        username=body.username,
        password_hash=hash_password(body.password),
        role=body.role,
    )
    created_user = get_user_by_id(created_id)
    if not created_user:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="User creation failed")
    log_admin_action(
        actor_username=current_user["username"],
        action="create_user",
        target_type="user",
        target_id=str(created_user["id"]),
        detail=f"username={created_user['username']}",
    )
    increment_counter("admin_action.create_user")
    structured_log("admin_action.create_user", actor=current_user["username"], target_id=created_user["id"])
    return AdminUserOut(
        id=created_user["id"],
        username=created_user["username"],
        role=created_user["role"],
        created_at=created_user["created_at"],
    )


@app.patch("/admin/users/{user_id}", response_model=AdminUserOut)
def admin_update_user(
    user_id: int,
    body: AdminUserUpdate,
    current_user: Annotated[dict, Depends(require_admin)],
) -> AdminUserOut:
    current = get_user_by_id(user_id)
    if not current:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    changes = body.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields to update")

    if "role" in changes:
        new_role = changes["role"]
        if current["role"] == "admin" and new_role != "admin" and count_admin_users() <= 1:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot demote last admin")
        update_user_role(user_id=user_id, role=new_role)
    if "password" in changes:
        update_user_password_by_id(user_id=user_id, password_hash=hash_password(changes["password"]))

    updated = get_user_by_id(user_id)
    if not updated:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="User update failed")
    log_admin_action(
        actor_username=current_user["username"],
        action="update_user",
        target_type="user",
        target_id=str(user_id),
        detail=",".join(sorted(changes.keys())),
    )
    increment_counter("admin_action.update_user")
    structured_log("admin_action.update_user", actor=current_user["username"], target_id=user_id)
    return AdminUserOut(
        id=updated["id"],
        username=updated["username"],
        role=updated["role"],
        created_at=updated["created_at"],
    )


@app.delete("/admin/users/{user_id}")
def admin_delete_user(user_id: int, current_user: Annotated[dict, Depends(require_admin)]) -> dict[str, bool]:
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user["role"] == "admin" and count_admin_users() <= 1:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete last admin")
    deleted = delete_user(user_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="User delete failed")
    log_admin_action(
        actor_username=current_user["username"],
        action="delete_user",
        target_type="user",
        target_id=str(user_id),
        detail=f"username={user['username']}",
    )
    increment_counter("admin_action.delete_user")
    structured_log("admin_action.delete_user", actor=current_user["username"], target_id=user_id)
    return {"ok": True}


@app.get("/admin/devices", response_model=list[AdminDeviceOut])
def admin_list_devices(_: Annotated[dict, Depends(require_admin)]) -> list[AdminDeviceOut]:
    return [_host_to_admin_out(row) for row in list_hosts()]


@app.get("/admin/hosts", response_model=list[AdminDeviceOut], deprecated=True)
def admin_list_hosts_legacy(_: Annotated[dict, Depends(require_admin)]) -> list[AdminDeviceOut]:
    return [_host_to_admin_out(row) for row in list_hosts()]


@app.post("/admin/devices", status_code=status.HTTP_201_CREATED, response_model=AdminDeviceOut)
def admin_create_device(
    body: AdminDeviceCreate,
    current_user: Annotated[dict, Depends(require_admin)],
) -> AdminDeviceOut:
    try:
        normalized_mac = normalize_mac(body.mac)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    host_id = create_host(
        host_id=body.id,
        name=body.name,
        mac=normalized_mac,
        group_name=body.group_name,
        broadcast=body.broadcast,
        subnet_cidr=body.subnet_cidr,
        udp_port=body.udp_port,
        interface=body.interface,
        source_ip=body.source_ip,
        source_network_cidr=body.source_network_cidr,
        display_name=body.display_name,
        check_method=body.check_method,
        check_target=body.check_target,
        check_port=body.check_port,
    )
    row = get_host_by_id(host_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Device creation failed")
    log_admin_action(
        actor_username=current_user["username"],
        action="create_device",
        target_type="device",
        target_id=host_id,
        detail=f"name={row['name']}",
    )
    increment_counter("admin_action.create_device")
    structured_log("admin_action.create_device", actor=current_user["username"], target_id=host_id)
    return _host_to_admin_out(row)


@app.patch("/admin/devices/{device_id}", response_model=AdminDeviceOut)
def admin_update_device(
    device_id: str,
    body: AdminDeviceUpdate,
    current_user: Annotated[dict, Depends(require_admin)],
) -> AdminDeviceOut:
    current = get_host_by_id(device_id)
    if not current:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    changes = body.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields to update")
    if "mac" in changes:
        try:
            changes["mac"] = normalize_mac(changes["mac"])
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    update_host(host_id=device_id, updates=changes)
    updated = get_host_by_id(device_id)
    if not updated:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Device update failed")
    log_admin_action(
        actor_username=current_user["username"],
        action="update_device",
        target_type="device",
        target_id=device_id,
        detail=",".join(sorted(changes.keys())),
    )
    increment_counter("admin_action.update_device")
    structured_log("admin_action.update_device", actor=current_user["username"], target_id=device_id)
    return _host_to_admin_out(updated)


@app.delete("/admin/devices/{device_id}")
def admin_delete_device(device_id: str, current_user: Annotated[dict, Depends(require_admin)]) -> dict[str, bool]:
    host = get_host_by_id(device_id)
    if not host:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    deleted = delete_host(device_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Device delete failed")
    log_admin_action(
        actor_username=current_user["username"],
        action="delete_device",
        target_type="device",
        target_id=device_id,
        detail=f"name={host['name']}",
    )
    increment_counter("admin_action.delete_device")
    structured_log("admin_action.delete_device", actor=current_user["username"], target_id=device_id)
    return {"ok": True}


@app.post("/admin/hosts", status_code=status.HTTP_201_CREATED, response_model=AdminDeviceOut, deprecated=True)
def admin_create_host_legacy(
    body: AdminDeviceCreate,
    user: Annotated[dict, Depends(require_admin)],
) -> AdminDeviceOut:
    return admin_create_device(body=body, current_user=user)


@app.get("/admin/assignments", response_model=list[AssignmentOut])
def admin_list_assignments(_: Annotated[dict, Depends(require_admin)]) -> list[AssignmentOut]:
    rows = list_assignments()
    return [
        AssignmentOut(
            user_id=row["user_id"],
            username=row["username"],
            device_id=row["device_id"],
            device_name=row["device_name"],
            created_at=row["created_at"],
        )
        for row in rows
    ]


@app.post("/admin/assignments", status_code=status.HTTP_201_CREATED)
def admin_create_assignment(
    body: AssignmentCreate,
    current_user: Annotated[dict, Depends(require_admin)],
) -> dict[str, str]:
    user = get_user_by_id(body.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    host = get_host_by_id(body.device_id)
    if not host:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    assign_device_to_user(user_id=body.user_id, device_id=body.device_id)
    log_admin_action(
        actor_username=current_user["username"],
        action="create_assignment",
        target_type="assignment",
        target_id=f"{body.user_id}:{body.device_id}",
        detail=None,
    )
    increment_counter("admin_action.create_assignment")
    return {"ok": "true"}


@app.delete("/admin/assignments/{user_id}/{device_id}")
def admin_delete_assignment(
    user_id: int,
    device_id: str,
    current_user: Annotated[dict, Depends(require_admin)],
) -> dict[str, bool]:
    deleted = remove_assignment(user_id=user_id, device_id=device_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assignment not found")
    log_admin_action(
        actor_username=current_user["username"],
        action="delete_assignment",
        target_type="assignment",
        target_id=f"{user_id}:{device_id}",
        detail=None,
    )
    increment_counter("admin_action.delete_assignment")
    return {"ok": True}


@app.post("/admin/invites", status_code=status.HTTP_201_CREATED, response_model=InviteCreateResponse)
def admin_create_invite(
    body: InviteCreate,
    current_user: Annotated[dict, Depends(require_admin)],
) -> InviteCreateResponse:
    user = get_user_by_username(body.username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Username not found")

    raw_token = secrets.token_urlsafe(24)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    invite_id = secrets.token_hex(16)
    now = datetime.now(UTC)
    expires_at = now + timedelta(hours=body.expires_in_hours)
    create_invite_token(
        invite_id=invite_id,
        token_hash=token_hash,
        username=body.username,
        backend_url_hint=body.backend_url_hint,
        expires_at=expires_at.isoformat(),
        created_by=current_user["username"],
    )
    log_admin_action(
        actor_username=current_user["username"],
        action="create_invite",
        target_type="invite",
        target_id=invite_id,
        detail=f"username={body.username}",
    )
    increment_counter("admin_action.create_invite")
    return InviteCreateResponse(
        id=invite_id,
        token=raw_token,
        username=body.username,
        backend_url_hint=body.backend_url_hint,
        expires_at=expires_at,
        claimed_at=None,
        created_by=current_user["username"],
        created_at=now,
    )


@app.get("/admin/invites", response_model=list[InviteOut])
def admin_list_invites(_: Annotated[dict, Depends(require_admin)]) -> list[InviteOut]:
    rows = list_invite_tokens()
    return [
        InviteOut(
            id=row["id"],
            username=row["username"],
            backend_url_hint=row["backend_url_hint"],
            expires_at=row["expires_at"],
            claimed_at=row["claimed_at"],
            created_by=row["created_by"],
            created_at=row["created_at"],
        )
        for row in rows
    ]


@app.post("/admin/invites/{invite_id}/revoke")
def admin_revoke_invite(
    invite_id: str,
    current_user: Annotated[dict, Depends(require_admin)],
) -> dict[str, bool]:
    revoked = revoke_invite(invite_id)
    if not revoked:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invite not found or already claimed")
    log_admin_action(
        actor_username=current_user["username"],
        action="revoke_invite",
        target_type="invite",
        target_id=invite_id,
        detail=None,
    )
    increment_counter("admin_action.revoke_invite")
    return {"ok": True}


@app.get("/admin/wake-logs")
def admin_wake_logs(_: Annotated[dict, Depends(require_admin)]) -> list[dict]:
    return [
        {
            "id": row["id"],
            "host_id": row["host_id"],
            "actor_username": row["actor_username"],
            "sent_to": row["sent_to"],
            "result": row["result"],
            "error_detail": row["error_detail"],
            "precheck_state": row["precheck_state"],
            "created_at": row["created_at"],
        }
        for row in list_wake_logs()
    ]


@app.get("/admin/power-check-logs")
def admin_power_check_logs(_: Annotated[dict, Depends(require_admin)]) -> list[dict]:
    return [
        {
            "id": row["id"],
            "device_id": row["device_id"],
            "method": row["method"],
            "result": row["result"],
            "detail": row["detail"],
            "latency_ms": row["latency_ms"],
            "created_at": row["created_at"],
        }
        for row in list_power_check_logs()
    ]


@app.get("/admin/audit-logs")
def admin_audit_logs(_: Annotated[dict, Depends(require_admin)]) -> list[dict]:
    return [
        {
            "id": row["id"],
            "actor_username": row["actor_username"],
            "action": row["action"],
            "target_type": row["target_type"],
            "target_id": row["target_id"],
            "detail": row["detail"],
            "created_at": row["created_at"],
        }
        for row in list_admin_audit_logs()
    ]


@app.get("/admin/metrics")
def admin_metrics(_: Annotated[dict, Depends(require_admin)]) -> dict:
    return {"counters": get_counters()}


@app.get("/admin/discovery/networks")
def admin_discovery_networks(_: Annotated[dict, Depends(require_admin)]) -> dict[str, object]:
    settings = get_settings()
    if not settings.discovery_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery disabled")
    snapshot = build_network_diagnostics_snapshot()
    bindings = discover_sender_bindings()
    network_counts: dict[str, int] = {}
    for row in bindings:
        network_cidr = str(row.get("network_cidr") or "")
        if not network_cidr:
            continue
        network_counts[network_cidr] = network_counts.get(network_cidr, 0) + 1
    warnings = [f"multiple_bindings_for_network:{cidr}" for cidr, count in network_counts.items() if count > 1]
    return {
        "discovered_at": snapshot.get("discovered_at"),
        "interfaces": snapshot.get("interfaces", []),
        "bindings": bindings,
        "warnings": warnings,
    }


@app.get("/admin/discovery/runs", response_model=list[DiscoveryRunOut])
def admin_list_discovery_runs(_: Annotated[dict, Depends(require_admin)]) -> list[DiscoveryRunOut]:
    settings = get_settings()
    if not settings.discovery_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery disabled")
    return [_discovery_run_to_out(dict(row)) for row in list_discovery_runs(limit=50)]


@app.post("/admin/discovery/runs", status_code=status.HTTP_202_ACCEPTED, response_model=DiscoveryRunOut)
def admin_start_discovery_run(
    body: DiscoveryRunCreate,
    background_tasks: BackgroundTasks,
    request: Request,
    current_user: Annotated[dict, Depends(require_admin)],
) -> DiscoveryRunOut:
    settings = get_settings()
    if not settings.discovery_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery disabled")
    ip = _get_request_ip(request) or "unknown"
    _enforce_rate_limit(
        "discovery",
        f"{current_user['username']}@{ip}",
        settings.discovery_rate_limit_per_minute,
        "Too many discovery runs",
    )

    fallback_bindings = discover_sender_bindings()
    source_bindings = normalize_source_bindings(
        source_bindings=[row.model_dump() for row in body.source_bindings],
        fallback_bindings=fallback_bindings,
    )
    selected_networks = {item.strip() for item in body.network_cidrs if item.strip()}
    if selected_networks:
        source_bindings = [row for row in source_bindings if str(row.get("network_cidr") or "") in selected_networks]
    if not source_bindings:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No valid source bindings available")

    power_ports = sorted({port for port in body.power_probe.ports if 1 <= port <= 65535})
    if not power_ports:
        power_ports = settings.discovery_default_tcp_ports_list
    options = {
        "network_cidrs": sorted(selected_networks),
        "source_bindings": source_bindings,
        "host_probe": {
            "enabled": body.host_probe.enabled,
            "timeout_ms": body.host_probe.timeout_ms,
            "max_hosts_per_network": body.host_probe.max_hosts_per_network,
        },
        "power_probe": {
            "ports": power_ports,
            "timeout_ms": body.power_probe.timeout_ms,
        },
    }
    run_id = create_discovery_run(
        requested_by=current_user["username"],
        options_json=json.dumps(options),
    )
    log_admin_action(
        actor_username=current_user["username"],
        action="start_discovery_run",
        target_type="discovery",
        target_id=run_id,
        detail=f"networks={len(options['source_bindings'])}",
    )
    background_tasks.add_task(_execute_discovery_run, run_id)
    row = get_discovery_run(run_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not create discovery run")
    return _discovery_run_to_out(dict(row))


@app.get("/admin/discovery/runs/{run_id}", response_model=DiscoveryRunOut)
def admin_get_discovery_run(run_id: str, _: Annotated[dict, Depends(require_admin)]) -> DiscoveryRunOut:
    settings = get_settings()
    if not settings.discovery_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery disabled")
    row = get_discovery_run(run_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery run not found")
    return _discovery_run_to_out(dict(row))


@app.get("/admin/discovery/runs/{run_id}/events")
def admin_get_discovery_events(run_id: str, _: Annotated[dict, Depends(require_admin)]) -> list[dict]:
    settings = get_settings()
    if not settings.discovery_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery disabled")
    if not get_discovery_run(run_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery run not found")
    return [
        {
            "id": row["id"],
            "run_id": row["run_id"],
            "candidate_id": row["candidate_id"],
            "event_type": row["event_type"],
            "detail": row["detail"],
            "created_at": row["created_at"],
        }
        for row in list_discovery_events(run_id, limit=500)
    ]


@app.get("/admin/discovery/runs/{run_id}/candidates", response_model=list[DiscoveryCandidateOut])
def admin_list_discovery_candidates(
    run_id: str,
    _: Annotated[dict, Depends(require_admin)],
    only_unimported: bool = False,
    wol_confidence: str | None = None,
    source_network_cidr: str | None = None,
) -> list[DiscoveryCandidateOut]:
    settings = get_settings()
    if not settings.discovery_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery disabled")
    if not get_discovery_run(run_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery run not found")
    rows = list_discovery_candidates(
        run_id=run_id,
        only_unimported=only_unimported,
        wol_confidence=wol_confidence,
        source_network_cidr=source_network_cidr,
    )
    mac_map: dict[str, tuple[str, str]] = {}
    for host in list_hosts():
        mac = str(host["mac"] or "")
        if mac and mac not in mac_map:
            mac_map[mac] = (str(host["id"]), str(host["name"]))
    out: list[DiscoveryCandidateOut] = []
    for row in rows:
        item = _discovery_candidate_to_out(dict(row))
        if item.mac and not item.imported_host_id:
            suggestion = mac_map.get(item.mac)
            if suggestion:
                item.suggested_host_id = suggestion[0]
                item.suggested_host_name = suggestion[1]
        out.append(item)
    return out


@app.post("/admin/discovery/candidates/{candidate_id}/validate-wake", response_model=DiscoveryValidateResponse)
def admin_validate_discovery_candidate_wake(
    candidate_id: str,
    current_user: Annotated[dict, Depends(require_admin)],
) -> DiscoveryValidateResponse:
    settings = get_settings()
    if not settings.discovery_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery disabled")
    candidate = get_discovery_candidate(candidate_id)
    if not candidate:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery candidate not found")

    run_id = candidate["run_id"]
    if not candidate["mac"]:
        detail = "missing_mac"
        log_discovery_event(run_id=run_id, candidate_id=candidate_id, event_type="validation", detail=detail)
        return DiscoveryValidateResponse(result="failed", detail=detail)

    target_ip = resolve_target(
        broadcast=candidate["broadcast_ip"],
        subnet_cidr=candidate["source_network_cidr"],
    )
    sent_ok, send_error = _send_magic_packet_with_retry(
        mac=candidate["mac"],
        target_ip=target_ip,
        udp_port=9,
        interface=candidate["source_interface"],
        source_ip=candidate["source_ip"],
    )
    if not sent_ok:
        detail = send_error or "wake_send_failed"
        log_discovery_event(run_id=run_id, candidate_id=candidate_id, event_type="validation", detail=detail)
        return DiscoveryValidateResponse(result="failed", detail=detail)

    if candidate["power_check_target"] and candidate["power_check_port"]:
        check = run_power_check(
            method="tcp",
            target=candidate["power_check_target"],
            port=candidate["power_check_port"],
            timeout_seconds=settings.power_check_timeout_seconds,
        )
        if check.result == "on":
            detail = f"validated:{check.detail}"
            log_discovery_event(run_id=run_id, candidate_id=candidate_id, event_type="validation", detail=detail)
            return DiscoveryValidateResponse(result="validated", detail=detail, latency_ms=check.latency_ms)
        detail = f"sent_not_validated:{check.detail}"
        log_discovery_event(run_id=run_id, candidate_id=candidate_id, event_type="validation", detail=detail)
        return DiscoveryValidateResponse(result="sent", detail=detail, latency_ms=check.latency_ms)

    detail = "magic_packet_sent"
    log_discovery_event(run_id=run_id, candidate_id=candidate_id, event_type="validation", detail=detail)
    return DiscoveryValidateResponse(result="sent", detail=detail)


@app.post("/admin/discovery/candidates/{candidate_id}/import", response_model=DiscoveryImportResponse)
def admin_import_discovery_candidate(
    candidate_id: str,
    body: DiscoveryImportRequest,
    current_user: Annotated[dict, Depends(require_admin)],
) -> DiscoveryImportResponse:
    settings = get_settings()
    if not settings.discovery_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery disabled")
    candidate = get_discovery_candidate(candidate_id)
    if not candidate:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery candidate not found")
    if candidate["imported_host_id"] and body.mode == "create_new":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Candidate already imported")
    run_id = candidate["run_id"]
    host_id, effective_mode = _import_discovery_candidate(
        dict(candidate),
        mode=body.mode,
        name=body.name,
        display_name=body.display_name,
        target_host_id=body.target_host_id,
        apply_power_settings=body.apply_power_settings,
        group_name=body.group_name,
    )

    mark_discovery_candidate_imported(candidate_id, host_id)
    log_discovery_event(
        run_id=run_id,
        candidate_id=candidate_id,
        event_type="import",
        detail=f"mode={body.mode} effective_mode={effective_mode} host_id={host_id}",
    )
    log_admin_action(
        actor_username=current_user["username"],
        action="import_discovery_candidate",
        target_type="discovery",
        target_id=candidate_id,
        detail=f"mode={body.mode} effective_mode={effective_mode} host_id={host_id}",
    )
    host = get_host_by_id(host_id)
    if not host:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Import failed")
    return DiscoveryImportResponse(candidate_id=candidate_id, mode=body.mode, host=_host_to_admin_out(dict(host)))


@app.post("/admin/discovery/runs/{run_id}/import-bulk", response_model=DiscoveryBulkImportResponse)
def admin_bulk_import_discovery_run(
    run_id: str,
    body: DiscoveryBulkImportRequest,
    current_user: Annotated[dict, Depends(require_admin)],
) -> DiscoveryBulkImportResponse:
    settings = get_settings()
    if not settings.discovery_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery disabled")
    run = get_discovery_run(run_id)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery run not found")
    candidates = list_discovery_candidates(run_id=run_id, only_unimported=True)
    processed = 0
    imported = 0
    merged = 0
    created = 0
    skipped = 0
    failed = 0
    details: list[dict] = []
    for row in candidates:
        candidate = dict(row)
        processed += 1
        candidate_id = str(candidate["id"])
        if not candidate.get("mac") and body.skip_without_mac:
            skipped += 1
            details.append({"candidate_id": candidate_id, "result": "skipped", "reason": "missing_mac"})
            continue
        try:
            host_id, effective_mode = _import_discovery_candidate(
                candidate,
                mode=body.mode,
                name=None,
                display_name=None,
                target_host_id=None,
                apply_power_settings=body.apply_power_settings,
                group_name=body.group_name,
                name_prefix=body.name_prefix,
            )
            mark_discovery_candidate_imported(candidate_id, host_id)
            log_discovery_event(
                run_id=run_id,
                candidate_id=candidate_id,
                event_type="import",
                detail=f"bulk mode={body.mode} effective_mode={effective_mode} host_id={host_id}",
            )
            imported += 1
            if effective_mode == "update_existing":
                merged += 1
            else:
                created += 1
            details.append(
                {
                    "candidate_id": candidate_id,
                    "result": "imported",
                    "effective_mode": effective_mode,
                    "host_id": host_id,
                }
            )
        except HTTPException as exc:
            failed += 1
            details.append({"candidate_id": candidate_id, "result": "failed", "reason": str(exc.detail)})
        except Exception as exc:
            failed += 1
            details.append({"candidate_id": candidate_id, "result": "failed", "reason": str(exc)})
    log_admin_action(
        actor_username=current_user["username"],
        action="bulk_import_discovery_run",
        target_type="discovery",
        target_id=run_id,
        detail=f"mode={body.mode} imported={imported} merged={merged} created={created} skipped={skipped} failed={failed}",
    )
    return DiscoveryBulkImportResponse(
        run_id=run_id,
        mode=body.mode,
        processed=processed,
        imported=imported,
        merged=merged,
        created=created,
        skipped=skipped,
        failed=failed,
        details=details,
    )


@app.get("/admin/diagnostics/devices")
def admin_device_diagnostics(_: Annotated[dict, Depends(require_admin)]) -> list[dict]:
    settings = get_settings()
    return [
        {
            "device_id": row["id"],
            "name": row["name"],
            "last_power_state": row["last_power_state"] or "unknown",
            "last_power_checked_at": row["last_power_checked_at"],
            "hints": device_diagnostic_hints(dict(row), stale_after_seconds=settings.power_state_stale_seconds * 3),
        }
        for row in list_hosts()
    ]


@app.get("/admin/diagnostics/network")
def admin_network_diagnostics(_: Annotated[dict, Depends(require_admin)]) -> dict[str, object]:
    if not _NETWORK_DIAGNOSTICS:
        _refresh_network_diagnostics()
    return _NETWORK_DIAGNOSTICS


def _parse_iso_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


@app.get("/admin/pilot-metrics")
def admin_pilot_metrics(_: Annotated[dict, Depends(require_admin)]) -> dict:
    claimed = list_claimed_invites(limit=5000)
    successful_wakes = list_successful_wakes(limit=20000)

    first_success_by_user: dict[str, datetime] = {}
    for row in successful_wakes:
        created = _parse_iso_dt(row["created_at"])
        if created is None:
            continue
        actor = str(row["actor_username"])
        if actor not in first_success_by_user:
            first_success_by_user[actor] = created

    total_claimed = 0
    success_within_2m = 0
    durations: list[float] = []
    per_user: list[dict] = []
    for row in claimed:
        username = str(row["username"])
        claimed_at = _parse_iso_dt(row["claimed_at"])
        if claimed_at is None:
            continue
        total_claimed += 1
        first_success = first_success_by_user.get(username)
        duration_seconds: float | None = None
        within_2m = False
        if first_success and first_success >= claimed_at:
            duration_seconds = (first_success - claimed_at).total_seconds()
            durations.append(duration_seconds)
            within_2m = duration_seconds <= 120
            if within_2m:
                success_within_2m += 1
        per_user.append(
            {
                "username": username,
                "claimed_at": row["claimed_at"],
                "first_successful_wake_at": first_success.isoformat() if first_success else None,
                "first_success_seconds": duration_seconds,
                "within_two_minutes": within_2m,
            }
        )

    completion_rate = (success_within_2m / total_claimed) if total_claimed else 0.0
    avg_seconds = (sum(durations) / len(durations)) if durations else None
    return {
        "total_claimed_users": total_claimed,
        "users_with_first_success_within_two_minutes": success_within_2m,
        "completion_rate_within_two_minutes": completion_rate,
        "target_met": completion_rate >= 0.9 if total_claimed else False,
        "average_seconds_to_first_success": avg_seconds,
        "users": per_user,
    }
