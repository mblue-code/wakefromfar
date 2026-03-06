from __future__ import annotations

import json
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .admin_ui import router as admin_ui_router
from .apns import APNSConfigurationError, APNSNotificationService
from .config import Settings, get_settings
from .diagnostics import device_diagnostic_hints
from .db import (
    assign_device_to_user,
    count_admin_users,
    create_host,
    create_discovery_candidate,
    create_discovery_run,
    create_activity_event,
    create_shutdown_poke_request,
    create_user,
    deactivate_notification_device,
    delete_host,
    delete_user,
    fail_discovery_run,
    get_assigned_host_by_id,
    get_discovery_candidate,
    get_discovery_run,
    get_host_by_mac,
    get_host_by_id,
    get_shutdown_poke_request,
    get_user_by_id,
    get_user_by_username,
    init_db,
    list_admin_audit_logs,
    list_assignments,
    list_discovery_candidates,
    list_discovery_events,
    list_discovery_runs,
    list_activity_events,
    list_shutdown_poke_requests,
    list_hosts,
    list_power_check_logs,
    list_users,
    list_wake_logs,
    list_assigned_hosts,
    log_admin_action,
    log_discovery_event,
    log_power_check,
    log_wake,
    mark_discovery_candidate_imported,
    mark_discovery_run_running,
    mark_shutdown_poke_resolved,
    mark_shutdown_poke_seen,
    remove_assignment,
    complete_discovery_run,
    upsert_notification_device,
    update_host,
    update_host_power_state,
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
from .password_policy import (
    MIN_ADMIN_PASSWORD_LENGTH,
    MIN_APP_SECRET_LENGTH,
    min_password_length_for_role,
    validate_password_for_role,
)
from .rate_limit import configure_rate_limiter, get_rate_limiter
from .request_context import get_request_ip, is_https_request, is_ip_in_networks
from .schemas import (
    AdminDeviceCreate,
    AdminDeviceOut,
    AdminDeviceUpdate,
    AdminUserCreate,
    AdminUserOut,
    AdminUserUpdate,
    APNSDeviceRegistrationRequest,
    AssignmentCreate,
    AssignmentOut,
    ActivityEventOut,
    DiscoveryCandidateOut,
    DiscoveryBulkImportRequest,
    DiscoveryBulkImportResponse,
    DiscoveryImportRequest,
    DiscoveryImportResponse,
    DiscoveryRunCreate,
    DiscoveryRunOut,
    DiscoveryValidateResponse,
    HostOut,
    LoginRequest,
    LoginResponse,
    MeWakeResponse,
    MyDeviceOut,
    NotificationDeviceOut,
    PowerCheckResponse,
    ShutdownPokeCreateRequest,
    ShutdownPokeOut,
    WakeResponse,
)
from .security import create_token, decode_token, hash_password, verify_password
from .telemetry import get_counters, increment_counter, structured_log
from .wol import normalize_mac, resolve_target, send_magic_packet

auth_scheme = HTTPBearer(auto_error=True)
_NETWORK_DIAGNOSTICS: dict[str, object] = {}
_UNSAFE_APP_SECRETS = {"change-me", "replace-with-a-random-long-secret"}
_UNSAFE_ADMIN_PASSWORDS = {"change-me-admin-password", "replace-with-strong-password"}
_ADMIN_UI_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'"
)


def _init_bootstrap() -> None:
    settings = get_settings()
    if settings.app_secret in _UNSAFE_APP_SECRETS:
        raise RuntimeError(
            "APP_SECRET uses an unsafe placeholder value. Set APP_SECRET to a random secret before startup."
        )
    if len(settings.app_secret) < MIN_APP_SECRET_LENGTH:
        raise RuntimeError(f"APP_SECRET is too short. Use at least {MIN_APP_SECRET_LENGTH} characters.")
    if settings.admin_pass and settings.admin_pass in _UNSAFE_ADMIN_PASSWORDS:
        raise RuntimeError(
            "ADMIN_PASS uses an unsafe placeholder value. Set ADMIN_PASS to a unique password before startup."
        )
    if settings.admin_pass and len(settings.admin_pass) < MIN_ADMIN_PASSWORD_LENGTH:
        raise RuntimeError(f"ADMIN_PASS is too short. Use at least {MIN_ADMIN_PASSWORD_LENGTH} characters.")
    if settings.apns_enabled:
        if not settings.apns_topic:
            raise RuntimeError("APNS_TOPIC must be set when APNS is enabled.")
        if not settings.apns_team_id or not settings.apns_key_id:
            raise RuntimeError("APNS_TEAM_ID and APNS_KEY_ID must be set when APNS is enabled.")
        if not settings.apns_private_key_text:
            raise RuntimeError("APNS private key material must be set when APNS is enabled.")
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


_DOCS_ENABLED = Settings().enable_api_docs
app = FastAPI(
    title="WoL Relay",
    version="0.1.0",
    lifespan=app_lifespan,
    docs_url="/docs" if _DOCS_ENABLED else None,
    redoc_url="/redoc" if _DOCS_ENABLED else None,
    openapi_url="/openapi.json" if _DOCS_ENABLED else None,
)
app.include_router(admin_ui_router)


@app.get("/favicon.ico", include_in_schema=False)
def favicon_ico() -> RedirectResponse:
    return RedirectResponse(url="/admin/ui/favicon.png", status_code=307)


@app.middleware("http")
async def allowlist_middleware(request: Request, call_next):
    settings = get_settings()
    if not settings.enforce_ip_allowlist:
        return await call_next(request)

    client_ip = get_request_ip(request, settings)
    if not client_ip:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing client IP")

    allowed = is_ip_in_networks(client_ip, settings.allowed_cidrs)

    if not allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Client IP not allowed")

    return await call_next(request)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/admin/ui"):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Content-Security-Policy", _ADMIN_UI_CSP)
        if is_https_request(request, get_settings()):
            response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
    return response


def _get_request_ip(request: Request) -> str | None:
    return get_request_ip(request, get_settings())


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


@app.get("/")
def root():
    return RedirectResponse("/admin/ui/login", status_code=302)


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
    token_version = int(user["token_version"] or 0)
    try:
        payload_version = int(payload.get("ver", 0))
    except (TypeError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    if payload_version != token_version:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired. Please log in again.")
    return {"id": user["id"], "username": user["username"], "role": user["role"]}


def require_admin(current_user: Annotated[dict, Depends(get_current_user)]) -> dict:
    if current_user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return current_user


_ACTIVITY_TYPE_FILTER_MAP: dict[str, tuple[str, ...]] = {
    "wake": ("wake_sent", "wake_failed", "wake_already_on"),
    "poke": ("shutdown_poke_requested", "shutdown_poke_seen", "shutdown_poke_resolved"),
    "error": ("wake_failed",),
}


def _host_label(host_row: dict) -> str:
    def _row_get(key: str):
        if isinstance(host_row, dict):
            return host_row.get(key)
        try:
            return host_row[key]  # type: ignore[index]
        except Exception:
            return None

    display_name = str(_row_get("display_name") or "").strip()
    if display_name:
        return display_name
    name = str(_row_get("name") or "").strip()
    if name:
        return name
    return str(_row_get("id") or "device")


def _emit_activity_event(
    *,
    event_type: str,
    actor: dict | None,
    target_type: str,
    target_id: str | None,
    server_id: str | None,
    summary: str,
    metadata: dict[str, object] | None = None,
) -> None:
    metadata_json = None
    if metadata:
        metadata_json = json.dumps(metadata, separators=(",", ":"))
    create_activity_event(
        event_type=event_type,
        actor_user_id=actor["id"] if actor else None,
        actor_username=actor["username"] if actor else None,
        target_type=target_type,
        target_id=target_id,
        server_id=server_id,
        summary=summary,
        metadata_json=metadata_json,
    )
    increment_counter("activity_events.created")


def _parse_activity_type_filters(raw: str | None) -> list[str] | None:
    if not raw:
        return None
    tokens = [part.strip().lower() for part in raw.split(",") if part.strip()]
    if not tokens or "all" in tokens:
        return None
    invalid = sorted({token for token in tokens if token not in _ACTIVITY_TYPE_FILTER_MAP})
    if invalid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported activity filter(s): {','.join(invalid)}",
        )
    event_types: set[str] = set()
    for token in tokens:
        event_types.update(_ACTIVITY_TYPE_FILTER_MAP[token])
    return sorted(event_types)


def _shutdown_poke_device_label(row: dict) -> str:
    def _row_get(key: str):
        if isinstance(row, dict):
            return row.get(key)
        try:
            return row[key]  # type: ignore[index]
        except Exception:
            return None

    display_name = str(_row_get("device_display_name") or "").strip()
    if display_name:
        return display_name
    name = str(_row_get("device_name") or "").strip()
    if name:
        return name
    return str(_row_get("server_id") or "device")


def _shutdown_poke_to_out(row: dict) -> ShutdownPokeOut:
    return ShutdownPokeOut(
        id=row["id"],
        server_id=row["server_id"],
        device_name=row["device_name"],
        device_display_name=row["device_display_name"],
        requester_user_id=row["requester_user_id"],
        requester_username=row["requester_username"],
        message=row["message"],
        status=row["status"],
        created_at=row["created_at"],
        seen_at=row["seen_at"],
        resolved_at=row["resolved_at"],
        resolved_by_user_id=row["resolved_by_user_id"],
        resolved_by_username=row["resolved_by_username"],
    )


def _notification_device_to_out(row: dict) -> NotificationDeviceOut:
    return NotificationDeviceOut(
        installation_id=row["installation_id"],
        platform=row["platform"],
        provider=row["provider"],
        app_bundle_id=row["app_bundle_id"],
        environment=row["environment"],
        is_active=bool(row["is_active"]),
        updated_at=row["updated_at"],
    )


def _get_apns_notification_service() -> APNSNotificationService:
    return APNSNotificationService(settings=get_settings())


def _dispatch_shutdown_poke_admin_notifications() -> None:
    settings = get_settings()
    if not settings.apns_enabled:
        return
    try:
        result = _get_apns_notification_service().send_admin_shutdown_request_alerts()
    except APNSConfigurationError as exc:
        increment_counter("apns.shutdown_request.config_error")
        structured_log("apns.shutdown_request.config_error", error=str(exc))
        return
    except Exception as exc:  # pragma: no cover
        increment_counter("apns.shutdown_request.dispatch_error")
        structured_log("apns.shutdown_request.dispatch_error", error=str(exc))
        return

    for _ in range(result.sent_count):
        increment_counter("apns.shutdown_request.sent")
    for _ in range(result.suppressed_count):
        increment_counter("apns.shutdown_request.suppressed")
    for _ in range(result.invalidated_count):
        increment_counter("apns.shutdown_request.invalidated")
    for _ in range(result.failed_count):
        increment_counter("apns.shutdown_request.failed")
    structured_log(
        "apns.shutdown_request.dispatched",
        sent_count=result.sent_count,
        suppressed_count=result.suppressed_count,
        invalidated_count=result.invalidated_count,
        failed_count=result.failed_count,
    )


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

    token, expires_in = create_token(
        username=user["username"],
        role=user["role"],
        token_version=int(user["token_version"] or 0),
    )
    increment_counter("login.success")
    structured_log("login.success", ip=ip, username=user["username"], role=user["role"])
    return LoginResponse(token=token, expires_in=expires_in)


@app.post("/onboarding/claim")
def onboarding_claim_disabled() -> dict[str, str]:
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail="Invite onboarding is disabled. Ask your admin for credentials and backend URL.",
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
def me_wake(
    host_id: str,
    request: Request,
    current_user: Annotated[dict, Depends(get_current_user)],
) -> MeWakeResponse:
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
    host_name = _host_label(host)
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
        _emit_activity_event(
            event_type="wake_already_on",
            actor=current_user,
            target_type="device",
            target_id=host_id,
            server_id=host_id,
            summary=f"{current_user['username']} woke {host_name} (already on)",
            metadata={
                "result": "already_on",
                "precheck_state": "on",
            },
        )
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
        _emit_activity_event(
            event_type="wake_failed",
            actor=current_user,
            target_type="device",
            target_id=host_id,
            server_id=host_id,
            summary=f"{current_user['username']} failed to wake {host_name}",
            metadata={
                "result": "failed",
                "precheck_state": precheck.result,
                "sent_to": sent_to,
                "error_detail": send_error or "",
            },
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
    _emit_activity_event(
        event_type="wake_sent",
        actor=current_user,
        target_type="device",
        target_id=host_id,
        server_id=host_id,
        summary=f"{current_user['username']} woke {host_name}",
        metadata={
            "result": "sent",
            "precheck_state": precheck.result,
            "precheck_detail": precheck.detail,
            "sent_to": sent_to,
        },
    )
    return MeWakeResponse(
        device_id=host_id,
        result="sent",
        message=wake_message,
        precheck_state=precheck.result,
        sent_to=sent_to,
        timestamp=now,
    )


@app.post("/me/notification-devices/apns", response_model=NotificationDeviceOut)
def me_register_apns_notification_device(
    body: APNSDeviceRegistrationRequest,
    current_user: Annotated[dict, Depends(get_current_user)],
) -> NotificationDeviceOut:
    row = upsert_notification_device(
        user_id=int(current_user["id"]),
        installation_id=body.installation_id,
        platform="ios",
        provider="apns",
        token=body.token,
        app_bundle_id=body.app_bundle_id,
        environment=body.environment,
    )
    increment_counter("apns.device.registered")
    structured_log(
        "apns.device.registered",
        user_id=current_user["id"],
        username=current_user["username"],
        installation_id=body.installation_id,
        environment=body.environment,
    )
    return _notification_device_to_out(row)


@app.delete(
    "/me/notification-devices/apns/{installation_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
def me_delete_apns_notification_device(
    installation_id: str,
    current_user: Annotated[dict, Depends(get_current_user)],
) -> None:
    deactivated = deactivate_notification_device(
        user_id=int(current_user["id"]),
        installation_id=installation_id,
        provider="apns",
    )
    if deactivated:
        increment_counter("apns.device.deactivated")
        structured_log(
            "apns.device.deactivated",
            user_id=current_user["id"],
            username=current_user["username"],
            installation_id=installation_id,
        )


@app.post("/me/devices/{host_id}/shutdown-poke", status_code=status.HTTP_201_CREATED, response_model=ShutdownPokeOut)
def me_shutdown_poke(
    host_id: str,
    background_tasks: BackgroundTasks,
    request: Request,
    current_user: Annotated[dict, Depends(get_current_user)],
    body: ShutdownPokeCreateRequest | None = None,
) -> ShutdownPokeOut:
    settings = get_settings()
    ip = _get_request_ip(request) or "unknown"
    _enforce_rate_limit(
        "shutdown_poke_request",
        f"{current_user['username']}@{ip}",
        settings.shutdown_poke_request_rate_limit_per_minute,
        "Too many shutdown requests",
    )
    host = _get_authorized_host(current_user=current_user, host_id=host_id)
    host_name = _host_label(host)
    message = (body.message if body else None) or None
    row = create_shutdown_poke_request(
        server_id=host_id,
        requester_user_id=int(current_user["id"]),
        requester_username=str(current_user["username"]),
        message=message,
    )
    poke_id = str(row["id"])
    _emit_activity_event(
        event_type="shutdown_poke_requested",
        actor=current_user,
        target_type="request",
        target_id=poke_id,
        server_id=host_id,
        summary=f"{current_user['username']} requested shutdown for {host_name}",
        metadata={
            "status": "open",
            "poke_id": poke_id,
            "message": str(row["message"] or ""),
        },
    )
    increment_counter("shutdown_poke.requested")
    increment_counter("shutdown_pokes.open")
    structured_log(
        "shutdown_poke.requested",
        actor=current_user["username"],
        poke_id=poke_id,
        device_id=host_id,
    )
    background_tasks.add_task(_dispatch_shutdown_poke_admin_notifications)
    return _shutdown_poke_to_out(row)


@app.get("/admin/shutdown-pokes", response_model=list[ShutdownPokeOut])
def admin_list_shutdown_pokes(
    _: Annotated[dict, Depends(require_admin)],
    status_filter: Annotated[Literal["open", "seen", "resolved"] | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[ShutdownPokeOut]:
    rows = list_shutdown_poke_requests(status_filter=status_filter, limit=limit)
    return [_shutdown_poke_to_out(row) for row in rows]


@app.post("/admin/shutdown-pokes/{poke_id}/seen", response_model=ShutdownPokeOut)
def admin_mark_shutdown_poke_seen(
    poke_id: str,
    request: Request,
    current_user: Annotated[dict, Depends(require_admin)],
) -> ShutdownPokeOut:
    settings = get_settings()
    ip = _get_request_ip(request) or "unknown"
    _enforce_rate_limit(
        "shutdown_poke_seen",
        f"{current_user['username']}@{ip}",
        settings.shutdown_poke_seen_rate_limit_per_minute,
        "Too many shutdown seen updates",
    )
    row = get_shutdown_poke_request(poke_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Shutdown poke not found")
    if row["status"] == "open":
        updated = mark_shutdown_poke_seen(poke_id=poke_id)
        if not updated:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Shutdown poke not found")
        row = updated
        device_label = _shutdown_poke_device_label(row)
        _emit_activity_event(
            event_type="shutdown_poke_seen",
            actor=current_user,
            target_type="request",
            target_id=poke_id,
            server_id=row["server_id"],
            summary=f"{current_user['username']} marked shutdown request for {device_label} as seen",
            metadata={"status": "seen", "poke_id": poke_id},
        )
        log_admin_action(
            actor_username=current_user["username"],
            action="seen_shutdown_poke",
            target_type="shutdown_poke",
            target_id=poke_id,
            detail=f"server_id={row['server_id']}",
        )
        increment_counter("shutdown_poke.seen")
        structured_log(
            "shutdown_poke.seen",
            actor=current_user["username"],
            poke_id=poke_id,
            device_id=row["server_id"],
        )
    return _shutdown_poke_to_out(row)


@app.post("/admin/shutdown-pokes/{poke_id}/resolve", response_model=ShutdownPokeOut)
def admin_mark_shutdown_poke_resolved(
    poke_id: str,
    request: Request,
    current_user: Annotated[dict, Depends(require_admin)],
) -> ShutdownPokeOut:
    settings = get_settings()
    ip = _get_request_ip(request) or "unknown"
    _enforce_rate_limit(
        "shutdown_poke_resolve",
        f"{current_user['username']}@{ip}",
        settings.shutdown_poke_resolve_rate_limit_per_minute,
        "Too many shutdown resolve updates",
    )
    row = get_shutdown_poke_request(poke_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Shutdown poke not found")
    if row["status"] != "resolved":
        updated = mark_shutdown_poke_resolved(poke_id=poke_id, actor_user_id=int(current_user["id"]))
        if not updated:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Shutdown poke not found")
        row = updated
        device_label = _shutdown_poke_device_label(row)
        _emit_activity_event(
            event_type="shutdown_poke_resolved",
            actor=current_user,
            target_type="request",
            target_id=poke_id,
            server_id=row["server_id"],
            summary=f"{current_user['username']} resolved shutdown request for {device_label}",
            metadata={"status": "resolved", "poke_id": poke_id},
        )
        log_admin_action(
            actor_username=current_user["username"],
            action="resolve_shutdown_poke",
            target_type="shutdown_poke",
            target_id=poke_id,
            detail=f"server_id={row['server_id']}",
        )
        increment_counter("shutdown_poke.resolved")
        increment_counter("shutdown_pokes.resolved")
        structured_log(
            "shutdown_poke.resolved",
            actor=current_user["username"],
            poke_id=poke_id,
            device_id=row["server_id"],
        )
    return _shutdown_poke_to_out(row)


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
    try:
        validate_password_for_role(body.password, body.role)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

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

    target_role = str(changes.get("role") or current["role"])
    if "role" in changes:
        new_role = str(changes["role"])
        if current["role"] == "admin" and new_role != "admin" and count_admin_users() <= 1:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot demote last admin")
        update_user_role(user_id=user_id, role=new_role)

    if target_role == "admin" and current["role"] != "admin" and "password" not in changes:
        required = min_password_length_for_role("admin")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Promoting a user to admin requires setting a new password with at least {required} characters.",
        )

    if "password" in changes:
        password_value = changes["password"]
        if password_value is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password cannot be null")
        try:
            validate_password_for_role(str(password_value), target_role)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        update_user_password_by_id(user_id=user_id, password_hash=hash_password(str(password_value)))

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


@app.post("/admin/invites")
def admin_create_invite_disabled(_: Annotated[dict, Depends(require_admin)]) -> dict[str, str]:
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail="Invite management is disabled. Create users manually and share credentials securely.",
    )


@app.get("/admin/invites")
def admin_list_invites_disabled(_: Annotated[dict, Depends(require_admin)]) -> dict[str, str]:
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail="Invite management is disabled. Create users manually and share credentials securely.",
    )


@app.post("/admin/invites/{invite_id}/revoke")
def admin_revoke_invite_disabled(
    invite_id: str,
    _: Annotated[dict, Depends(require_admin)],
) -> dict[str, str]:
    del invite_id
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail="Invite management is disabled. Create users manually and share credentials securely.",
    )


@app.get("/admin/mobile/events", response_model=list[ActivityEventOut])
def admin_mobile_events(
    _: Annotated[dict, Depends(require_admin)],
    cursor: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    type_filter: Annotated[str | None, Query(alias="type")] = None,
) -> list[ActivityEventOut]:
    increment_counter("activity_feed.poll_requests")
    event_types = _parse_activity_type_filters(type_filter)
    try:
        rows = list_activity_events(limit=limit, cursor_id=cursor, event_types=event_types)
    except Exception as exc:
        increment_counter("activity_feed.poll_errors")
        structured_log(
            "activity_feed.poll_error",
            error=str(exc),
            cursor=cursor,
            limit=limit,
            type_filter=type_filter or "",
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not load activity events")
    return [
        ActivityEventOut(
            id=row["id"],
            event_type=row["event_type"],
            actor_user_id=row["actor_user_id"],
            actor_username=row["actor_username"],
            target_type=row["target_type"],
            target_id=row["target_id"],
            server_id=row["server_id"],
            summary=row["summary"],
            metadata=_parse_json_dict(row["metadata_json"]) if row["metadata_json"] else None,
            created_at=row["created_at"],
        )
        for row in rows
    ]


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


@app.get("/admin/pilot-metrics")
def admin_pilot_metrics_disabled(_: Annotated[dict, Depends(require_admin)]) -> dict[str, str]:
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail="Pilot metrics are disabled because invite onboarding has been removed.",
    )
