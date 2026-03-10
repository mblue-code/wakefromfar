from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .admin_ui import enforce_admin_ui_post_request, router as admin_ui_router
from .app_proof import APP_PROOF_HEADER, AppProofError, AppProofService
from .apns import APNSConfigurationError, APNSNotificationService
from .config import Settings, get_settings
from .diagnostics import device_diagnostic_hints
from .db import (
    count_admin_users,
    get_app_installation,
    create_host,
    create_device_membership,
    create_discovery_candidate,
    create_discovery_run,
    create_activity_event,
    create_scheduled_wake_job,
    create_shutdown_poke_request,
    create_user,
    delete_scheduled_wake_job,
    deactivate_notification_device,
    delete_device_membership,
    delete_host,
    delete_user,
    fail_discovery_run,
    get_discovery_candidate,
    get_discovery_run,
    get_device_membership_by_id,
    get_device_membership_for_user_device,
    get_device_for_user_preferences,
    get_scheduled_wake_job,
    get_host_by_mac,
    get_host_by_id,
    get_shutdown_poke_request,
    get_user_by_id,
    get_user_by_username,
    init_db,
    list_admin_audit_logs,
    list_all_devices_for_user_preferences,
    list_device_memberships,
    list_discovery_candidates,
    list_discovery_events,
    list_discovery_runs,
    list_activity_events,
    list_app_installations,
    list_due_scheduled_wake_jobs,
    list_scheduled_wake_jobs,
    list_scheduled_wake_runs,
    list_shutdown_poke_requests,
    list_hosts,
    list_power_check_logs,
    list_users,
    list_wake_logs,
    get_visible_device_for_user,
    list_visible_devices_for_user,
    log_admin_action,
    log_discovery_event,
    log_power_check,
    log_wake,
    mark_scheduled_wake_job_executed,
    mark_discovery_candidate_imported,
    mark_discovery_run_running,
    claim_scheduled_wake_job,
    record_scheduled_wake_run,
    revoke_app_installation,
    mark_shutdown_poke_resolved,
    mark_shutdown_poke_seen,
    complete_discovery_run,
    upsert_notification_device,
    update_scheduled_wake_job,
    update_device_membership,
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
from .request_context import (
    AUTHENTICATED_TLS_REQUIRED_DETAIL,
    LOGIN_TLS_REQUIRED_DETAIL,
    get_request_ip,
    is_auth_transport_allowed,
    is_https_request,
    is_ip_in_networks,
    parse_cidrs,
)
from .schemas import (
    AdminDeviceCreate,
    AdminDeviceOut,
    AdminDeviceUpdate,
    AndroidAppProofVerifyRequest,
    AdminUserCreate,
    AdminUserOut,
    AdminUserUpdate,
    APNSDeviceRegistrationRequest,
    ActivityEventOut,
    AppInstallationOut,
    AppInstallationRevokeRequest,
    AppProofChallengeRequest,
    AppProofChallengeResponse,
    AppProofVerifyResponse,
    DeviceMembershipCreate,
    DeviceMembershipOut,
    DeviceMembershipUpdate,
    DevicePermissionsOut,
    DiscoveryCandidateOut,
    DiscoveryBulkImportRequest,
    DiscoveryBulkImportResponse,
    DiscoveryImportRequest,
    DiscoveryImportResponse,
    DiscoveryRunCreate,
    DiscoveryRunOut,
    DiscoveryValidateResponse,
    IOSAppProofVerifyRequest,
    LoginRequest,
    LoginResponse,
    MeWakeResponse,
    MyDeviceOut,
    MyDevicePreferencesUpdate,
    NotificationDeviceOut,
    PowerCheckResponse,
    SecurityStatusOut,
    ScheduledWakeCreate,
    ScheduledWakeOut,
    ScheduledWakeRunOut,
    ScheduledWakeSummaryOut,
    ScheduledWakeUpdate,
    ShutdownPokeCreateRequest,
    ShutdownPokeOut,
)
from .security_status import build_security_status
from .scheduled_wakes import compute_next_run_at_iso, normalize_schedule_definition, parse_days_of_week_json
from .security import create_token, decode_token, hash_password, verify_password
from .telemetry import get_counters, get_recent_events, increment_counter, structured_log
from .wol import normalize_mac, resolve_target, send_magic_packet

auth_scheme = HTTPBearer(auto_error=True)
_NETWORK_DIAGNOSTICS: dict[str, object] = {}
_UNSAFE_APP_SECRETS = {"change-me", "replace-with-a-random-long-secret"}
_UNSAFE_ADMIN_PASSWORDS = {"change-me-admin-password", "replace-with-strong-password"}
_ADMIN_NETWORK_DENIED_DETAIL = "Admin access is not allowed from this network"
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
_SCHEDULED_WAKE_RUNNER_LOCK = asyncio.Lock()


@dataclass
class _WakeExecutionOutcome:
    result: Literal["already_on", "sent", "failed"]
    message: str
    detail: str
    precheck_state: Literal["on", "off", "unknown"]
    precheck_detail: str
    sent_to: str | None
    error_detail: str | None
    wake_log_id: int | None


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
    _validate_network_exposure_settings(settings)
    _validate_auth_transport_settings(settings)
    _validate_app_proof_settings(settings)
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


def _validate_network_exposure_settings(settings: Settings) -> None:
    if not settings.enforce_ip_allowlist:
        if settings.allow_unsafe_public_exposure:
            return
        raise RuntimeError(
            "Refusing to start with ENFORCE_IP_ALLOWLIST=false unless "
            "ALLOW_UNSAFE_PUBLIC_EXPOSURE=true is explicitly set."
        )

    allowed_cidrs = settings.allowed_cidrs
    if not allowed_cidrs:
        raise RuntimeError(
            "IP_ALLOWLIST_CIDRS is empty. Set IP_ALLOWLIST_CIDRS to a comma-separated list of valid CIDRs "
            "or set ENFORCE_IP_ALLOWLIST=false and ALLOW_UNSAFE_PUBLIC_EXPOSURE=true to acknowledge unsafe "
            "exposure."
        )

    valid_cidrs, invalid_cidrs = parse_cidrs(allowed_cidrs)
    if invalid_cidrs:
        invalid_values = ", ".join(invalid_cidrs)
        if not valid_cidrs:
            raise RuntimeError(
                "IP_ALLOWLIST_CIDRS did not contain any valid CIDRs. Invalid entries: "
                f"{invalid_values}. Set a valid allowlist or set ENFORCE_IP_ALLOWLIST=false and "
                "ALLOW_UNSAFE_PUBLIC_EXPOSURE=true to acknowledge unsafe exposure."
            )
        raise RuntimeError(
            f"IP_ALLOWLIST_CIDRS contains invalid CIDR entries: {invalid_values}. Set IP_ALLOWLIST_CIDRS "
            "to a comma-separated list of valid CIDRs or set ENFORCE_IP_ALLOWLIST=false and "
            "ALLOW_UNSAFE_PUBLIC_EXPOSURE=true to acknowledge unsafe exposure."
        )
    if not valid_cidrs:
        raise RuntimeError(
            "IP_ALLOWLIST_CIDRS did not contain any valid CIDRs. Set a valid allowlist or set "
            "ENFORCE_IP_ALLOWLIST=false and ALLOW_UNSAFE_PUBLIC_EXPOSURE=true to acknowledge unsafe "
            "exposure."
        )
    _validate_admin_network_settings(settings)


def _validate_admin_network_settings(settings: Settings) -> None:
    admin_cidrs = settings.admin_allowed_cidrs_list
    if not admin_cidrs:
        if settings.allow_unsafe_public_exposure:
            return
        raise RuntimeError(
            "ADMIN_IP_ALLOWLIST_CIDRS is empty. Set ADMIN_IP_ALLOWLIST_CIDRS to a comma-separated list of valid "
            "CIDRs or set ALLOW_UNSAFE_PUBLIC_EXPOSURE=true to acknowledge an unsafe admin-plane configuration."
        )

    valid_cidrs, invalid_cidrs = parse_cidrs(admin_cidrs)
    if invalid_cidrs:
        invalid_values = ", ".join(invalid_cidrs)
        if settings.allow_unsafe_public_exposure:
            return
        if not valid_cidrs:
            raise RuntimeError(
                "ADMIN_IP_ALLOWLIST_CIDRS did not contain any valid CIDRs. Invalid entries: "
                f"{invalid_values}. Set ADMIN_IP_ALLOWLIST_CIDRS to a comma-separated list of valid CIDRs or set "
                "ALLOW_UNSAFE_PUBLIC_EXPOSURE=true to acknowledge an unsafe admin-plane configuration."
            )
        raise RuntimeError(
            "ADMIN_IP_ALLOWLIST_CIDRS contains invalid CIDR entries: "
            f"{invalid_values}. Set ADMIN_IP_ALLOWLIST_CIDRS to a comma-separated list of valid CIDRs or set "
            "ALLOW_UNSAFE_PUBLIC_EXPOSURE=true to acknowledge an unsafe admin-plane configuration."
        )
    if not valid_cidrs and not settings.allow_unsafe_public_exposure:
        raise RuntimeError(
            "ADMIN_IP_ALLOWLIST_CIDRS did not contain any valid CIDRs. Set ADMIN_IP_ALLOWLIST_CIDRS to a "
            "comma-separated list of valid CIDRs or set ALLOW_UNSAFE_PUBLIC_EXPOSURE=true to acknowledge an "
            "unsafe admin-plane configuration."
        )


def _validate_app_proof_settings(settings: Settings) -> None:
    if settings.app_proof_challenge_ttl_seconds <= 0:
        raise RuntimeError("APP_PROOF_CHALLENGE_TTL_SECONDS must be greater than 0.")
    if settings.app_proof_degraded_grace_seconds < 0:
        raise RuntimeError("APP_PROOF_DEGRADED_GRACE_SECONDS must be 0 or greater.")
    if settings.app_proof_provider_timeout_seconds <= 0:
        raise RuntimeError("APP_PROOF_PROVIDER_TIMEOUT_SECONDS must be greater than 0.")
    if settings.app_proof_mode == "disabled":
        return
    if settings.app_proof_android_enabled:
        if not settings.app_proof_android_package_name:
            raise RuntimeError("APP_PROOF_ANDROID_PACKAGE_NAME must be set when app proof is enabled.")
        if settings.app_proof_android_require_play_recognized and not settings.app_proof_android_allowed_cert_sha256_list:
            raise RuntimeError(
                "APP_PROOF_ANDROID_ALLOWED_CERT_SHA256 must contain at least one signing certificate digest "
                "when Android app proof is enabled."
            )
    if settings.app_proof_ios_enabled:
        if not settings.app_proof_ios_team_id or not settings.app_proof_ios_bundle_id:
            raise RuntimeError(
                "APP_PROOF_IOS_TEAM_ID and APP_PROOF_IOS_BUNDLE_ID must be set when iOS app proof is enabled."
            )


def _validate_auth_transport_settings(settings: Settings) -> None:
    if not settings.allow_insecure_private_http:
        return
    _, invalid_cidrs = parse_cidrs(settings.private_http_allowed_cidrs_list)
    if invalid_cidrs:
        invalid_values = ", ".join(invalid_cidrs)
        raise RuntimeError(
            "PRIVATE_HTTP_ALLOWED_CIDRS contains invalid CIDR entries: "
            f"{invalid_values}. Set PRIVATE_HTTP_ALLOWED_CIDRS to a comma-separated list of valid CIDRs."
        )


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
    runner_task: asyncio.Task[None] | None = None
    settings = get_settings()
    if settings.scheduled_wake_runner:
        runner_task = asyncio.create_task(_scheduled_wake_runner_loop())
    try:
        yield
    finally:
        if runner_task is not None:
            runner_task.cancel()
            with suppress(asyncio.CancelledError):
                await runner_task


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


def _path_matches_prefix(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix + "/")


def _is_admin_ui_path(path: str) -> bool:
    return _path_matches_prefix(path, "/admin/ui")


def _is_admin_plane_path(path: str) -> bool:
    return _path_matches_prefix(path, "/admin")


def _is_request_on_admin_allowed_network(request: Request) -> bool:
    settings = get_settings()
    client_ip = get_request_ip(request, settings)
    if not client_ip:
        return False
    try:
        admin_cidrs = settings.parsed_admin_allowed_cidrs
    except ValueError:
        return False
    return is_ip_in_networks(client_ip, admin_cidrs)


def _json_error(status_code: int, detail: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"detail": detail})


def _record_security_block(
    request: Request,
    *,
    counter: str,
    event: str,
    detail: str,
    reason: str,
) -> None:
    increment_counter(counter)
    structured_log(
        event,
        path=request.url.path,
        method=request.method,
        client_ip=_get_request_ip(request) or "unknown",
        detail=detail,
        reason=reason,
    )


def _security_status_payload() -> SecurityStatusOut:
    settings = get_settings()
    installation_rows = [dict(row) for row in list_app_installations(limit=200)]
    recent_events = get_recent_events(limit=200)
    return build_security_status(
        settings=settings,
        counters=get_counters(),
        installation_rows=installation_rows,
        recent_events=recent_events,
    )


async def _enforce_admin_ui_post_guard(request: Request):
    if request.method != "POST" or not _is_admin_ui_path(request.url.path):
        return None
    try:
        await enforce_admin_ui_post_request(request)
    except HTTPException as exc:
        return PlainTextResponse(str(exc.detail), status_code=exc.status_code)
    return None


@app.get("/favicon.ico", include_in_schema=False)
def favicon_ico():
    if not get_settings().admin_ui_enabled:
        return PlainTextResponse("Not Found", status_code=404)
    return RedirectResponse(url="/admin/ui/favicon.png", status_code=307)


@app.middleware("http")
async def allowlist_middleware(request: Request, call_next):
    settings = get_settings()
    if _is_admin_ui_path(request.url.path) and not settings.admin_ui_enabled:
        return PlainTextResponse("Not Found", status_code=404)

    if not settings.enforce_ip_allowlist:
        if _is_admin_plane_path(request.url.path) and not _is_request_on_admin_allowed_network(request):
            _record_security_block(
                request,
                counter="security.admin_network.blocked",
                event="security.admin_network.blocked",
                detail=_ADMIN_NETWORK_DENIED_DETAIL,
                reason="admin_allowlist_miss",
            )
            return _json_error(status.HTTP_403_FORBIDDEN, _ADMIN_NETWORK_DENIED_DETAIL)
        admin_ui_post_guard = await _enforce_admin_ui_post_guard(request)
        if admin_ui_post_guard is not None:
            return admin_ui_post_guard
        return await call_next(request)

    client_ip = get_request_ip(request, settings)
    if not client_ip:
        _record_security_block(
            request,
            counter="security.ip_allowlist.blocked",
            event="security.ip_allowlist.blocked",
            detail="Missing client IP",
            reason="missing_client_ip",
        )
        return _json_error(status.HTTP_403_FORBIDDEN, "Missing client IP")

    allowed = is_ip_in_networks(client_ip, settings.allowed_cidrs)

    if not allowed:
        _record_security_block(
            request,
            counter="security.ip_allowlist.blocked",
            event="security.ip_allowlist.blocked",
            detail="Client IP not allowed",
            reason="allowlist_miss",
        )
        return _json_error(status.HTTP_403_FORBIDDEN, "Client IP not allowed")

    if _is_admin_plane_path(request.url.path) and not _is_request_on_admin_allowed_network(request):
        _record_security_block(
            request,
            counter="security.admin_network.blocked",
            event="security.admin_network.blocked",
            detail=_ADMIN_NETWORK_DENIED_DETAIL,
            reason="admin_allowlist_miss",
        )
        return _json_error(status.HTTP_403_FORBIDDEN, _ADMIN_NETWORK_DENIED_DETAIL)

    admin_ui_post_guard = await _enforce_admin_ui_post_guard(request)
    if admin_ui_post_guard is not None:
        return admin_ui_post_guard

    return await call_next(request)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/admin/ui"):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Content-Security-Policy", _ADMIN_UI_CSP)
        if is_https_request(request, get_settings()):
            response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
    return response


def _get_request_ip(request: Request) -> str | None:
    return get_request_ip(request, get_settings())


def _app_proof_service() -> AppProofService:
    return AppProofService(get_settings())


def _parse_json_dict(value: str | None) -> dict[str, object] | None:
    if not value:
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _serialize_app_installation(row) -> AppInstallationOut:
    return AppInstallationOut(
        installation_id=row["installation_id"],
        platform=row["platform"],
        status=row["status"],
        user_id=row["user_id"],
        session_version=int(row["session_version"] or 0),
        proof_method=row["proof_method"],
        app_id=row["app_id"],
        app_version=row["app_version"],
        os_version=row["os_version"],
        last_verified_at=row["last_verified_at"],
        last_login_at=row["last_login_at"],
        last_seen_ip=row["last_seen_ip"],
        last_provider_status=row["last_provider_status"],
        last_provider_error=row["last_provider_error"],
        last_verdict_json=_parse_json_dict(row["last_verdict_json"]),
        last_failure_reason=row["last_failure_reason"],
        last_failure_detail=row["last_failure_detail"],
        last_failure_at=row["last_failure_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        revoked_at=row["revoked_at"],
        revoked_reason=row["revoked_reason"],
    )


def _enforce_auth_transport(request: Request, *, detail: str) -> None:
    if is_auth_transport_allowed(request, get_settings()):
        return
    _record_security_block(
        request,
        counter="security.transport_auth.blocked",
        event="security.transport_auth.blocked",
        detail=detail,
        reason="https_required",
    )
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


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
    if not get_settings().admin_ui_enabled:
        return PlainTextResponse("WakeFromFar backend", status_code=200)
    return RedirectResponse("/admin/ui/login", status_code=302)


@app.get("/health")
def health() -> dict[str, str]:
    return {"ok": "true"}


@app.post("/auth/app-proof/challenge", response_model=AppProofChallengeResponse)
def issue_app_proof_challenge(body: AppProofChallengeRequest, request: Request) -> AppProofChallengeResponse:
    _enforce_auth_transport(request, detail=LOGIN_TLS_REQUIRED_DETAIL)
    response = _app_proof_service().issue_challenge(
        platform=body.platform,
        purpose=body.purpose,
        installation_id=body.installation_id,
        username=body.username,
        app_version=body.app_version,
        os_version=body.os_version,
        client_ip=_get_request_ip(request),
    )
    return AppProofChallengeResponse(
        challenge_id=response["challenge_id"],
        challenge=response["challenge"],
        purpose=response["purpose"],
        expires_in=response["expires_in"],
        binding=response["binding"],
    )


@app.post("/auth/app-proof/verify/android", response_model=AppProofVerifyResponse)
def verify_android_app_proof(body: AndroidAppProofVerifyRequest, request: Request) -> AppProofVerifyResponse:
    _enforce_auth_transport(request, detail=LOGIN_TLS_REQUIRED_DETAIL)
    service = _app_proof_service()
    try:
        proof = service.verify_android(
            challenge_id=body.challenge_id,
            installation_id=body.installation_id,
            request_hash=body.request_hash,
            integrity_token=body.integrity_token,
            app_version=body.app_version,
            os_version=body.os_version,
            client_ip=_get_request_ip(request),
        )
    except AppProofError as exc:
        service.record_verify_error(
            platform="android",
            purpose=None,
            installation_id=body.installation_id,
            challenge_id=body.challenge_id,
            reason=exc.reason,
            detail=exc.detail,
            client_ip=_get_request_ip(request),
            event=exc.log_event,
        )
        raise exc.to_http_exception()
    proof_ticket, expires_in = service.build_proof_ticket(proof)
    return AppProofVerifyResponse(
        proof_ticket=proof_ticket,
        proof_expires_in=expires_in,
        installation_status=proof.installation_status,
    )


@app.post("/auth/app-proof/verify/ios", response_model=AppProofVerifyResponse)
def verify_ios_app_proof(body: IOSAppProofVerifyRequest, request: Request) -> AppProofVerifyResponse:
    _enforce_auth_transport(request, detail=LOGIN_TLS_REQUIRED_DETAIL)
    service = _app_proof_service()
    try:
        proof = service.verify_ios(
            mode=body.mode,
            challenge_id=body.challenge_id,
            installation_id=body.installation_id,
            key_id=body.key_id,
            attestation_object=body.attestation_object,
            assertion_object=body.assertion_object,
            receipt=body.receipt,
            app_version=body.app_version,
            os_version=body.os_version,
            client_ip=_get_request_ip(request),
        )
    except AppProofError as exc:
        service.record_verify_error(
            platform="ios",
            purpose=None,
            installation_id=body.installation_id,
            challenge_id=body.challenge_id,
            reason=exc.reason,
            detail=exc.detail,
            client_ip=_get_request_ip(request),
            event=exc.log_event,
        )
        raise exc.to_http_exception()
    proof_ticket, expires_in = service.build_proof_ticket(proof)
    return AppProofVerifyResponse(
        proof_ticket=proof_ticket,
        proof_expires_in=expires_in,
        installation_status=proof.installation_status,
    )


def get_current_user(
    request: Request,
    creds: Annotated[HTTPAuthorizationCredentials, Depends(auth_scheme)],
) -> dict:
    _enforce_auth_transport(request, detail=AUTHENTICATED_TLS_REQUIRED_DETAIL)
    payload = decode_token(creds.credentials)
    _app_proof_service().ensure_authenticated_installation(
        token_payload=payload,
        presented_installation_id=request.headers.get(APP_PROOF_HEADER),
    )
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


def _device_membership_to_out(row: dict) -> DeviceMembershipOut:
    return DeviceMembershipOut(
        id=row["id"],
        user_id=row["user_id"],
        device_id=row["device_id"],
        username=row["username"],
        device_name=row["device_name"],
        device_display_name=row["device_display_name"],
        can_view_status=bool(row["can_view_status"]),
        can_wake=bool(row["can_wake"]),
        can_request_shutdown=bool(row["can_request_shutdown"]),
        can_manage_schedule=bool(row["can_manage_schedule"]),
        is_favorite=bool(row["is_favorite"]),
        sort_order=int(row["sort_order"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _host_to_my_device_out(row: dict, is_stale: bool, force_admin_permissions: bool = False) -> MyDeviceOut:
    def _optional_bool(key: str, default: bool) -> bool:
        value = row[key] if key in row.keys() else None
        return default if value is None else bool(value)

    def _optional_int(key: str, default: int) -> int:
        value = row[key] if key in row.keys() else None
        return default if value is None else int(value)

    total_schedules = _optional_int("scheduled_wake_total_count", 0)
    enabled_schedules = _optional_int("scheduled_wake_enabled_count", 0)
    schedule_summary = None
    if total_schedules > 0:
        schedule_summary = ScheduledWakeSummaryOut(
            total_count=total_schedules,
            enabled_count=enabled_schedules,
            next_run_at=row["scheduled_wake_next_run_at"] if "scheduled_wake_next_run_at" in row.keys() else None,
        )

    permissions = DevicePermissionsOut(
        can_view_status=True if force_admin_permissions else _optional_bool("can_view_status", True),
        can_wake=True if force_admin_permissions else _optional_bool("can_wake", True),
        can_request_shutdown=True if force_admin_permissions else _optional_bool("can_request_shutdown", True),
        can_manage_schedule=True if force_admin_permissions else _optional_bool("can_manage_schedule", True),
    )
    return MyDeviceOut(
        id=row["id"],
        name=row["name"],
        display_name=row["display_name"],
        mac=row["mac"],
        group_name=row["group_name"],
        is_favorite=_optional_bool("is_favorite", False),
        sort_order=_optional_int("sort_order", 0),
        permissions=permissions,
        last_power_state=row["last_power_state"] or "unknown",
        last_power_checked_at=row["last_power_checked_at"],
        is_stale=is_stale,
        scheduled_wake_summary=schedule_summary,
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


_DEVICE_OPERATION_FLAGS: dict[str, tuple[str | None, str | None]] = {
    "view": (None, None),
    "power_check": ("can_view_status", "Power-check not permitted for this device"),
    "wake": ("can_wake", "Wake not permitted for this device"),
    "shutdown_poke": ("can_request_shutdown", "Shutdown request not permitted for this device"),
}


def _get_authorized_device(
    current_user: dict,
    host_id: str,
    operation: Literal["view", "power_check", "wake", "shutdown_poke"],
):
    host = get_host_by_id(host_id)
    if not host:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    if current_user["role"] == "admin":
        return host
    membership = get_device_membership_for_user_device(int(current_user["id"]), host_id)
    if not membership:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    flag_name, forbidden_detail = _DEVICE_OPERATION_FLAGS[operation]
    if flag_name is not None and not bool(membership[flag_name]):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=forbidden_detail)
    return host


def _validate_sort_order(sort_order: int | None) -> None:
    if sort_order is None:
        return
    if sort_order < 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="sort_order must be non-negative")


def _list_me_device_rows(current_user: dict) -> list[sqlite3.Row]:
    if current_user["role"] == "admin":
        return list_all_devices_for_user_preferences(int(current_user["id"]))
    return list_visible_devices_for_user(int(current_user["id"]))


def _get_me_device_row(current_user: dict, host_id: str) -> sqlite3.Row | None:
    if current_user["role"] == "admin":
        return get_device_for_user_preferences(int(current_user["id"]), host_id)
    return get_visible_device_for_user(int(current_user["id"]), host_id)


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


def _execute_wake_for_device(host: dict, *, actor_username: str) -> _WakeExecutionOutcome:
    precheck = _run_and_persist_power_check(host)
    if precheck.result == "on":
        wake_log_id = log_wake(
            host_id=host["id"],
            actor_username=actor_username,
            sent_to="",
            result="already_on",
            precheck_state="on",
        )
        return _WakeExecutionOutcome(
            result="already_on",
            message="Device is already on",
            detail="device_already_on",
            precheck_state="on",
            precheck_detail=precheck.detail,
            sent_to=None,
            error_detail=None,
            wake_log_id=wake_log_id,
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
        wake_log_id = log_wake(
            host_id=host["id"],
            actor_username=actor_username,
            sent_to=sent_to,
            result="failed",
            error_detail=send_error,
            precheck_state=precheck.result,
        )
        return _WakeExecutionOutcome(
            result="failed",
            message="Wake failed",
            detail=send_error or "wake_send_failed",
            precheck_state=precheck.result,
            precheck_detail=precheck.detail,
            sent_to=sent_to,
            error_detail=send_error,
            wake_log_id=wake_log_id,
        )

    is_misconfigured_precheck = precheck.result == "unknown" and (
        precheck.detail.startswith("missing_check_") or precheck.detail == "invalid_method"
    )
    message = "Magic packet sent"
    detail = "magic_packet_sent"
    if is_misconfigured_precheck:
        message = "Magic packet sent (power-check misconfigured; verify check settings)"
        detail = "magic_packet_sent_power_check_misconfigured"

    wake_log_id = log_wake(
        host_id=host["id"],
        actor_username=actor_username,
        sent_to=sent_to,
        result="sent",
        precheck_state=precheck.result,
    )
    return _WakeExecutionOutcome(
        result="sent",
        message=message,
        detail=detail,
        precheck_state=precheck.result,
        precheck_detail=precheck.detail,
        sent_to=sent_to,
        error_detail=None,
        wake_log_id=wake_log_id,
    )


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


def _parse_scheduled_wake_days(days_of_week_json: str) -> list[str]:
    try:
        return parse_days_of_week_json(days_of_week_json)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc


def _scheduled_wake_to_out(row: dict) -> ScheduledWakeOut:
    return ScheduledWakeOut(
        id=row["id"],
        device_id=row["device_id"],
        device_name=row["device_name"],
        device_display_name=row["device_display_name"],
        label=row["label"],
        enabled=bool(row["enabled"]),
        timezone=row["timezone"],
        days_of_week=_parse_scheduled_wake_days(row["days_of_week_json"]),
        local_time=row["local_time"],
        next_run_at=row["next_run_at"],
        last_run_at=row["last_run_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _scheduled_wake_run_to_out(row: dict) -> ScheduledWakeRunOut:
    return ScheduledWakeRunOut(
        id=row["id"],
        job_id=row["job_id"],
        device_id=row["device_id"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        result=row["result"],
        detail=row["detail"],
        wake_log_id=row["wake_log_id"],
    )


def _resolved_scheduled_wake_values(
    *,
    payload: dict[str, object],
    current_job: sqlite3.Row | None = None,
) -> dict[str, object]:
    now_utc = datetime.now(UTC)
    current_days = _parse_scheduled_wake_days(current_job["days_of_week_json"]) if current_job is not None else []

    device_id = str(payload.get("device_id") if "device_id" in payload else (current_job["device_id"] if current_job else ""))
    label = str(payload.get("label") if "label" in payload else (current_job["label"] if current_job else "")).strip()
    enabled = bool(payload.get("enabled") if "enabled" in payload else (bool(current_job["enabled"]) if current_job else True))
    timezone_name = (
        str(payload.get("timezone") if "timezone" in payload else (current_job["timezone"] if current_job else "")).strip()
    )
    days_of_week = payload.get("days_of_week") if "days_of_week" in payload else current_days
    local_time = str(
        payload.get("local_time") if "local_time" in payload else (current_job["local_time"] if current_job else "")
    ).strip()

    if not device_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="device_id is required")
    if not label:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="label is required")
    try:
        timezone_name, normalized_days, normalized_local_time = normalize_schedule_definition(
            timezone_name=timezone_name,
            days_of_week=[str(day) for day in days_of_week] if isinstance(days_of_week, list) else [],
            local_time=local_time,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    if get_host_by_id(device_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    schedule_fields_changed = current_job is None or any(
        key in payload for key in ("timezone", "days_of_week", "local_time", "enabled")
    )
    next_run_at = current_job["next_run_at"] if current_job is not None else None
    if enabled and schedule_fields_changed:
        next_run_at = compute_next_run_at_iso(
            timezone_name=timezone_name,
            days_of_week=normalized_days,
            local_time=normalized_local_time,
            now_utc=now_utc,
        )
    if not enabled:
        next_run_at = None

    return {
        "device_id": device_id,
        "label": label,
        "enabled": enabled,
        "timezone": timezone_name,
        "days_of_week": normalized_days,
        "local_time": normalized_local_time,
        "next_run_at": next_run_at,
    }


def _run_scheduled_wake_job(job: sqlite3.Row) -> ScheduledWakeRunOut:
    started_at = datetime.now(UTC)
    finished_at = started_at
    result: Literal["sent", "already_on", "failed", "skipped"] = "skipped"
    detail = "scheduled device not found"
    wake_log_id: int | None = None
    try:
        host = get_host_by_id(str(job["device_id"]))
        if host is None:
            result = "skipped"
            detail = "scheduled device not found"
        else:
            outcome = _execute_wake_for_device(dict(host), actor_username="scheduler")
            result = outcome.result
            detail = outcome.detail
            wake_log_id = outcome.wake_log_id
        finished_at = datetime.now(UTC)
    except Exception as exc:
        finished_at = datetime.now(UTC)
        result = "failed"
        detail = f"scheduled wake execution error: {exc}"
        structured_log(
            "scheduled_wake.run.error",
            job_id=job["id"],
            device_id=job["device_id"],
            error=str(exc),
        )

    run_row = record_scheduled_wake_run(
        job_id=str(job["id"]),
        device_id=str(job["device_id"]),
        started_at=started_at.isoformat(),
        finished_at=finished_at.isoformat(),
        result=result,
        detail=detail,
        wake_log_id=wake_log_id,
    )
    mark_scheduled_wake_job_executed(
        job_id=str(job["id"]),
        last_run_at=finished_at.isoformat(),
        next_run_at=job["next_run_at"],
    )
    increment_counter(f"scheduled_wake.run.{result}")
    structured_log(
        "scheduled_wake.run.completed",
        job_id=job["id"],
        device_id=job["device_id"],
        result=result,
        detail=detail,
        wake_log_id=wake_log_id,
    )
    return _scheduled_wake_run_to_out(run_row)


def run_scheduled_wake_runner_cycle(limit: int | None = None) -> int:
    settings = get_settings()
    safe_limit = max(1, limit or settings.scheduled_wake_max_jobs_per_poll)
    poll_now = datetime.now(UTC)
    due_jobs = list_due_scheduled_wake_jobs(poll_now.isoformat(), limit=safe_limit)
    processed = 0
    for due_job in due_jobs:
        due_at_text = str(due_job["next_run_at"] or "")
        if not due_at_text:
            continue
        due_at = datetime.fromisoformat(due_at_text)
        claimed_next_run_at = compute_next_run_at_iso(
            timezone_name=str(due_job["timezone"]),
            days_of_week=_parse_scheduled_wake_days(str(due_job["days_of_week_json"])),
            local_time=str(due_job["local_time"]),
            now_utc=due_at.astimezone(UTC),
        )
        claimed = claim_scheduled_wake_job(
            job_id=str(due_job["id"]),
            expected_next_run_at=due_at_text,
            claimed_next_run_at=claimed_next_run_at,
            claimed_at=poll_now.isoformat(),
        )
        if claimed is None:
            continue
        _run_scheduled_wake_job(claimed)
        processed += 1
    return processed


async def _scheduled_wake_runner_loop() -> None:
    settings = get_settings()
    structured_log(
        "scheduled_wake.runner.started",
        poll_seconds=settings.scheduled_wake_poll_seconds,
        max_jobs_per_poll=settings.scheduled_wake_max_jobs_per_poll,
    )
    while True:
        try:
            async with _SCHEDULED_WAKE_RUNNER_LOCK:
                processed = await asyncio.to_thread(run_scheduled_wake_runner_cycle)
                if processed:
                    structured_log("scheduled_wake.runner.poll", processed=processed)
        except Exception as exc:
            structured_log("scheduled_wake.runner.error", error=str(exc))
        await asyncio.sleep(settings.scheduled_wake_poll_seconds)


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
    _enforce_auth_transport(request, detail=LOGIN_TLS_REQUIRED_DETAIL)
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

    service = _app_proof_service()
    proof_decision = service.validate_login_proof(
        username=user["username"],
        role=user["role"],
        installation_id=body.installation_id,
        proof_ticket=body.proof_ticket,
        client_ip=ip,
    )
    if not proof_decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Valid mobile app proof is required")

    installation = None
    if proof_decision.proof is not None:
        installation = service.update_installation_after_login(
            installation_id=proof_decision.proof.installation_id,
            user_id=int(user["id"]),
            client_ip=ip,
        )

    token, expires_in = create_token(
        username=user["username"],
        role=user["role"],
        token_version=int(user["token_version"] or 0),
        installation_id=str(installation["installation_id"]) if installation else None,
        app_proof_method=str(installation["proof_method"]) if installation else None,
        installation_session_version=int(installation["session_version"] or 0) if installation else None,
    )
    increment_counter("login.success")
    structured_log(
        "login.success",
        ip=ip,
        username=user["username"],
        role=user["role"],
        installation_id=str(installation["installation_id"]) if installation else None,
        app_proof_mode=settings.app_proof_mode,
        degraded=proof_decision.degraded,
        degraded_reason=proof_decision.degraded_reason,
    )
    return LoginResponse(token=token, expires_in=expires_in)


@app.post("/onboarding/claim")
def onboarding_claim_disabled() -> dict[str, str]:
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail="Invite onboarding is disabled. Ask your admin for credentials and backend URL.",
    )


@app.get("/me/devices", response_model=list[MyDeviceOut])
def me_devices(
    background_tasks: BackgroundTasks,
    current_user: Annotated[dict, Depends(get_current_user)],
) -> list[MyDeviceOut]:
    rows = _list_me_device_rows(current_user)
    result: list[MyDeviceOut] = []
    for row in rows:
        stale = _is_stale(row["last_power_checked_at"])
        if stale:
            background_tasks.add_task(_run_background_power_check, row["id"])
        result.append(
            _host_to_my_device_out(
                row=row,
                is_stale=stale,
                force_admin_permissions=current_user["role"] == "admin",
            )
        )
    return result


@app.patch("/me/devices/{host_id}/preferences", response_model=MyDeviceOut)
def me_update_device_preferences(
    host_id: str,
    body: MyDevicePreferencesUpdate,
    current_user: Annotated[dict, Depends(get_current_user)],
) -> MyDeviceOut:
    updates = {key: value for key, value in body.model_dump(exclude_unset=True).items() if value is not None}
    _validate_sort_order(updates.get("sort_order"))

    if current_user["role"] == "admin":
        host = get_host_by_id(host_id)
        if not host:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    else:
        host = _get_authorized_device(current_user=current_user, host_id=host_id, operation="view")

    membership = get_device_membership_for_user_device(int(current_user["id"]), host_id)
    if membership is None:
        if current_user["role"] != "admin":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
        membership = create_device_membership(
            user_id=int(current_user["id"]),
            device_id=host_id,
            can_view_status=True,
            can_wake=True,
            can_request_shutdown=True,
            can_manage_schedule=True,
            is_favorite=bool(updates["is_favorite"]) if "is_favorite" in updates else False,
            sort_order=int(updates["sort_order"]) if "sort_order" in updates else 0,
        )
    elif updates:
        membership = update_device_membership(
            membership["id"],
            {key: int(value) if isinstance(value, bool) else value for key, value in updates.items()},
        )
        if membership is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device membership not found")

    row = _get_me_device_row(current_user, host_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return _host_to_my_device_out(
        row=row,
        is_stale=_is_stale(row["last_power_checked_at"]),
        force_admin_permissions=current_user["role"] == "admin",
    )


@app.post("/me/devices/{host_id}/power-check", response_model=PowerCheckResponse)
def me_power_check(host_id: str, current_user: Annotated[dict, Depends(get_current_user)]) -> PowerCheckResponse:
    host = _get_authorized_device(current_user=current_user, host_id=host_id, operation="power_check")
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
    host = _get_authorized_device(current_user=current_user, host_id=host_id, operation="wake")
    host_name = _host_label(host)
    now = datetime.now(UTC)
    outcome = _execute_wake_for_device(dict(host), actor_username=current_user["username"])
    event_type = {
        "already_on": "wake_already_on",
        "failed": "wake_failed",
        "sent": "wake_sent",
    }[outcome.result]
    event_summary = {
        "already_on": f"{current_user['username']} woke {host_name} (already on)",
        "failed": f"{current_user['username']} failed to wake {host_name}",
        "sent": f"{current_user['username']} woke {host_name}",
    }[outcome.result]
    metadata = {
        "result": outcome.result,
        "precheck_state": outcome.precheck_state,
    }
    if outcome.sent_to is not None:
        metadata["sent_to"] = outcome.sent_to
    if outcome.precheck_detail:
        metadata["precheck_detail"] = outcome.precheck_detail
    if outcome.error_detail:
        metadata["error_detail"] = outcome.error_detail

    increment_counter(f"wake.{outcome.result}")
    structured_log(
        f"wake.{outcome.result}",
        actor=current_user["username"],
        device_id=host_id,
        ip=ip,
        precheck_state=outcome.precheck_state,
        precheck_detail=outcome.precheck_detail,
        error=outcome.error_detail,
    )
    _emit_activity_event(
        event_type=event_type,
        actor=current_user,
        target_type="device",
        target_id=host_id,
        server_id=host_id,
        summary=event_summary,
        metadata=metadata,
    )
    return MeWakeResponse(
        device_id=host_id,
        result=outcome.result,
        message=outcome.message,
        precheck_state=outcome.precheck_state,
        sent_to=outcome.sent_to,
        timestamp=now,
        error_detail=outcome.error_detail,
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
    host = _get_authorized_device(current_user=current_user, host_id=host_id, operation="shutdown_poke")
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


@app.get("/admin/device-memberships", response_model=list[DeviceMembershipOut])
def admin_list_device_memberships(_: Annotated[dict, Depends(require_admin)]) -> list[DeviceMembershipOut]:
    rows = list_device_memberships()
    return [_device_membership_to_out(row) for row in rows]


@app.post("/admin/device-memberships", status_code=status.HTTP_201_CREATED, response_model=DeviceMembershipOut)
def admin_create_device_membership(
    body: DeviceMembershipCreate,
    current_user: Annotated[dict, Depends(require_admin)],
) -> DeviceMembershipOut:
    user = get_user_by_id(body.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    host = get_host_by_id(body.device_id)
    if not host:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    try:
        row = create_device_membership(
            user_id=body.user_id,
            device_id=body.device_id,
            can_view_status=body.can_view_status,
            can_wake=body.can_wake,
            can_request_shutdown=body.can_request_shutdown,
            can_manage_schedule=body.can_manage_schedule,
            is_favorite=body.is_favorite,
            sort_order=body.sort_order,
        )
    except sqlite3.IntegrityError as exc:
        if "UNIQUE constraint failed" in str(exc):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Device membership already exists") from exc
        raise
    log_admin_action(
        actor_username=current_user["username"],
        action="create_device_membership",
        target_type="device_membership",
        target_id=row["id"],
        detail=f"user_id={body.user_id},device_id={body.device_id}",
    )
    increment_counter("admin_action.create_device_membership")
    return _device_membership_to_out(row)


@app.patch("/admin/device-memberships/{membership_id}", response_model=DeviceMembershipOut)
def admin_update_device_membership(
    membership_id: str,
    body: DeviceMembershipUpdate,
    current_user: Annotated[dict, Depends(require_admin)],
) -> DeviceMembershipOut:
    existing = get_device_membership_by_id(membership_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device membership not found")
    updates = {key: value for key, value in body.model_dump(exclude_unset=True).items() if value is not None}
    _validate_sort_order(updates.get("sort_order"))
    row = update_device_membership(
        membership_id,
        {key: int(value) if isinstance(value, bool) else value for key, value in updates.items()},
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device membership not found")
    log_admin_action(
        actor_username=current_user["username"],
        action="update_device_membership",
        target_type="device_membership",
        target_id=membership_id,
        detail=json.dumps(updates, sort_keys=True, separators=(",", ":")),
    )
    increment_counter("admin_action.update_device_membership")
    return _device_membership_to_out(row)


@app.delete("/admin/device-memberships/{membership_id}")
def admin_delete_device_membership(
    membership_id: str,
    current_user: Annotated[dict, Depends(require_admin)],
) -> dict[str, bool]:
    existing = get_device_membership_by_id(membership_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device membership not found")
    deleted = delete_device_membership(membership_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device membership not found")
    log_admin_action(
        actor_username=current_user["username"],
        action="delete_device_membership",
        target_type="device_membership",
        target_id=membership_id,
        detail=f"user_id={existing['user_id']},device_id={existing['device_id']}",
    )
    increment_counter("admin_action.delete_device_membership")
    return {"ok": True}


@app.get("/admin/scheduled-wakes/runs", response_model=list[ScheduledWakeRunOut])
def admin_list_scheduled_wake_runs(
    _: Annotated[dict, Depends(require_admin)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    job_id: str | None = None,
    device_id: str | None = None,
) -> list[ScheduledWakeRunOut]:
    rows = list_scheduled_wake_runs(limit=limit, job_id=job_id, device_id=device_id)
    return [_scheduled_wake_run_to_out(row) for row in rows]


@app.get("/admin/scheduled-wakes", response_model=list[ScheduledWakeOut])
def admin_list_scheduled_wakes(
    _: Annotated[dict, Depends(require_admin)],
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[ScheduledWakeOut]:
    return [_scheduled_wake_to_out(row) for row in list_scheduled_wake_jobs(limit=limit)]


@app.post("/admin/scheduled-wakes", status_code=status.HTTP_201_CREATED, response_model=ScheduledWakeOut)
def admin_create_scheduled_wake(
    body: ScheduledWakeCreate,
    current_user: Annotated[dict, Depends(require_admin)],
) -> ScheduledWakeOut:
    resolved = _resolved_scheduled_wake_values(payload=body.model_dump())
    row = create_scheduled_wake_job(
        device_id=str(resolved["device_id"]),
        created_by_user_id=int(current_user["id"]),
        label=str(resolved["label"]),
        enabled=bool(resolved["enabled"]),
        timezone=str(resolved["timezone"]),
        days_of_week=[str(day) for day in resolved["days_of_week"]],
        local_time=str(resolved["local_time"]),
        next_run_at=str(resolved["next_run_at"]) if resolved["next_run_at"] is not None else None,
    )
    log_admin_action(
        actor_username=current_user["username"],
        action="create_scheduled_wake_job",
        target_type="scheduled_wake_job",
        target_id=str(row["id"]),
        detail=json.dumps(
            {
                "device_id": resolved["device_id"],
                "enabled": resolved["enabled"],
                "days_of_week": resolved["days_of_week"],
                "local_time": resolved["local_time"],
                "timezone": resolved["timezone"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
    )
    increment_counter("scheduled_wake.created")
    structured_log(
        "scheduled_wake.created",
        actor=current_user["username"],
        job_id=row["id"],
        device_id=row["device_id"],
        enabled=bool(row["enabled"]),
        next_run_at=row["next_run_at"],
    )
    return _scheduled_wake_to_out(row)


@app.patch("/admin/scheduled-wakes/{job_id}", response_model=ScheduledWakeOut)
def admin_update_scheduled_wake(
    job_id: str,
    body: ScheduledWakeUpdate,
    current_user: Annotated[dict, Depends(require_admin)],
) -> ScheduledWakeOut:
    current = get_scheduled_wake_job(job_id)
    if not current:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scheduled wake job not found")

    payload = body.model_dump(exclude_unset=True)
    if not payload:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields to update")

    resolved = _resolved_scheduled_wake_values(payload=payload, current_job=current)
    row = update_scheduled_wake_job(
        job_id,
        {
            "device_id": resolved["device_id"],
            "label": resolved["label"],
            "enabled": int(bool(resolved["enabled"])),
            "timezone": resolved["timezone"],
            "days_of_week": resolved["days_of_week"],
            "local_time": resolved["local_time"],
            "next_run_at": resolved["next_run_at"],
        },
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scheduled wake job not found")
    log_admin_action(
        actor_username=current_user["username"],
        action="update_scheduled_wake_job",
        target_type="scheduled_wake_job",
        target_id=job_id,
        detail=json.dumps(payload, sort_keys=True, separators=(",", ":")),
    )
    increment_counter("scheduled_wake.updated")
    structured_log(
        "scheduled_wake.updated",
        actor=current_user["username"],
        job_id=job_id,
        device_id=row["device_id"],
        enabled=bool(row["enabled"]),
        next_run_at=row["next_run_at"],
    )
    return _scheduled_wake_to_out(row)


@app.delete("/admin/scheduled-wakes/{job_id}")
def admin_delete_scheduled_wake(
    job_id: str,
    current_user: Annotated[dict, Depends(require_admin)],
) -> dict[str, bool]:
    current = get_scheduled_wake_job(job_id)
    if not current:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scheduled wake job not found")
    deleted = delete_scheduled_wake_job(job_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scheduled wake job not found")
    log_admin_action(
        actor_username=current_user["username"],
        action="delete_scheduled_wake_job",
        target_type="scheduled_wake_job",
        target_id=job_id,
        detail=f"device_id={current['device_id']},label={current['label']}",
    )
    increment_counter("scheduled_wake.deleted")
    structured_log(
        "scheduled_wake.deleted",
        actor=current_user["username"],
        job_id=job_id,
        device_id=current["device_id"],
    )
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
    return {
        "counters": get_counters(),
        "security_status": _security_status_payload().model_dump(mode="json"),
    }


@app.get("/admin/security-status", response_model=SecurityStatusOut)
def admin_security_status(_: Annotated[dict, Depends(require_admin)]) -> SecurityStatusOut:
    return _security_status_payload()


@app.get("/admin/app-installations", response_model=list[AppInstallationOut])
def admin_list_app_installations(
    _: Annotated[dict, Depends(require_admin)],
    user_id: int | None = Query(default=None),
    platform: Literal["android", "ios"] | None = Query(default=None),
    status_filter: Literal["pending", "trusted", "report_only", "revoked"] | None = Query(default=None, alias="status"),
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[AppInstallationOut]:
    return [
        _serialize_app_installation(row)
        for row in list_app_installations(user_id=user_id, platform=platform, status=status_filter, limit=limit)
    ]


@app.post("/admin/app-installations/{installation_id}/revoke", response_model=AppInstallationOut)
def admin_revoke_app_installation(
    installation_id: str,
    body: AppInstallationRevokeRequest,
    current_user: Annotated[dict, Depends(require_admin)],
) -> AppInstallationOut:
    row = revoke_app_installation(installation_id, reason=body.reason)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Installation not found")
    log_admin_action(
        actor_username=current_user["username"],
        action="revoke_installation",
        target_type="app_installation",
        target_id=installation_id,
        detail=body.reason or "",
    )
    increment_counter("app_proof.installation_revoked")
    structured_log(
        "app_proof.installation_revoked",
        actor=current_user["username"],
        installation_id=installation_id,
        reason=body.reason,
    )
    return _serialize_app_installation(row)


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
