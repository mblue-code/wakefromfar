from __future__ import annotations

import hashlib
import ipaddress
import secrets
import time
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, status
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
    create_user,
    delete_host,
    delete_user,
    get_assigned_host_by_id,
    get_host_by_id,
    get_invite_by_hash,
    get_user_by_id,
    get_user_by_username,
    init_db,
    list_admin_audit_logs,
    list_assignments,
    list_claimed_invites,
    list_hosts,
    list_invite_tokens,
    list_power_check_logs,
    list_successful_wakes,
    list_users,
    list_wake_logs,
    list_assigned_hosts,
    log_admin_action,
    log_power_check,
    log_wake,
    remove_assignment,
    revoke_invite,
    update_host,
    update_host_power_state,
    update_user_password,
    update_user_password_by_id,
    update_user_role,
    upsert_admin,
)
from .power import PowerCheckResult, run_power_check
from .schemas import (
    AdminDeviceCreate,
    AdminDeviceOut,
    AdminDeviceUpdate,
    AdminUserCreate,
    AdminUserOut,
    AdminUserUpdate,
    AssignmentCreate,
    AssignmentOut,
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

app = FastAPI(title="WoL Relay", version="0.1.0")
app.include_router(admin_ui_router)
auth_scheme = HTTPBearer(auto_error=True)
LOGIN_ATTEMPTS: dict[str, deque[datetime]] = defaultdict(deque)
ONBOARDING_ATTEMPTS: dict[str, deque[datetime]] = defaultdict(deque)
WAKE_ATTEMPTS: dict[str, deque[datetime]] = defaultdict(deque)


def _init_bootstrap() -> None:
    settings = get_settings()
    init_db()
    if settings.admin_user and settings.admin_pass:
        upsert_admin(settings.admin_user, hash_password(settings.admin_pass))


@app.on_event("startup")
def on_startup() -> None:
    _init_bootstrap()


@app.middleware("http")
async def allowlist_middleware(request: Request, call_next):
    settings = get_settings()
    if not settings.enforce_ip_allowlist:
        return await call_next(request)

    client_ip = request.client.host if request.client else None
    if not client_ip:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing client IP")

    allowed = False
    ip_obj = ipaddress.ip_address(client_ip)
    for cidr in settings.allowed_cidrs:
        if ip_obj in ipaddress.ip_network(cidr, strict=False):
            allowed = True
            break

    if not allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Client IP not allowed")

    return await call_next(request)


def _clean_attempts(store: dict[str, deque[datetime]], key: str, now: datetime) -> None:
    attempts = store[key]
    while attempts and (now - attempts[0]).total_seconds() > 60:
        attempts.popleft()


def _enforce_rate_limit(
    store: dict[str, deque[datetime]],
    key: str,
    limit: int,
    detail: str,
) -> None:
    now = datetime.now(UTC)
    _clean_attempts(store, key, now)
    if len(store[key]) >= limit:
        increment_counter("rate_limit.blocked")
        structured_log("rate_limit.blocked", key=key, detail=detail, limit=limit)
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=detail)
    store[key].append(now)


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
        check_method=row["check_method"] or "tcp",
        check_target=row["check_target"],
        check_port=row["check_port"],
        last_power_state=row["last_power_state"] or "unknown",
        last_power_checked_at=row["last_power_checked_at"],
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


def _send_magic_packet_with_retry(mac: str, target_ip: str, udp_port: int, interface: str | None) -> tuple[bool, str | None]:
    settings = get_settings()
    max_attempts = max(1, settings.wake_send_max_attempts)
    last_error: str | None = None
    for attempt in range(max_attempts):
        try:
            send_magic_packet(mac=mac, target_ip=target_ip, udp_port=udp_port, interface=interface)
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


@app.post("/auth/login", response_model=LoginResponse)
def login(body: LoginRequest, request: Request) -> LoginResponse:
    settings = get_settings()
    now = datetime.now(UTC)
    ip = request.client.host if request.client else "unknown"

    _clean_attempts(LOGIN_ATTEMPTS, ip, now)
    if len(LOGIN_ATTEMPTS[ip]) >= settings.login_rate_limit_per_minute:
        increment_counter("login.rate_limited")
        structured_log("login.rate_limited", ip=ip)
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many login attempts")

    user = get_user_by_username(body.username)
    if not user or not verify_password(body.password, user["password_hash"]):
        LOGIN_ATTEMPTS[ip].append(now)
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
    ip = request.client.host if request.client else "unknown"
    _enforce_rate_limit(
        ONBOARDING_ATTEMPTS,
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

    updated = update_user_password(username=user["username"], password_hash=hash_password(body.password))
    if not updated:
        increment_counter("onboarding.failed")
        structured_log("onboarding.failed", ip=ip, reason="password_update_failed", username=user["username"])
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not set password")
    claimed = claim_invite(invite_id=invite["id"], claimed_at=now.isoformat())
    if not claimed:
        increment_counter("onboarding.failed")
        structured_log("onboarding.failed", ip=ip, reason="claim_race", username=user["username"])
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Invite token already claimed")

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
    ip = request.client.host if request.client else "unknown"
    rate_key = f"{current_user['username']}@{ip}"
    _enforce_rate_limit(
        WAKE_ATTEMPTS,
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
