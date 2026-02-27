from __future__ import annotations

import ipaddress
from collections import defaultdict, deque
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import get_settings
from .db import (
    create_host,
    create_user,
    get_host_by_id,
    get_user_by_username,
    init_db,
    list_hosts,
    log_wake,
    upsert_admin,
)
from .schemas import (
    AdminHostCreate,
    AdminUserCreate,
    HostOut,
    LoginRequest,
    LoginResponse,
    WakeResponse,
)
from .security import create_token, decode_token, hash_password, verify_password
from .wol import normalize_mac, resolve_target, send_magic_packet

app = FastAPI(title="WoL Relay", version="0.1.0")
auth_scheme = HTTPBearer(auto_error=True)
LOGIN_ATTEMPTS: dict[str, deque[datetime]] = defaultdict(deque)


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


def _clean_attempts(ip: str, now: datetime) -> None:
    attempts = LOGIN_ATTEMPTS[ip]
    while attempts and (now - attempts[0]).total_seconds() > 60:
        attempts.popleft()


@app.get("/health")
def health() -> dict[str, str]:
    return {"ok": "true"}


def get_current_user(
    creds: Annotated[HTTPAuthorizationCredentials, Depends(auth_scheme)],
) -> dict:
    payload = decode_token(creds.credentials)
    return {"username": payload.get("sub", ""), "role": payload.get("role", "user")}


def require_admin(current_user: Annotated[dict, Depends(get_current_user)]) -> dict:
    if current_user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return current_user


@app.post("/auth/login", response_model=LoginResponse)
def login(body: LoginRequest, request: Request) -> LoginResponse:
    settings = get_settings()
    now = datetime.now(UTC)
    ip = request.client.host if request.client else "unknown"

    _clean_attempts(ip, now)
    if len(LOGIN_ATTEMPTS[ip]) >= settings.login_rate_limit_per_minute:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many login attempts")

    user = get_user_by_username(body.username)
    if not user or not verify_password(body.password, user["password_hash"]):
        LOGIN_ATTEMPTS[ip].append(now)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token, expires_in = create_token(username=user["username"], role=user["role"])
    return LoginResponse(token=token, expires_in=expires_in)


@app.get("/hosts", response_model=list[HostOut])
def get_hosts(_: Annotated[dict, Depends(get_current_user)]) -> list[HostOut]:
    rows = list_hosts()
    return [
        HostOut(
            id=row["id"],
            name=row["name"],
            mac=row["mac"],
            group_name=row["group_name"],
            broadcast=row["broadcast"],
            subnet_cidr=row["subnet_cidr"],
            udp_port=row["udp_port"],
        )
        for row in rows
    ]


@app.post("/hosts/{host_id}/wake", response_model=WakeResponse)
def wake_host(host_id: str, current_user: Annotated[dict, Depends(get_current_user)]) -> WakeResponse:
    row = get_host_by_id(host_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host not found")

    target_ip = resolve_target(broadcast=row["broadcast"], subnet_cidr=row["subnet_cidr"])
    udp_port = row["udp_port"] or 9
    try:
        send_magic_packet(
            mac=row["mac"],
            target_ip=target_ip,
            udp_port=udp_port,
            interface=row["interface"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"WoL send failed: {exc}") from exc

    sent_to = f"{target_ip}:{udp_port}"
    log_wake(host_id=host_id, actor_username=current_user["username"], sent_to=sent_to)
    return WakeResponse(ok=True, sent_to=sent_to, timestamp=datetime.now(UTC))


@app.post("/admin/users", status_code=status.HTTP_201_CREATED)
def admin_create_user(
    body: AdminUserCreate,
    _: Annotated[dict, Depends(require_admin)],
) -> dict[str, str]:
    if get_user_by_username(body.username):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")

    create_user(
        username=body.username,
        password_hash=hash_password(body.password),
        role=body.role,
    )
    return {"ok": "true"}


@app.post("/admin/hosts", status_code=status.HTTP_201_CREATED)
def admin_create_host(
    body: AdminHostCreate,
    _: Annotated[dict, Depends(require_admin)],
) -> dict[str, str]:
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
    )
    return {"ok": "true", "id": host_id}
