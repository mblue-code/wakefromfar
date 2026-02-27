from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    expires_in: int


class OnboardingClaimRequest(BaseModel):
    token: str
    password: str = Field(min_length=12)


class OnboardingClaimResponse(BaseModel):
    token: str
    expires_in: int
    username: str
    role: str
    backend_url_hint: str | None = None


class HostOut(BaseModel):
    id: str
    name: str
    mac: str
    group_name: str | None = None
    broadcast: str | None = None
    subnet_cidr: str | None = None
    udp_port: int = 9
    display_name: str | None = None
    last_power_state: Literal["on", "off", "unknown"] = "unknown"
    last_power_checked_at: datetime | None = None
    is_stale: bool | None = None


class WakeResponse(BaseModel):
    ok: bool
    sent_to: str
    timestamp: datetime
    result: Literal["sent", "failed"] | None = None
    error_detail: str | None = None


class AdminUserCreate(BaseModel):
    username: str
    password: str = Field(min_length=12)
    role: str = Field(pattern="^(admin|user)$")


class AdminUserUpdate(BaseModel):
    password: str | None = Field(default=None, min_length=12)
    role: str | None = Field(default=None, pattern="^(admin|user)$")


class AdminUserOut(BaseModel):
    id: int
    username: str
    role: str
    created_at: datetime


class AdminDeviceCreate(BaseModel):
    id: str | None = None
    name: str
    display_name: str | None = None
    mac: str
    group_name: str | None = None
    broadcast: str | None = None
    subnet_cidr: str | None = None
    udp_port: int = Field(default=9, ge=1, le=65535)
    interface: str | None = None
    check_method: Literal["tcp", "icmp"] = "tcp"
    check_target: str | None = None
    check_port: int | None = Field(default=None, ge=1, le=65535)


class AdminDeviceUpdate(BaseModel):
    name: str | None = None
    display_name: str | None = None
    mac: str | None = None
    group_name: str | None = None
    broadcast: str | None = None
    subnet_cidr: str | None = None
    udp_port: int | None = Field(default=None, ge=1, le=65535)
    interface: str | None = None
    check_method: Literal["tcp", "icmp"] | None = None
    check_target: str | None = None
    check_port: int | None = Field(default=None, ge=1, le=65535)


class AdminDeviceOut(BaseModel):
    id: str
    name: str
    display_name: str | None = None
    mac: str
    group_name: str | None = None
    broadcast: str | None = None
    subnet_cidr: str | None = None
    udp_port: int
    interface: str | None = None
    check_method: Literal["tcp", "icmp"] = "tcp"
    check_target: str | None = None
    check_port: int | None = None
    last_power_state: Literal["on", "off", "unknown"] = "unknown"
    last_power_checked_at: datetime | None = None


class AssignmentCreate(BaseModel):
    user_id: int
    device_id: str


class AssignmentOut(BaseModel):
    user_id: int
    username: str
    device_id: str
    device_name: str
    created_at: datetime


class InviteCreate(BaseModel):
    username: str
    backend_url_hint: str | None = None
    expires_in_hours: int = Field(default=72, ge=1, le=24 * 30)


class InviteOut(BaseModel):
    id: str
    username: str
    backend_url_hint: str | None = None
    expires_at: datetime
    claimed_at: datetime | None = None
    created_by: str
    created_at: datetime


class InviteCreateResponse(InviteOut):
    token: str


class MyDeviceOut(BaseModel):
    id: str
    name: str
    display_name: str | None = None
    mac: str
    group_name: str | None = None
    last_power_state: Literal["on", "off", "unknown"] = "unknown"
    last_power_checked_at: datetime | None = None
    is_stale: bool


class PowerCheckResponse(BaseModel):
    device_id: str
    method: str
    result: Literal["on", "off", "unknown"]
    detail: str
    latency_ms: int | None = None
    checked_at: datetime


class MeWakeResponse(BaseModel):
    device_id: str
    result: Literal["already_on", "sent", "failed"]
    message: str
    precheck_state: Literal["on", "off", "unknown"]
    sent_to: str | None = None
    timestamp: datetime
    error_detail: str | None = None
