from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from .password_policy import MIN_USER_PASSWORD_LENGTH


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    expires_in: int


class OnboardingClaimRequest(BaseModel):
    token: str
    password: str = Field(min_length=MIN_USER_PASSWORD_LENGTH)


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
    source_ip: str | None = None
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
    password: str = Field(min_length=MIN_USER_PASSWORD_LENGTH)
    role: str = Field(pattern="^(admin|user)$")


class AdminUserUpdate(BaseModel):
    password: str | None = Field(default=None, min_length=MIN_USER_PASSWORD_LENGTH)
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
    source_ip: str | None = None
    source_network_cidr: str | None = None
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
    source_ip: str | None = None
    source_network_cidr: str | None = None
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
    source_ip: str | None = None
    source_network_cidr: str | None = None
    check_method: Literal["tcp", "icmp"] = "tcp"
    check_target: str | None = None
    check_port: int | None = None
    last_power_state: Literal["on", "off", "unknown"] = "unknown"
    last_power_checked_at: datetime | None = None
    provisioning_source: Literal["manual", "discovery"] = "manual"
    discovery_confidence: Literal["high", "medium", "low", "unknown"] | None = None
    last_discovered_at: datetime | None = None


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


class ActivityEventOut(BaseModel):
    id: int
    event_type: str
    actor_user_id: int | None = None
    actor_username: str | None = None
    target_type: str
    target_id: str | None = None
    server_id: str | None = None
    summary: str
    metadata: dict[str, object] | None = None
    created_at: datetime


class ShutdownPokeCreateRequest(BaseModel):
    message: str | None = Field(default=None, max_length=280)


class ShutdownPokeOut(BaseModel):
    id: str
    server_id: str
    device_name: str | None = None
    device_display_name: str | None = None
    requester_user_id: int
    requester_username: str
    message: str | None = None
    status: Literal["open", "seen", "resolved"]
    created_at: datetime
    seen_at: datetime | None = None
    resolved_at: datetime | None = None
    resolved_by_user_id: int | None = None
    resolved_by_username: str | None = None


class APNSDeviceRegistrationRequest(BaseModel):
    installation_id: str = Field(min_length=1, max_length=128)
    token: str = Field(min_length=32, max_length=512)
    app_bundle_id: str = Field(min_length=1, max_length=255)
    environment: Literal["development", "production"]


class NotificationDeviceOut(BaseModel):
    installation_id: str
    platform: Literal["ios"]
    provider: Literal["apns"]
    app_bundle_id: str
    environment: Literal["development", "production"]
    is_active: bool
    updated_at: datetime


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


class DiscoverySourceBinding(BaseModel):
    network_cidr: str
    source_ip: str
    interface: str | None = None
    broadcast_ip: str | None = None


class DiscoveryHostProbeOptions(BaseModel):
    enabled: bool = False
    timeout_ms: int = Field(default=200, ge=50, le=5000)
    max_hosts_per_network: int = Field(default=256, ge=1, le=4096)


class DiscoveryPowerProbeOptions(BaseModel):
    ports: list[int] = Field(default_factory=lambda: [22, 80, 443, 445])
    timeout_ms: int = Field(default=200, ge=50, le=5000)


class DiscoveryRunCreate(BaseModel):
    network_cidrs: list[str] = Field(default_factory=list)
    source_bindings: list[DiscoverySourceBinding] = Field(default_factory=list)
    host_probe: DiscoveryHostProbeOptions = Field(default_factory=DiscoveryHostProbeOptions)
    power_probe: DiscoveryPowerProbeOptions = Field(default_factory=DiscoveryPowerProbeOptions)


class DiscoveryRunOut(BaseModel):
    id: str
    requested_by: str
    status: Literal["queued", "running", "completed", "failed", "canceled"]
    options: dict
    summary: dict | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime


class DiscoveryCandidateOut(BaseModel):
    id: str
    run_id: str
    hostname: str | None = None
    mac: str | None = None
    ip: str | None = None
    source_interface: str | None = None
    source_ip: str | None = None
    source_network_cidr: str | None = None
    broadcast_ip: str | None = None
    wol_confidence: Literal["high", "medium", "low", "unknown"]
    power_check_method: str | None = None
    power_check_target: str | None = None
    power_check_port: int | None = None
    power_data_source: Literal["none", "inferred", "agent", "api"] = "inferred"
    imported_host_id: str | None = None
    suggested_host_id: str | None = None
    suggested_host_name: str | None = None
    notes: dict | None = None
    created_at: datetime
    updated_at: datetime


class DiscoveryValidateResponse(BaseModel):
    result: Literal["sent", "validated", "failed"]
    detail: str
    latency_ms: int | None = None


class DiscoveryImportRequest(BaseModel):
    mode: Literal["create_new", "update_existing", "auto_merge_by_mac"] = "create_new"
    name: str | None = None
    display_name: str | None = None
    target_host_id: str | None = None
    apply_power_settings: bool = True
    group_name: str | None = None


class DiscoveryImportResponse(BaseModel):
    candidate_id: str
    mode: Literal["create_new", "update_existing", "auto_merge_by_mac"]
    host: AdminDeviceOut


class DiscoveryBulkImportRequest(BaseModel):
    mode: Literal["auto_merge_by_mac", "create_new"] = "auto_merge_by_mac"
    name_prefix: str | None = None
    apply_power_settings: bool = True
    group_name: str | None = None
    skip_without_mac: bool = True


class DiscoveryBulkImportResponse(BaseModel):
    run_id: str
    mode: Literal["auto_merge_by_mac", "create_new"]
    processed: int
    imported: int
    merged: int
    created: int
    skipped: int
    failed: int
    details: list[dict]
