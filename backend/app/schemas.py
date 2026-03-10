from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from .password_policy import MIN_USER_PASSWORD_LENGTH


class LoginRequest(BaseModel):
    username: str
    password: str
    installation_id: str | None = Field(default=None, min_length=1, max_length=128)
    proof_ticket: str | None = None


class LoginResponse(BaseModel):
    token: str
    expires_in: int


class AppProofChallengeRequest(BaseModel):
    platform: Literal["android", "ios"]
    purpose: Literal["enroll", "login", "reauth"]
    installation_id: str = Field(min_length=1, max_length=128)
    username: str | None = None
    app_version: str | None = Field(default=None, max_length=64)
    os_version: str | None = Field(default=None, max_length=64)


class AppProofChallengeBinding(BaseModel):
    canonical_fields: list[str]


class AppProofChallengeResponse(BaseModel):
    challenge_id: str
    challenge: str
    purpose: Literal["enroll", "login", "reauth"]
    expires_in: int
    binding: AppProofChallengeBinding


class AndroidAppProofVerifyRequest(BaseModel):
    challenge_id: str
    installation_id: str = Field(min_length=1, max_length=128)
    request_hash: str = Field(min_length=10, max_length=256)
    integrity_token: str = Field(min_length=16)
    app_version: str | None = Field(default=None, max_length=64)
    os_version: str | None = Field(default=None, max_length=64)


class IOSAppProofVerifyRequest(BaseModel):
    mode: Literal["attest", "assert"]
    challenge_id: str
    installation_id: str = Field(min_length=1, max_length=128)
    key_id: str = Field(min_length=8, max_length=512)
    attestation_object: str | None = None
    assertion_object: str | None = None
    receipt: str | None = None
    app_version: str | None = Field(default=None, max_length=64)
    os_version: str | None = Field(default=None, max_length=64)


class AppProofVerifyResponse(BaseModel):
    proof_ticket: str
    proof_expires_in: int
    installation_status: Literal["pending", "trusted", "report_only", "revoked"]


class AppInstallationOut(BaseModel):
    installation_id: str
    platform: Literal["android", "ios"]
    status: Literal["pending", "trusted", "report_only", "revoked"]
    user_id: int | None = None
    session_version: int
    proof_method: str | None = None
    app_id: str | None = None
    app_version: str | None = None
    os_version: str | None = None
    last_verified_at: datetime | None = None
    last_login_at: datetime | None = None
    last_seen_ip: str | None = None
    last_provider_status: str | None = None
    last_provider_error: str | None = None
    last_verdict_json: dict[str, object] | None = None
    last_failure_reason: str | None = None
    last_failure_detail: str | None = None
    last_failure_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    revoked_at: datetime | None = None
    revoked_reason: str | None = None


class AppInstallationRevokeRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=255)


class SecurityWarningOut(BaseModel):
    code: str
    severity: Literal["info", "warning"]
    message: str


class SecurityDeferralOut(BaseModel):
    code: str
    message: str


class SecurityCounterOut(BaseModel):
    name: str
    value: int


class RecentSecurityCategoryOut(BaseModel):
    category: str
    count: int
    last_seen_at: datetime | None = None


class InstallationPlatformSummaryOut(BaseModel):
    total: int
    by_status: dict[str, int]


class SecurityStatusOut(BaseModel):
    generated_at: datetime
    private_network_first: bool
    hardening_mode: str
    app_proof_mode: Literal["disabled", "report_only", "soft_enforce", "enforce_login"]
    admin_bearer_login_app_proof_deferred: bool
    admin_ui_enabled: bool
    admin_mfa_required: bool
    require_tls_for_auth: bool
    allow_insecure_private_http: bool
    allow_unsafe_public_exposure: bool
    ip_allowlist_enabled: bool
    allowlist_summary: dict[str, object]
    app_proof_installations: dict[str, InstallationPlatformSummaryOut]
    recent_app_proof_failures: list[RecentSecurityCategoryOut]
    security_counters: list[SecurityCounterOut]
    warnings: list[SecurityWarningOut]
    deferrals: list[SecurityDeferralOut]


class OnboardingClaimRequest(BaseModel):
    token: str
    password: str = Field(min_length=MIN_USER_PASSWORD_LENGTH)


class OnboardingClaimResponse(BaseModel):
    token: str
    expires_in: int
    username: str
    role: str
    backend_url_hint: str | None = None


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


class DevicePermissionsOut(BaseModel):
    can_view_status: bool
    can_wake: bool
    can_request_shutdown: bool
    can_manage_schedule: bool


class DeviceMembershipCreate(BaseModel):
    user_id: int
    device_id: str
    can_view_status: bool = True
    can_wake: bool = True
    can_request_shutdown: bool = True
    can_manage_schedule: bool = False
    is_favorite: bool = False
    sort_order: int = 0


class DeviceMembershipUpdate(BaseModel):
    can_view_status: bool | None = None
    can_wake: bool | None = None
    can_request_shutdown: bool | None = None
    can_manage_schedule: bool | None = None
    is_favorite: bool | None = None
    sort_order: int | None = None


class MyDevicePreferencesUpdate(BaseModel):
    is_favorite: bool | None = None
    sort_order: int | None = None


class DeviceMembershipOut(BaseModel):
    id: str
    user_id: int
    device_id: str
    username: str | None = None
    device_name: str | None = None
    device_display_name: str | None = None
    can_view_status: bool
    can_wake: bool
    can_request_shutdown: bool
    can_manage_schedule: bool
    is_favorite: bool
    sort_order: int
    created_at: datetime
    updated_at: datetime


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


class ScheduledWakeSummaryOut(BaseModel):
    total_count: int
    enabled_count: int
    next_run_at: datetime | None = None


class MyDeviceOut(BaseModel):
    id: str
    name: str
    display_name: str | None = None
    mac: str
    group_name: str | None = None
    is_favorite: bool
    sort_order: int
    permissions: DevicePermissionsOut
    last_power_state: Literal["on", "off", "unknown"] = "unknown"
    last_power_checked_at: datetime | None = None
    is_stale: bool
    scheduled_wake_summary: ScheduledWakeSummaryOut | None = None


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


class ScheduledWakeCreate(BaseModel):
    device_id: str
    label: str
    enabled: bool = True
    timezone: str
    days_of_week: list[str]
    local_time: str


class ScheduledWakeUpdate(BaseModel):
    device_id: str | None = None
    label: str | None = None
    enabled: bool | None = None
    timezone: str | None = None
    days_of_week: list[str] | None = None
    local_time: str | None = None


class ScheduledWakeOut(BaseModel):
    id: str
    device_id: str
    device_name: str | None = None
    device_display_name: str | None = None
    label: str
    enabled: bool
    timezone: str
    days_of_week: list[str]
    local_time: str
    next_run_at: datetime | None = None
    last_run_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class ScheduledWakeRunOut(BaseModel):
    id: str
    job_id: str
    device_id: str
    started_at: datetime
    finished_at: datetime | None = None
    result: Literal["sent", "already_on", "failed", "skipped"]
    detail: str | None = None
    wake_log_id: int | None = None


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
