from __future__ import annotations

import html
import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse

from fastapi import APIRouter, BackgroundTasks, Form, HTTPException, Request, status
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse

from .config import get_settings
from .discovery import collect_discovery_candidates, discover_sender_bindings, normalize_source_bindings, summarize_candidates
from .diagnostics import device_diagnostic_hints
from .network import build_network_diagnostics_snapshot
from .db import (
    complete_discovery_run,
    count_admin_users,
    create_host,
    create_device_membership,
    create_discovery_candidate,
    create_discovery_run,
    create_scheduled_wake_job,
    create_user,
    delete_scheduled_wake_job,
    delete_device_membership,
    delete_host,
    delete_user,
    fail_discovery_run,
    get_discovery_candidate,
    get_discovery_run,
    get_device_membership_by_id,
    get_device_membership_for_user_device,
    get_host_by_mac,
    get_host_by_id,
    get_scheduled_wake_job,
    get_user_by_id,
    get_user_by_username,
    enable_user_mfa,
    list_discovery_candidates,
    list_discovery_events,
    list_discovery_runs,
    list_admin_audit_logs,
    list_app_installations,
    list_device_memberships,
    list_hosts,
    list_power_check_logs,
    list_scheduled_wake_jobs,
    list_scheduled_wake_runs,
    list_users,
    list_wake_logs,
    log_admin_action,
    log_discovery_event,
    log_power_check,
    mark_discovery_candidate_imported,
    mark_discovery_run_running,
    update_scheduled_wake_job,
    update_device_membership,
    update_host,
    update_host_power_state,
    update_user_password_by_id,
    update_user_role,
)
from .power import run_power_check
from .password_policy import min_password_length_for_role
from .rate_limit import get_rate_limiter
from .request_context import (
    AUTHENTICATED_TLS_REQUIRED_DETAIL,
    LOGIN_TLS_REQUIRED_DETAIL,
    get_request_ip,
    is_auth_transport_allowed,
    is_https_request,
)
from .scheduled_wakes import DAY_ORDER, compute_next_run_at_iso, normalize_schedule_definition, parse_days_of_week_json
from .security import (
    build_totp_otpauth_uri,
    create_state_token,
    create_token,
    decode_state_token,
    decode_token,
    decrypt_secret_value,
    encrypt_secret_value,
    generate_totp_secret,
    hash_password,
    verify_password,
    verify_totp_code,
)
from .security_status import build_security_status
from .telemetry import get_counters, get_recent_events, increment_counter, structured_log
from .wol import normalize_mac, resolve_target, send_magic_packet

router = APIRouter(prefix="/admin/ui", tags=["admin-ui"])
_STATIC_DIR = Path(__file__).with_name("static")
_FAVICON_PATH = _STATIC_DIR / "favicon.png"

_SUPPORTED_LANGS = {"en", "de"}
_ADMIN_UI_COOKIE_PATH = "/admin/ui"
_ADMIN_UI_SESSION_COOKIE = "admin_session"
_ADMIN_UI_PENDING_COOKIE = "admin_pending_session"
_ADMIN_UI_CSRF_COOKIE = "admin_ui_csrf"
_ADMIN_UI_CSRF_FIELD = "csrf_token"
_INVALID_CSRF_DETAIL = "Invalid CSRF token"
_INVALID_ADMIN_UI_ORIGIN_DETAIL = "Admin UI POST origin is not allowed"
_ADMIN_PENDING_STATE_TYPE = "admin_ui_pending"
_ADMIN_PENDING_PURPOSE_VERIFY = "verify"
_ADMIN_PENDING_PURPOSE_SETUP = "setup"


def _security_ui_event(request: Request, *, counter: str, event: str, reason: str, **fields: object) -> None:
    increment_counter(counter)
    structured_log(
        event,
        reason=reason,
        path=request.url.path,
        method=request.method,
        client_ip=get_request_ip(request, get_settings()) or "unknown",
        **fields,
    )


def _default_port_for_scheme(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _normalize_origin_value(raw_value: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlparse(raw_value)
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    return (scheme, parsed.hostname.lower(), port or _default_port_for_scheme(scheme))


def _expected_admin_origin(request: Request) -> tuple[str, str, int] | None:
    settings = get_settings()
    scheme = "https" if is_https_request(request, settings) else request.url.scheme.lower()
    host = (request.headers.get("host") or request.url.netloc or "").strip()
    if not host:
        return None
    return _normalize_origin_value(f"{scheme}://{host}")


def _validate_admin_ui_post_origin(request: Request) -> None:
    expected_origin = _expected_admin_origin(request)
    if expected_origin is None:
        _security_ui_event(
            request,
            counter="security.admin_ui.origin_failed",
            event="security.admin_ui.origin_failed",
            reason="missing_expected_origin",
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=_INVALID_ADMIN_UI_ORIGIN_DETAIL)

    origin = (request.headers.get("origin") or "").strip()
    if origin:
        if _normalize_origin_value(origin) != expected_origin:
            _security_ui_event(
                request,
                counter="security.admin_ui.origin_failed",
                event="security.admin_ui.origin_failed",
                reason="origin_mismatch",
                origin=origin,
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=_INVALID_ADMIN_UI_ORIGIN_DETAIL)
        return

    referer = (request.headers.get("referer") or "").strip()
    if referer and _normalize_origin_value(referer) == expected_origin:
        return

    _security_ui_event(
        request,
        counter="security.admin_ui.origin_failed",
        event="security.admin_ui.origin_failed",
        reason="referer_mismatch",
        referer=referer or None,
    )
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=_INVALID_ADMIN_UI_ORIGIN_DETAIL)


def _sign_csrf_nonce(nonce: str) -> str:
    return hmac.new(
        get_settings().app_secret.encode("utf-8"),
        nonce.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _build_csrf_token() -> str:
    nonce = secrets.token_urlsafe(32)
    return f"{nonce}.{_sign_csrf_nonce(nonce)}"


def _is_valid_csrf_token(token: str | None) -> bool:
    if not token:
        return False
    nonce, separator, signature = token.partition(".")
    if not separator or not nonce or not signature:
        return False
    return hmac.compare_digest(signature, _sign_csrf_nonce(nonce))


def _get_or_create_csrf_token(request: Request) -> str:
    cached = getattr(request.state, "admin_ui_csrf_token", None)
    if isinstance(cached, str) and _is_valid_csrf_token(cached):
        return cached
    cookie_token = (request.cookies.get(_ADMIN_UI_CSRF_COOKIE) or "").strip()
    token = cookie_token if _is_valid_csrf_token(cookie_token) else _build_csrf_token()
    request.state.admin_ui_csrf_token = token
    return token


def _apply_csrf_cookie(request: Request, response, *, rotate: bool = False) -> None:
    existing_cookie = (request.cookies.get(_ADMIN_UI_CSRF_COOKIE) or "").strip()
    if rotate:
        token = _build_csrf_token()
        request.state.admin_ui_csrf_token = token
    else:
        token = _get_or_create_csrf_token(request)
        if existing_cookie == token:
            return
    response.set_cookie(
        _ADMIN_UI_CSRF_COOKIE,
        token,
        httponly=True,
        samesite="strict",
        secure=is_https_request(request, get_settings()),
        path=_ADMIN_UI_COOKIE_PATH,
    )


def _delete_csrf_cookie(response) -> None:
    response.delete_cookie(_ADMIN_UI_CSRF_COOKIE, path=_ADMIN_UI_COOKIE_PATH)


def _csrf_form_input(request: Request) -> str:
    return (
        f'<input type="hidden" name="{_ADMIN_UI_CSRF_FIELD}" '
        f'value="{_esc(_get_or_create_csrf_token(request))}" />'
    )


async def enforce_admin_ui_post_request(request: Request) -> None:
    settings = get_settings()
    if request.url.path == "/admin/ui/login":
        if not is_auth_transport_allowed(request, settings):
            _security_ui_event(
                request,
                counter="security.transport_auth.blocked",
                event="security.transport_auth.blocked",
                reason="https_required",
                detail=LOGIN_TLS_REQUIRED_DETAIL,
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=LOGIN_TLS_REQUIRED_DETAIL)
    elif (_admin_from_cookie(request) or _pending_admin_from_cookie(request)) and not is_auth_transport_allowed(request, settings):
        _security_ui_event(
            request,
            counter="security.transport_auth.blocked",
            event="security.transport_auth.blocked",
            reason="https_required",
            detail=AUTHENTICATED_TLS_REQUIRED_DETAIL,
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=AUTHENTICATED_TLS_REQUIRED_DETAIL)
    _validate_admin_ui_post_origin(request)
    request_body = (await request.body()).decode("utf-8", "replace")
    submitted_value = ""
    for key, value in parse_qsl(request_body, keep_blank_values=True):
        if key == _ADMIN_UI_CSRF_FIELD:
            submitted_value = value
            break
    expected_token = _get_or_create_csrf_token(request)
    if not submitted_value or not _is_valid_csrf_token(submitted_value):
        _security_ui_event(
            request,
            counter="security.admin_ui.csrf_failed",
            event="security.admin_ui.csrf_failed",
            reason="missing_or_invalid_token",
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=_INVALID_CSRF_DETAIL)
    if not hmac.compare_digest(submitted_value, expected_token):
        _security_ui_event(
            request,
            counter="security.admin_ui.csrf_failed",
            event="security.admin_ui.csrf_failed",
            reason="token_mismatch",
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=_INVALID_CSRF_DETAIL)

_I18N = {
    "en": {
        "nav_dashboard": "Dashboard",
        "nav_users": "Users",
        "nav_devices": "Devices",
        "nav_scheduled_wakes": "Scheduled Wakes",
        "nav_device_access": "Device Access",
        "nav_invites": "Invites",
        "nav_diagnostics": "Diagnostics",
        "nav_discovery": "Discovery",
        "nav_wake_logs": "Wake Logs",
        "nav_power_logs": "Power Logs",
        "nav_audit_logs": "Audit Logs",
        "nav_metrics": "Metrics",
        "nav_mfa": "MFA",
        "nav_pilot_metrics": "Pilot Metrics",
        "nav_logout": "Logout",
        "signed_in_as": "Signed in as",
        "language": "Language",
        "lang_en": "English",
        "lang_de": "Deutsch",
        "title_admin_login": "Admin Login",
        "label_username": "Username",
        "label_password": "Password",
        "label_totp_code": "Authenticator code",
        "action_login": "Login",
        "action_verify_mfa": "Verify code",
        "action_enable_mfa": "Enable MFA",
        "error_invalid_admin_credentials": "Invalid admin credentials",
        "error_too_many_login_attempts": "Too many login attempts. Please try again in a minute.",
        "error_invalid_mfa_code": "Invalid authenticator code",
        "error_too_many_mfa_attempts": "Too many MFA verification attempts. Please try again in a minute.",
        "error_mfa_pending_expired": "MFA session expired. Please sign in again.",
        "title_admin_dashboard": "Admin Dashboard",
        "title_admin_mfa": "Admin MFA",
        "title_admin_mfa_verify": "Verify MFA",
        "title_admin_mfa_setup": "Set up MFA",
        "title_users": "Users",
        "title_devices": "Devices",
        "title_scheduled_wakes": "Scheduled Wakes",
        "title_new_scheduled_wake": "New Scheduled Wake",
        "title_edit_scheduled_wake": "Edit Scheduled Wake",
        "title_device_access": "Device Access",
        "title_invites": "Invites",
        "title_wake_logs": "Wake Logs",
        "title_power_check_logs": "Power Check Logs",
        "title_diagnostics": "Diagnostics",
        "title_discovery": "Discovery",
        "title_audit_logs": "Audit Logs",
        "title_metrics": "Metrics",
        "title_pilot_metrics": "Pilot Metrics",
        "card_users": "Users",
        "card_devices": "Devices",
        "card_scheduled_wakes": "Scheduled Wakes",
        "card_device_access": "Device Access",
        "card_invites": "Invites",
        "heading_recent_wake_logs": "Recent Wake Logs",
        "heading_recent_power_checks": "Recent Power Checks",
        "heading_create_user": "Create User",
        "heading_users": "Users",
        "heading_create_device": "Create Device",
        "heading_devices": "Devices",
        "heading_schedule_filters": "Schedule Filters",
        "heading_scheduled_wakes": "Scheduled Wakes",
        "heading_create_scheduled_wake": "Create Scheduled Wake",
        "heading_edit_scheduled_wake": "Edit Scheduled Wake",
        "heading_recent_scheduled_wake_runs": "Recent Scheduled Wake Runs",
        "heading_grant_device_access": "Grant Device Access",
        "heading_device_access": "Current Device Access",
        "heading_new_invite": "New Invite",
        "heading_create_invite": "Create Invite",
        "heading_invites": "Invites",
        "heading_wake_logs": "Wake Logs",
        "heading_power_check_logs": "Power Check Logs",
        "heading_network_interfaces": "Network Interfaces",
        "heading_discovery_scan": "Run Discovery Scan",
        "heading_discovery_runs": "Discovery Runs",
        "heading_discovery_candidates": "Discovery Candidates",
        "heading_device_diagnostics_hints": "Device Diagnostics Hints",
        "heading_admin_audit_logs": "Admin Audit Logs",
        "heading_mfa_status": "MFA Status",
        "heading_mfa_setup": "Set Up Authenticator App",
        "heading_runtime_counters": "Runtime Counters",
        "heading_pilot_metrics": "Pilot Metrics",
        "col_id": "ID",
        "col_user_id": "User ID",
        "col_user": "User",
        "col_username": "Username",
        "col_role": "Role",
        "col_created": "Created",
        "col_updated": "Updated",
        "col_created_by": "Created By",
        "col_update": "Update",
        "col_delete": "Delete",
        "col_name": "Name",
        "col_label": "Label",
        "col_enabled": "Enabled",
        "col_interface": "Interface",
        "col_display": "Display",
        "col_mac": "MAC",
        "col_ipv4": "IPv4",
        "col_netmask": "Netmask",
        "col_network": "Network",
        "col_broadcast": "Broadcast",
        "col_up": "Up",
        "col_loopback": "Loopback",
        "col_method": "Method",
        "col_target": "Target",
        "col_port": "Port",
        "col_state": "State",
        "col_checked_at": "Checked At",
        "col_timezone": "Timezone",
        "col_days": "Days",
        "col_local_time": "Local Time",
        "col_next_run": "Next Run",
        "col_last_run": "Last Run",
        "col_recent_result": "Recent Result",
        "col_started_at": "Started At",
        "col_finished_at": "Finished At",
        "col_schedules": "Schedules",
        "col_diagnostics": "Diagnostics",
        "col_actions": "Actions",
        "col_device_id": "Device ID",
        "col_device": "Device",
        "col_action": "Action",
        "col_backend_hint": "Backend Hint",
        "col_expires_at": "Expires At",
        "col_claimed_at": "Claimed At",
        "col_host_id": "Host ID",
        "col_actor": "Actor",
        "col_result": "Result",
        "col_time": "Time",
        "col_precheck": "Precheck",
        "col_error": "Error",
        "col_detail": "Detail",
        "col_latency_ms": "Latency ms",
        "col_hints": "Hints",
        "col_target_type": "Target Type",
        "col_target_id": "Target ID",
        "col_counter": "Counter",
        "col_value": "Value",
        "col_run_id": "Run ID",
        "col_status": "Status",
        "col_summary": "Summary",
        "col_view_status": "View Status",
        "col_wake": "Wake",
        "col_request_shutdown": "Shutdown",
        "col_manage_schedule": "Manage Schedule",
        "col_favorite": "Favorite",
        "col_sort_order": "Sort Order",
        "col_wol_confidence": "WoL Confidence",
        "col_source_network": "Source Network",
        "col_imported_host": "Imported Host",
        "col_suggested_host": "Suggested Host",
        "col_first_successful_wake": "First Successful Wake",
        "col_seconds": "Seconds",
        "col_within_2m": "Within 2m",
        "placeholder_new_password_optional": "new password (optional)",
        "placeholder_username": "username",
        "placeholder_password_min12": "password (>=10 user, >=12 admin)",
        "placeholder_display_name": "display name",
        "placeholder_check_target": "check target",
        "placeholder_check_port": "check port",
        "placeholder_group": "group",
        "placeholder_broadcast_ip": "broadcast ip",
        "placeholder_subnet_cidr": "subnet cidr",
        "placeholder_udp_port": "udp port",
        "placeholder_interface": "interface",
        "placeholder_name": "name",
        "placeholder_backend_url_hint_optional": "backend url hint (optional)",
        "placeholder_hours": "hours",
        "placeholder_host_id_filter": "host id filter",
        "placeholder_network_cidrs": "network cidrs (comma separated, optional)",
        "placeholder_power_ports": "power probe ports, e.g. 22,80,443,445",
        "placeholder_actor_filter": "actor filter",
        "placeholder_device_id_filter": "device id filter",
        "placeholder_sort_order": "sort order",
        "option_all_results": "all results",
        "option_all_methods": "all methods",
        "action_save": "Save",
        "action_delete": "Delete",
        "action_edit": "Edit",
        "action_create": "Create",
        "action_create_schedule": "Create Schedule",
        "action_update_schedule": "Update Schedule",
        "action_enable": "Enable",
        "action_disable": "Disable",
        "action_manage_schedules": "Manage Schedules",
        "action_add_schedule": "Add Schedule",
        "action_test_power_check": "Test Power Check",
        "action_grant_access": "Grant access",
        "action_remove": "Remove access",
        "action_create_invite": "Create Invite",
        "action_revoke": "Revoke",
        "action_filter": "Filter",
        "action_cancel": "Cancel",
        "heading_discovery_events": "Events",
        "action_run_discovery": "Run Discovery",
        "action_validate_wake": "Validate Wake",
        "action_import_candidate": "Import",
        "action_merge_suggested": "Merge Suggested",
        "action_bulk_import": "Bulk Import",
        "confirm_delete_user": "Delete user '{username}'?",
        "confirm_delete_device": "Delete device '{device}'?",
        "confirm_delete_schedule": "Delete scheduled wake '{label}'?",
        "confirm_remove_device_access": "Remove access for '{username}' to '{device}'?",
        "confirm_revoke_invite": "Revoke this invite?",
        "label_token": "Token",
        "label_link": "Link",
        "label_can_view_status": "Can view status",
        "label_can_wake": "Can wake",
        "label_can_request_shutdown": "Can request shutdown",
        "label_can_manage_schedule": "Can manage schedule",
        "label_is_favorite": "Favorite",
        "label_sort_order": "Sort order",
        "label_enabled": "Enabled",
        "label_timezone": "Timezone",
        "label_days_of_week": "Days of week",
        "label_local_time": "Local time",
        "label_filter_enabled": "Enabled state",
        "alt_invite_qr_code": "Invite QR Code",
        "error_invalid_role": "Invalid role",
        "error_password_min_length_user": "Password must be at least 10 characters",
        "error_password_min_length_admin": "Admin password must be at least 12 characters",
        "error_admin_promotion_requires_password": "Promoting to admin requires setting a new admin password",
        "error_username_exists": "Username already exists",
        "error_user_not_found": "User not found",
        "error_cannot_demote_last_admin": "Cannot demote last admin",
        "error_cannot_delete_last_admin": "Cannot delete last admin",
        "error_invalid_check_method": "Invalid check_method",
        "error_check_port_integer": "check_port must be integer",
        "error_invalid_timezone": "Invalid timezone",
        "error_invalid_local_time": "local_time must use HH:MM",
        "error_schedule_days_required": "Select at least one day",
        "error_schedule_label_required": "Label is required",
        "error_schedule_not_found": "Scheduled wake not found",
        "error_sort_order_integer": "sort_order must be integer",
        "error_device_not_found": "Device not found",
        "error_device_access_not_found": "Membership not found",
        "error_username_not_found": "Username not found",
        "error_expires_in_hours_range": "expires_in_hours out of range",
        "error_invite_not_found_or_claimed": "Invite not found or already claimed",
        "msg_user_created": "User '{username}' created",
        "msg_user_updated": "Updated user '{username}'",
        "msg_user_deleted": "Deleted user '{username}'",
        "msg_device_created": "Created device {device_id}",
        "msg_device_updated": "Updated device {device_id}",
        "msg_device_deleted": "Deleted device {device_id}",
        "msg_schedule_created": "Created scheduled wake '{label}'",
        "msg_schedule_updated": "Updated scheduled wake '{label}'",
        "msg_schedule_deleted": "Deleted scheduled wake '{label}'",
        "msg_schedule_enabled": "Enabled scheduled wake '{label}'",
        "msg_schedule_disabled": "Disabled scheduled wake '{label}'",
        "msg_power_check_result": "Power check {result} ({detail})",
        "msg_membership_created": "Granted device access for '{username}' to '{device}'",
        "msg_membership_updated": "Updated permissions for '{username}' on '{device}'",
        "msg_membership_deleted": "Removed device access for '{username}' to '{device}'",
        "msg_invite_created_for": "Invite created for {username}",
        "msg_invite_revoked": "Invite revoked",
        "msg_discovery_run_started": "Discovery run started: {run_id}",
        "msg_discovery_candidate_imported": "Candidate imported to host {host_id}",
        "msg_discovery_validate_result": "Validation result: {result} ({detail})",
        "msg_discovery_bulk_imported": "Bulk import complete: imported={imported}, merged={merged}, created={created}, skipped={skipped}, failed={failed}",
        "text_total_claimed_users": "Total claimed users",
        "text_detected_networks": "Detected IPv4 networks",
        "text_multiple_networks_available": "Multiple active networks available",
        "text_users_first_success_2m": "Users with first successful wake within 2 min",
        "text_completion_rate_2m": "Completion rate within 2 min",
        "text_target_90": "target: 90%",
        "value_yes": "yes",
        "value_no": "no",
        "text_no_schedules": "No scheduled wakes found.",
        "text_no_schedule_runs": "No recent scheduled wake runs found.",
        "text_schedule_summary_none": "No schedules",
        "text_schedule_summary_disabled": "{total} configured, all disabled",
        "text_schedule_summary_active": "{enabled} active of {total}",
        "option_all_devices": "all devices",
        "option_enabled_all": "all",
        "option_enabled_only": "enabled only",
        "option_disabled_only": "disabled only",
        "day_mon": "Mon",
        "day_tue": "Tue",
        "day_wed": "Wed",
        "day_thu": "Thu",
        "day_fri": "Fri",
        "day_sat": "Sat",
        "day_sun": "Sun",
        "error_discovery_disabled": "Discovery feature is disabled",
        "error_no_discovery_bindings": "No valid discovery source bindings available",
        "text_active_sender_bindings": "Active sender bindings",
        "text_mfa_enabled": "MFA is enabled for this admin account.",
        "text_mfa_not_enabled": "MFA is not enabled for this admin account yet.",
        "text_mfa_required_rollout": "Browser admin logins now support staged TOTP rollout. When ADMIN_MFA_REQUIRED=true, non-enrolled admins are restricted to setup until MFA is enabled.",
        "text_mfa_verify_intro": "Enter the current 6-digit code from your authenticator app to finish the admin browser login.",
        "text_mfa_setup_intro": "Scan or enter this secret in an authenticator app, then submit the current 6-digit code to enable MFA.",
        "text_mfa_recovery_hint": "Break-glass recovery: python -m app.cli admin-disable-mfa --username {username}",
        "text_mfa_enabled_at": "Enabled at: {enabled_at}",
        "label_mfa_issuer": "Issuer",
        "label_mfa_account": "Account label",
        "label_mfa_secret": "Manual secret",
        "label_mfa_otpauth_uri": "otpauth URI",
        "label_import_mode": "Import mode",
        "option_auto_merge_by_mac": "auto merge by MAC",
        "option_create_new": "create new only",
        "empty_state": "No records found",
        "nav_section_management": "MANAGEMENT",
        "nav_section_scheduling": "SCHEDULING",
        "nav_section_logs": "LOGS",
        "nav_section_system": "SYSTEM",
    },
    "de": {
        "nav_dashboard": "Dashboard",
        "nav_users": "Benutzer",
        "nav_devices": "Geräte",
        "nav_scheduled_wakes": "Geplante Wakes",
        "nav_device_access": "Gerätezugriff",
        "nav_invites": "Einladungen",
        "nav_diagnostics": "Diagnose",
        "nav_discovery": "Discovery",
        "nav_wake_logs": "Wake-Logs",
        "nav_power_logs": "Power-Logs",
        "nav_audit_logs": "Audit-Logs",
        "nav_metrics": "Metriken",
        "nav_mfa": "MFA",
        "nav_pilot_metrics": "Pilot-Metriken",
        "nav_logout": "Abmelden",
        "signed_in_as": "Angemeldet als",
        "language": "Sprache",
        "lang_en": "English",
        "lang_de": "Deutsch",
        "title_admin_login": "Admin-Login",
        "label_username": "Benutzername",
        "label_password": "Passwort",
        "label_totp_code": "Authenticator-Code",
        "action_login": "Anmelden",
        "action_verify_mfa": "Code prüfen",
        "action_enable_mfa": "MFA aktivieren",
        "error_invalid_admin_credentials": "Ungültige Admin-Zugangsdaten",
        "error_too_many_login_attempts": "Zu viele Login-Versuche. Bitte in einer Minute erneut versuchen.",
        "error_invalid_mfa_code": "Ungültiger Authenticator-Code",
        "error_too_many_mfa_attempts": "Zu viele MFA-Prüfversuche. Bitte in einer Minute erneut versuchen.",
        "error_mfa_pending_expired": "Die MFA-Sitzung ist abgelaufen. Bitte erneut anmelden.",
        "title_admin_dashboard": "Admin-Dashboard",
        "title_admin_mfa": "Admin-MFA",
        "title_admin_mfa_verify": "MFA prüfen",
        "title_admin_mfa_setup": "MFA einrichten",
        "title_users": "Benutzer",
        "title_devices": "Geräte",
        "title_scheduled_wakes": "Geplante Wakes",
        "title_new_scheduled_wake": "Geplanten Wake anlegen",
        "title_edit_scheduled_wake": "Geplanten Wake bearbeiten",
        "title_device_access": "Gerätezugriff",
        "title_invites": "Einladungen",
        "title_wake_logs": "Wake-Logs",
        "title_power_check_logs": "Power-Check-Logs",
        "title_diagnostics": "Diagnose",
        "title_discovery": "Discovery",
        "title_audit_logs": "Audit-Logs",
        "title_metrics": "Metriken",
        "title_pilot_metrics": "Pilot-Metriken",
        "card_users": "Benutzer",
        "card_devices": "Geräte",
        "card_scheduled_wakes": "Geplante Wakes",
        "card_device_access": "Gerätezugriff",
        "card_invites": "Einladungen",
        "heading_recent_wake_logs": "Neueste Wake-Logs",
        "heading_recent_power_checks": "Neueste Power-Checks",
        "heading_create_user": "Benutzer erstellen",
        "heading_users": "Benutzer",
        "heading_create_device": "Gerät erstellen",
        "heading_devices": "Geräte",
        "heading_schedule_filters": "Schedule-Filter",
        "heading_scheduled_wakes": "Geplante Wakes",
        "heading_create_scheduled_wake": "Geplanten Wake anlegen",
        "heading_edit_scheduled_wake": "Geplanten Wake bearbeiten",
        "heading_recent_scheduled_wake_runs": "Letzte Läufe geplanter Wakes",
        "heading_grant_device_access": "Gerätezugriff vergeben",
        "heading_device_access": "Aktueller Gerätezugriff",
        "heading_new_invite": "Neue Einladung",
        "heading_create_invite": "Einladung erstellen",
        "heading_invites": "Einladungen",
        "heading_wake_logs": "Wake-Logs",
        "heading_power_check_logs": "Power-Check-Logs",
        "heading_network_interfaces": "Netzwerkschnittstellen",
        "heading_discovery_scan": "Discovery-Scan starten",
        "heading_discovery_runs": "Discovery-Läufe",
        "heading_discovery_candidates": "Discovery-Kandidaten",
        "heading_device_diagnostics_hints": "Diagnosehinweise für Geräte",
        "heading_admin_audit_logs": "Admin-Audit-Logs",
        "heading_mfa_status": "MFA-Status",
        "heading_mfa_setup": "Authenticator-App einrichten",
        "heading_runtime_counters": "Laufzeit-Zähler",
        "heading_pilot_metrics": "Pilot-Metriken",
        "col_id": "ID",
        "col_user_id": "Benutzer-ID",
        "col_user": "Benutzer",
        "col_username": "Benutzername",
        "col_role": "Rolle",
        "col_created": "Erstellt",
        "col_updated": "Aktualisiert",
        "col_created_by": "Erstellt von",
        "col_update": "Aktualisieren",
        "col_delete": "Löschen",
        "col_name": "Name",
        "col_label": "Bezeichnung",
        "col_enabled": "Aktiv",
        "col_interface": "Interface",
        "col_display": "Anzeige",
        "col_mac": "MAC",
        "col_ipv4": "IPv4",
        "col_netmask": "Netzmaske",
        "col_network": "Netz",
        "col_broadcast": "Broadcast",
        "col_up": "Aktiv",
        "col_loopback": "Loopback",
        "col_method": "Methode",
        "col_target": "Ziel",
        "col_port": "Port",
        "col_state": "Status",
        "col_checked_at": "Geprüft am",
        "col_timezone": "Zeitzone",
        "col_days": "Tage",
        "col_local_time": "Lokale Uhrzeit",
        "col_next_run": "Nächster Lauf",
        "col_last_run": "Letzter Lauf",
        "col_recent_result": "Letztes Ergebnis",
        "col_started_at": "Gestartet am",
        "col_finished_at": "Beendet am",
        "col_schedules": "Zeitpläne",
        "col_diagnostics": "Diagnose",
        "col_actions": "Aktionen",
        "col_device_id": "Geräte-ID",
        "col_device": "Gerät",
        "col_action": "Aktion",
        "col_backend_hint": "Backend-Hinweis",
        "col_expires_at": "Läuft ab",
        "col_claimed_at": "Eingelöst am",
        "col_host_id": "Host-ID",
        "col_actor": "Auslöser",
        "col_result": "Ergebnis",
        "col_time": "Zeit",
        "col_precheck": "Precheck",
        "col_error": "Fehler",
        "col_detail": "Detail",
        "col_latency_ms": "Latenz (ms)",
        "col_hints": "Hinweise",
        "col_target_type": "Zieltyp",
        "col_target_id": "Ziel-ID",
        "col_counter": "Zähler",
        "col_value": "Wert",
        "col_run_id": "Run-ID",
        "col_status": "Status",
        "col_summary": "Zusammenfassung",
        "col_view_status": "Status sehen",
        "col_wake": "Aufwecken",
        "col_request_shutdown": "Shutdown anfragen",
        "col_manage_schedule": "Zeitplan verwalten",
        "col_favorite": "Favorit",
        "col_sort_order": "Sortierung",
        "col_wol_confidence": "WoL-Vertrauen",
        "col_source_network": "Quellnetz",
        "col_imported_host": "Importierter Host",
        "col_suggested_host": "Vorgeschlagener Host",
        "col_first_successful_wake": "Erstes erfolgreiches Aufwecken",
        "col_seconds": "Sekunden",
        "col_within_2m": "Innerhalb von 2 Min.",
        "placeholder_new_password_optional": "Neues Passwort (optional)",
        "placeholder_username": "Benutzername",
        "placeholder_password_min12": "Passwort (mind. 10 Benutzer, mind. 12 Admin)",
        "placeholder_display_name": "Anzeigename",
        "placeholder_check_target": "Prüfziel",
        "placeholder_check_port": "Prüfport",
        "placeholder_group": "Gruppe",
        "placeholder_broadcast_ip": "Broadcast-IP",
        "placeholder_subnet_cidr": "Subnetz-CIDR",
        "placeholder_udp_port": "UDP-Port",
        "placeholder_interface": "Schnittstelle",
        "placeholder_name": "Name",
        "placeholder_backend_url_hint_optional": "Backend-URL-Hinweis (optional)",
        "placeholder_hours": "Stunden",
        "placeholder_host_id_filter": "Host-ID-Filter",
        "placeholder_network_cidrs": "Netz-CIDRs (kommagetrennt, optional)",
        "placeholder_power_ports": "Power-Probe-Ports, z. B. 22, 80, 443, 445",
        "placeholder_actor_filter": "Auslöser-Filter",
        "placeholder_device_id_filter": "Geräte-ID-Filter",
        "placeholder_sort_order": "Sortierung",
        "option_all_results": "Alle Ergebnisse",
        "option_all_methods": "Alle Methoden",
        "action_save": "Speichern",
        "action_delete": "Löschen",
        "action_edit": "Bearbeiten",
        "action_create": "Erstellen",
        "action_create_schedule": "Zeitplan anlegen",
        "action_update_schedule": "Zeitplan speichern",
        "action_enable": "Aktivieren",
        "action_disable": "Deaktivieren",
        "action_manage_schedules": "Zeitpläne verwalten",
        "action_add_schedule": "Zeitplan anlegen",
        "action_test_power_check": "Power-Check testen",
        "action_grant_access": "Zugriff vergeben",
        "action_remove": "Zugriff entfernen",
        "action_create_invite": "Einladung erstellen",
        "action_revoke": "Widerrufen",
        "action_filter": "Filtern",
        "action_cancel": "Abbrechen",
        "heading_discovery_events": "Ereignisse",
        "action_run_discovery": "Discovery starten",
        "action_validate_wake": "Wake validieren",
        "action_import_candidate": "Importieren",
        "action_merge_suggested": "Vorschlag zusammenführen",
        "action_bulk_import": "Bulk-Import",
        "confirm_delete_user": "Benutzer '{username}' löschen?",
        "confirm_delete_device": "Gerät '{device}' löschen?",
        "confirm_delete_schedule": "Geplanten Wake '{label}' löschen?",
        "confirm_remove_device_access": "Zugriff von '{username}' auf '{device}' entfernen?",
        "confirm_revoke_invite": "Diese Einladung widerrufen?",
        "label_token": "Token",
        "label_link": "Link",
        "label_can_view_status": "Status sehen",
        "label_can_wake": "Aufwecken",
        "label_can_request_shutdown": "Shutdown anfragen",
        "label_can_manage_schedule": "Zeitplan verwalten",
        "label_is_favorite": "Favorit",
        "label_sort_order": "Sortierung",
        "label_enabled": "Aktiv",
        "label_timezone": "Zeitzone",
        "label_days_of_week": "Wochentage",
        "label_local_time": "Lokale Uhrzeit",
        "label_filter_enabled": "Aktiv-Status",
        "alt_invite_qr_code": "Einladungs-QR-Code",
        "error_invalid_role": "Ungültige Rolle",
        "error_password_min_length_user": "Passwort muss mindestens 10 Zeichen haben",
        "error_password_min_length_admin": "Admin-Passwort muss mindestens 12 Zeichen haben",
        "error_admin_promotion_requires_password": "Für die Beförderung zum Admin muss ein neues Admin-Passwort gesetzt werden",
        "error_username_exists": "Benutzername existiert bereits",
        "error_user_not_found": "Benutzer nicht gefunden",
        "error_cannot_demote_last_admin": "Letzter Admin kann nicht herabgestuft werden",
        "error_cannot_delete_last_admin": "Letzter Admin kann nicht gelöscht werden",
        "error_invalid_check_method": "Ungültige check_method",
        "error_check_port_integer": "check_port muss eine ganze Zahl sein",
        "error_invalid_timezone": "Ungültige Zeitzone",
        "error_invalid_local_time": "local_time muss HH:MM verwenden",
        "error_schedule_days_required": "Mindestens ein Tag muss ausgewählt sein",
        "error_schedule_label_required": "Bezeichnung ist erforderlich",
        "error_schedule_not_found": "Geplanter Wake nicht gefunden",
        "error_sort_order_integer": "sort_order muss eine ganze Zahl sein",
        "error_device_not_found": "Gerät nicht gefunden",
        "error_device_access_not_found": "Mitgliedschaft nicht gefunden",
        "error_username_not_found": "Benutzername nicht gefunden",
        "error_expires_in_hours_range": "expires_in_hours außerhalb des Bereichs",
        "error_invite_not_found_or_claimed": "Einladung nicht gefunden oder bereits eingelöst",
        "msg_user_created": "Benutzer '{username}' erstellt",
        "msg_user_updated": "Benutzer '{username}' aktualisiert",
        "msg_user_deleted": "Benutzer '{username}' gelöscht",
        "msg_device_created": "Gerät {device_id} erstellt",
        "msg_device_updated": "Gerät {device_id} aktualisiert",
        "msg_device_deleted": "Gerät {device_id} gelöscht",
        "msg_schedule_created": "Geplanter Wake '{label}' erstellt",
        "msg_schedule_updated": "Geplanter Wake '{label}' aktualisiert",
        "msg_schedule_deleted": "Geplanter Wake '{label}' gelöscht",
        "msg_schedule_enabled": "Geplanter Wake '{label}' aktiviert",
        "msg_schedule_disabled": "Geplanter Wake '{label}' deaktiviert",
        "msg_power_check_result": "Power-Check {result} ({detail})",
        "msg_membership_created": "Gerätezugriff für '{username}' auf '{device}' vergeben",
        "msg_membership_updated": "Berechtigungen für '{username}' auf '{device}' aktualisiert",
        "msg_membership_deleted": "Gerätezugriff für '{username}' auf '{device}' entfernt",
        "msg_invite_created_for": "Einladung für {username} erstellt",
        "msg_invite_revoked": "Einladung widerrufen",
        "msg_discovery_run_started": "Discovery-Run gestartet: {run_id}",
        "msg_discovery_candidate_imported": "Kandidat in Host {host_id} importiert",
        "msg_discovery_validate_result": "Validierung: {result} ({detail})",
        "msg_discovery_bulk_imported": "Bulk-Import abgeschlossen: importiert={imported}, zusammengeführt={merged}, erstellt={created}, übersprungen={skipped}, fehlgeschlagen={failed}",
        "text_total_claimed_users": "Insgesamt eingelöste Benutzer",
        "text_detected_networks": "Erkannte IPv4-Netze",
        "text_multiple_networks_available": "Mehrere aktive Netzwerke verfügbar",
        "text_users_first_success_2m": "Benutzer mit erstem erfolgreichen Wake innerhalb von 2 Min.",
        "text_completion_rate_2m": "Abschlussrate innerhalb von 2 Min.",
        "text_target_90": "Ziel: 90%",
        "value_yes": "ja",
        "value_no": "nein",
        "text_no_schedules": "Keine geplanten Wakes gefunden.",
        "text_no_schedule_runs": "Keine letzten Läufe geplanter Wakes gefunden.",
        "text_schedule_summary_none": "Keine Zeitpläne",
        "text_schedule_summary_disabled": "{total} konfiguriert, alle deaktiviert",
        "text_schedule_summary_active": "{enabled} aktiv von {total}",
        "option_all_devices": "alle Geräte",
        "option_enabled_all": "alle",
        "option_enabled_only": "nur aktiv",
        "option_disabled_only": "nur deaktiviert",
        "day_mon": "Mo",
        "day_tue": "Di",
        "day_wed": "Mi",
        "day_thu": "Do",
        "day_fri": "Fr",
        "day_sat": "Sa",
        "day_sun": "So",
        "error_discovery_disabled": "Discovery-Funktion ist deaktiviert",
        "error_no_discovery_bindings": "Keine gültigen Discovery-Quellbindungen verfügbar",
        "text_active_sender_bindings": "Aktive Sender-Bindings",
        "text_mfa_enabled": "MFA ist für dieses Admin-Konto aktiviert.",
        "text_mfa_not_enabled": "MFA ist für dieses Admin-Konto noch nicht aktiviert.",
        "text_mfa_required_rollout": "Browser-Admin-Logins unterstützen jetzt einen gestuften TOTP-Rollout. Wenn ADMIN_MFA_REQUIRED=true gesetzt ist, bleiben nicht eingerichtete Admins auf den Setup-Flow beschränkt, bis MFA aktiviert wurde.",
        "text_mfa_verify_intro": "Gib den aktuellen 6-stelligen Code aus deiner Authenticator-App ein, um den Browser-Login abzuschließen.",
        "text_mfa_setup_intro": "Scanne oder übernimm dieses Secret in eine Authenticator-App und bestätige danach mit dem aktuellen 6-stelligen Code die Aktivierung von MFA.",
        "text_mfa_recovery_hint": "Break-Glass-Recovery: python -m app.cli admin-disable-mfa --username {username}",
        "text_mfa_enabled_at": "Aktiviert am: {enabled_at}",
        "label_mfa_issuer": "Issuer",
        "label_mfa_account": "Account-Label",
        "label_mfa_secret": "Manuelles Secret",
        "label_mfa_otpauth_uri": "otpauth-URI",
        "label_import_mode": "Import-Modus",
        "option_auto_merge_by_mac": "Automatisch per MAC zusammenführen",
        "option_create_new": "Nur neu erstellen",
        "empty_state": "Keine Einträge gefunden",
        "nav_section_management": "VERWALTUNG",
        "nav_section_scheduling": "PLANUNG",
        "nav_section_logs": "PROTOKOLLE",
        "nav_section_system": "SYSTEM",
    },
}


def _lang(request: Request) -> str:
    requested = request.query_params.get("lang", "").strip().lower()
    if requested in _SUPPORTED_LANGS:
        return requested
    cookie_lang = (request.cookies.get("admin_ui_lang") or "").strip().lower()
    if cookie_lang in _SUPPORTED_LANGS:
        return cookie_lang
    accept_language = (request.headers.get("accept-language") or "").lower()
    for segment in accept_language.split(","):
        code = segment.split(";")[0].strip()
        if code.startswith("de"):
            return "de"
        if code.startswith("en"):
            return "en"
    return "en"


def _tr(request: Request, key: str, **kwargs: object) -> str:
    lang = _lang(request)
    template = _I18N.get(lang, {}).get(key, _I18N["en"].get(key, key))
    return template.format(**kwargs)


def _with_lang(path: str, lang: str) -> str:
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}{urlencode({'lang': lang})}"


def _lang_switch_url(request: Request, lang: str) -> str:
    params = dict(request.query_params)
    params["lang"] = lang
    return f"{request.url.path}?{urlencode(params)}"


def _apply_lang_cookie(request: Request, response: HTMLResponse | RedirectResponse, lang: str | None = None) -> None:
    resolved = lang or _lang(request)
    if request.cookies.get("admin_ui_lang") != resolved:
        settings = get_settings()
        response.set_cookie(
            "admin_ui_lang",
            resolved,
            max_age=60 * 60 * 24 * 365,
            samesite="lax",
            secure=is_https_request(request, settings),
            path="/admin/ui",
        )


def _esc(value: object | None) -> str:
    if value is None:
        return ""
    return html.escape(str(value))


_BADGE_COLORS = {
    "sent": "#22a55a", "on": "#22a55a", "completed": "#22a55a", "enabled": "#22a55a", "high": "#22a55a",
    "already_on": "#3b82f6", "running": "#3b82f6",
    "failed": "#e53535", "error": "#e53535", "low": "#e53535",
    "off": "#8b92a8", "unknown": "#8b92a8", "disabled": "#8b92a8", "pending": "#8b92a8",
    "tcp": "#7c3aed", "icmp": "#0d9488",
    "admin": "#4f6ef7", "medium": "#e5930a",
    "user": "#8b92a8",
}


def _device_cell(device_id: str | None, name_map: dict[str, str]) -> str:
    did = str(device_id or "")
    name = name_map.get(did)
    if name:
        return f'<span title="{_esc(did)}">{_esc(name)}</span>'
    return _esc(did)


def _badge(value: str) -> str:
    color = _BADGE_COLORS.get(value.lower(), "#666")
    return f'<span class="badge" style="background:{color}">{_esc(value)}</span>'


def _short_id(val) -> str:
    s = str(val or "")
    if len(s) > 12:
        return f'<span title="{_esc(s)}">{_esc(s[:8])}\u2026</span>'
    return _esc(s)


def _empty_row(request: Request, colspan: int) -> str:
    return f'<tr><td colspan="{colspan}" style="text-align:center;padding:var(--space-6);color:var(--muted);font-style:italic">{_tr(request, "empty_state")}</td></tr>'


def _checkbox_checked(value: object) -> str:
    return "checked" if bool(value) else ""


def _bool_text(request: Request, value: object) -> str:
    return _tr(request, "value_yes") if bool(value) else _tr(request, "value_no")


def _bool_icon(val: object) -> str:
    return '<span style="color:var(--success)">&#10003;</span>' if val else '<span style="color:var(--muted)">&mdash;</span>'


def _form_checkbox(value: str) -> bool:
    return bool(value.strip())


def _device_membership_device_label(row: dict) -> str:
    display_name = str(row.get("device_display_name") or "").strip()
    name = str(row.get("device_name") or "").strip()
    device_id = str(row.get("device_id") or "").strip()
    if display_name and name and display_name != name:
        return f"{display_name} ({name})"
    if display_name:
        return display_name
    if name:
        return name
    return device_id


def _device_display_label(row: dict) -> str:
    display_name = str(row.get("display_name") or "").strip()
    name = str(row.get("name") or "").strip()
    device_id = str(row.get("id") or "").strip()
    if display_name and name and display_name != name:
        return f"{display_name} ({name})"
    if display_name:
        return display_name
    if name:
        return name
    return device_id


def _schedule_validation_error(request: Request, detail: str) -> str:
    mapping = {
        "Invalid timezone": "error_invalid_timezone",
        "timezone is required": "error_invalid_timezone",
        "local_time must use HH:MM": "error_invalid_local_time",
        "days_of_week must contain at least one day": "error_schedule_days_required",
        "days_of_week must contain only mon,tue,wed,thu,fri,sat,sun": "error_schedule_days_required",
    }
    key = mapping.get(detail)
    return _tr(request, key) if key else detail


def _schedule_day_label(request: Request, day: str) -> str:
    return _tr(request, f"day_{day}")


def _format_schedule_days(request: Request, days_of_week: list[str]) -> str:
    return ", ".join(_schedule_day_label(request, day) for day in days_of_week)


def _schedule_summary_text(request: Request, row: dict) -> str:
    total = int(row["scheduled_wake_total_count"] or 0)
    enabled = int(row["scheduled_wake_enabled_count"] or 0)
    if total <= 0:
        return _tr(request, "text_schedule_summary_none")
    if enabled <= 0:
        return _tr(request, "text_schedule_summary_disabled", total=total)
    return _tr(request, "text_schedule_summary_active", enabled=enabled, total=total)


def _schedule_filter_path(request: Request, *, device_id: str | None = None, enabled: str | None = None) -> str:
    params: dict[str, str] = {"lang": _lang(request)}
    if device_id:
        params["device_id"] = device_id
    if enabled:
        params["enabled"] = enabled
    return f"/admin/ui/scheduled-wakes?{urlencode(params)}"


def _schedule_form_path(request: Request, *, device_id: str | None = None) -> str:
    params: dict[str, str] = {"lang": _lang(request)}
    if device_id:
        params["device_id"] = device_id
    return f"/admin/ui/scheduled-wakes/new?{urlencode(params)}"


def _resolve_scheduled_wake_form_values(
    request: Request,
    *,
    device_id: str,
    label: str,
    enabled: bool,
    timezone_name: str,
    days_of_week: list[str],
    local_time: str,
    current_job: dict | None = None,
) -> dict[str, object]:
    resolved_device_id = device_id.strip() or str(current_job["device_id"] if current_job else "").strip()
    resolved_label = label.strip() or str(current_job["label"] if current_job else "").strip()

    if not resolved_label:
        raise ValueError(_tr(request, "error_schedule_label_required"))
    if not resolved_device_id or get_host_by_id(resolved_device_id) is None:
        raise ValueError(_tr(request, "error_device_not_found"))

    current_days = parse_days_of_week_json(str(current_job["days_of_week_json"])) if current_job else []
    raw_days = days_of_week or current_days
    raw_timezone = timezone_name.strip() or str(current_job["timezone"] if current_job else "").strip()
    raw_local_time = local_time.strip() or str(current_job["local_time"] if current_job else "").strip()

    try:
        normalized_timezone, normalized_days, normalized_local_time = normalize_schedule_definition(
            timezone_name=raw_timezone,
            days_of_week=raw_days,
            local_time=raw_local_time,
        )
    except ValueError as exc:
        raise ValueError(_schedule_validation_error(request, str(exc))) from exc

    next_run_at: str | None
    if enabled:
        next_run_at = compute_next_run_at_iso(
            timezone_name=normalized_timezone,
            days_of_week=normalized_days,
            local_time=normalized_local_time,
            now_utc=datetime.now(UTC),
        )
    else:
        next_run_at = None

    return {
        "device_id": resolved_device_id,
        "label": resolved_label,
        "enabled": enabled,
        "timezone": normalized_timezone,
        "days_of_week": normalized_days,
        "local_time": normalized_local_time,
        "next_run_at": next_run_at,
    }


def _scheduled_wake_form_body(
    request: Request,
    *,
    title: str,
    action_path: str,
    submit_label: str,
    devices: list[dict],
    values: dict[str, object],
    return_to: str,
) -> str:
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    csrf_input = _csrf_form_input(request)
    device_options = "".join(
        f'<option value="{_esc(row["id"])}" {"selected" if str(values.get("device_id") or "") == str(row["id"]) else ""}>'
        f'{_esc(_device_display_label(dict(row)))}</option>'
        for row in devices
    )
    selected_days = {str(day) for day in values.get("days_of_week", []) if str(day)}
    day_checkboxes = "".join(
        f'<label class="checkbox-item"><input type="checkbox" name="days_of_week" value="{day}" '
        f'{"checked" if day in selected_days else ""} />{_esc(_schedule_day_label(request, day))}</label>'
        for day in DAY_ORDER
    )
    checked = "checked" if bool(values.get("enabled", True)) else ""
    return f"""
    <article>
      <h2>{_esc(title)}</h2>
      <form method="post" action="{_esc(action_path)}" style="display:grid;gap:12px;max-width:760px;">
        {csrf_input}
        <input type="hidden" name="return_to" value="{_esc(return_to)}" />
        <label class="stacked-cell">{t("col_device")}
          <select name="device_id" required>{device_options}</select>
        </label>
        <label class="stacked-cell">{t("col_label")}
          <input name="label" required value="{_esc(values.get('label'))}" />
        </label>
        <label class="checkbox-item"><input type="checkbox" name="enabled" value="1" {checked} />{t("label_enabled")}</label>
        <label class="stacked-cell">{t("label_timezone")}
          <input name="timezone" required value="{_esc(values.get('timezone'))}" placeholder="Europe/Berlin" />
        </label>
        <label class="stacked-cell">{t("label_days_of_week")}
          <span class="checkbox-group">{day_checkboxes}</span>
        </label>
        <label class="stacked-cell">{t("label_local_time")}
          <input name="local_time" required value="{_esc(values.get('local_time'))}" placeholder="07:30" />
        </label>
        <div class="form-inline">
          <button type="submit">{_esc(submit_label)}</button>
          <a href="{_esc(_with_lang(return_to, _lang(request)))}">{t("action_manage_schedules")}</a>
        </div>
      </form>
    </article>
    """


def _safe_next_path(next_path: str | None) -> str:
    if not next_path:
        return "/admin/ui"
    candidate = next_path.strip()
    parsed = urlparse(candidate)
    if parsed.scheme or parsed.netloc:
        return "/admin/ui"
    if "\r" in candidate or "\n" in candidate:
        return "/admin/ui"
    if not candidate.startswith("/admin/ui"):
        return "/admin/ui"
    return candidate


def _is_user_mfa_enabled(user: dict | None) -> bool:
    if not user:
        return False
    return bool(user["mfa_enabled"]) and bool(str(user["mfa_totp_secret_encrypted"] or "").strip())


def _pending_state_path(pending_state: dict[str, object]) -> str:
    purpose = str(pending_state.get("purpose") or "")
    return "/admin/ui/mfa/setup" if purpose == _ADMIN_PENDING_PURPOSE_SETUP else "/admin/ui/mfa/verify"


def _pending_redirect(request: Request, pending_state: dict[str, object]) -> RedirectResponse:
    return RedirectResponse(
        _with_lang(_pending_state_path(pending_state), _lang(request)),
        status_code=303,
    )


def _set_admin_cookie(request: Request, response: RedirectResponse, name: str, value: str) -> None:
    response.set_cookie(
        name,
        value,
        httponly=True,
        samesite="strict",
        secure=is_https_request(request, get_settings()),
        path=_ADMIN_UI_COOKIE_PATH,
    )


def _delete_admin_cookie(response: RedirectResponse, name: str) -> None:
    response.delete_cookie(name, path=_ADMIN_UI_COOKIE_PATH)


def _build_pending_admin_state(
    user: dict,
    *,
    purpose: str,
    next_path: str,
    encrypted_secret: str | None = None,
) -> str:
    extra_claims: dict[str, object] = {
        "ver": int(user["token_version"] or 0),
        "purpose": purpose,
        "next": _safe_next_path(next_path),
    }
    if encrypted_secret:
        extra_claims["pending_secret"] = encrypted_secret
    return create_state_token(
        subject=str(user["username"]),
        state_type=_ADMIN_PENDING_STATE_TYPE,
        expires_seconds=get_settings().admin_mfa_pending_expires_seconds,
        extra_claims=extra_claims,
    )


def _pending_admin_from_cookie(request: Request) -> dict[str, object] | None:
    token = request.cookies.get(_ADMIN_UI_PENDING_COOKIE)
    if not token:
        return None
    try:
        payload = decode_state_token(token, expected_type=_ADMIN_PENDING_STATE_TYPE)
    except Exception:
        return None
    username = str(payload.get("sub") or "")
    user = get_user_by_username(username)
    if not user or user["role"] != "admin":
        return None
    try:
        payload_version = int(payload.get("ver", 0))
    except (TypeError, ValueError):
        return None
    if payload_version != int(user["token_version"] or 0):
        return None
    purpose = str(payload.get("purpose") or "")
    if purpose not in {_ADMIN_PENDING_PURPOSE_VERIFY, _ADMIN_PENDING_PURPOSE_SETUP}:
        return None
    pending_secret = payload.get("pending_secret")
    return {
        "user": user,
        "purpose": purpose,
        "next": _safe_next_path(str(payload.get("next") or "/admin/ui")),
        "pending_secret": str(pending_secret) if isinstance(pending_secret, str) and pending_secret else None,
    }


def _issue_full_admin_session_response(
    request: Request,
    *,
    user: dict,
    next_path: str,
    lang: str,
    message: str | None = None,
) -> RedirectResponse:
    token, _ = create_token(username=user["username"], role=user["role"], token_version=int(user["token_version"] or 0))
    if message:
        response = _redirect(next_path, message=message, request=request)
    else:
        response = RedirectResponse(_safe_next_path(next_path), status_code=303)
    _set_admin_cookie(request, response, _ADMIN_UI_SESSION_COOKIE, token)
    _delete_admin_cookie(response, _ADMIN_UI_PENDING_COOKIE)
    _apply_csrf_cookie(request, response, rotate=True)
    _apply_lang_cookie(request, response, lang)
    return response


def _clear_pending_admin_state(response: RedirectResponse) -> None:
    _delete_admin_cookie(response, _ADMIN_UI_PENDING_COOKIE)


def _redirect_to_login(request: Request, *, error: str | None = None, next_path: str | None = None) -> RedirectResponse:
    params = {"next": _safe_next_path(next_path), "lang": _lang(request)}
    if error:
        params["error"] = error
    response = RedirectResponse(f"/admin/ui/login?{urlencode(params)}", status_code=303)
    _clear_pending_admin_state(response)
    _apply_lang_cookie(request, response)
    return response


def _require_pending_admin(request: Request, *, purpose: str) -> dict[str, object] | RedirectResponse:
    pending_state = _pending_admin_from_cookie(request)
    if pending_state is None:
        _security_ui_event(
            request,
            counter="security.admin_ui.mfa.pending_expired",
            event="security.admin_ui.mfa.pending_expired",
            reason="missing_or_expired_pending_state",
        )
        return _redirect_to_login(request, error=_tr(request, "error_mfa_pending_expired"), next_path=request.url.path)
    if not is_auth_transport_allowed(request, get_settings()):
        _security_ui_event(
            request,
            counter="security.transport_auth.blocked",
            event="security.transport_auth.blocked",
            reason="https_required",
            detail=AUTHENTICATED_TLS_REQUIRED_DETAIL,
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=AUTHENTICATED_TLS_REQUIRED_DETAIL)
    if str(pending_state["purpose"]) != purpose:
        return _pending_redirect(request, pending_state)
    return pending_state


def _login_ip_key(request: Request) -> str:
    return get_request_ip(request, get_settings()) or "unknown"


def _is_login_rate_limited(request: Request) -> bool:
    ip_key = _login_ip_key(request)
    settings = get_settings()
    return get_rate_limiter().is_limited(
        scope="admin_ui_login",
        key=ip_key,
        limit=settings.login_rate_limit_per_minute,
        window_seconds=60,
    )


def _record_failed_login_attempt(request: Request) -> None:
    ip_key = _login_ip_key(request)
    get_rate_limiter().record_attempt(scope="admin_ui_login", key=ip_key, window_seconds=60)


def _admin_from_cookie(request: Request):
    token = request.cookies.get(_ADMIN_UI_SESSION_COOKIE)
    if not token:
        return None
    try:
        payload = decode_token(token)
    except Exception:
        return None
    if payload.get("role") != "admin":
        return None
    username = payload.get("sub", "")
    user = get_user_by_username(username)
    if not user or user["role"] != "admin":
        return None
    try:
        payload_version = int(payload.get("ver", 0))
    except (TypeError, ValueError):
        return None
    if payload_version != int(user["token_version"] or 0):
        return None
    return user


def _require_admin_or_redirect(request: Request):
    user = _admin_from_cookie(request)
    if user:
        if not is_auth_transport_allowed(request, get_settings()):
            _security_ui_event(
                request,
                counter="security.transport_auth.blocked",
                event="security.transport_auth.blocked",
                reason="https_required",
                detail=AUTHENTICATED_TLS_REQUIRED_DETAIL,
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=AUTHENTICATED_TLS_REQUIRED_DETAIL)
        if get_settings().admin_mfa_required and not _is_user_mfa_enabled(user) and request.url.path != "/admin/ui/mfa":
            return _redirect("/admin/ui/mfa", request=request)
        return user
    pending_state = _pending_admin_from_cookie(request)
    if pending_state:
        return _pending_redirect(request, pending_state)
    next_path = request.url.path
    if request.url.query:
        next_path = f"{next_path}?{request.url.query}"
    return _redirect_to_login(request, next_path=next_path)


def _layout(request: Request, title: str, body: str, admin_username: str, message: str | None = None, error: str | None = None) -> HTMLResponse:
    lang = _lang(request)
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    flashes = ""
    if message:
        flashes += f'<div class="flash flash-ok"><span>\u2713 {_esc(message)}</span><button class="flash-close" aria-label="dismiss">\u00d7</button></div>'
    if error:
        flashes += f'<div class="flash flash-err"><span>\u2715 {_esc(error)}</span><button class="flash-close" aria-label="dismiss">\u00d7</button></div>'
    cur = request.url.path

    def _nav(path: str, label: str) -> str:
        exact = path == "/admin/ui"
        is_active = (cur == path) if exact else (cur == path or cur.startswith(path + "/"))
        cur_attr = ' aria-current="page"' if is_active else ""
        return f'<a href="{_with_lang(path, lang)}"{cur_attr}>{label}</a>'

    sidebar = f"""<aside class="sidebar">
      <div class="sidebar-brand">WakeFromFar</div>
      <nav>
        <span class="nav-label">{t('nav_section_management')}</span>
        {_nav('/admin/ui', t('nav_dashboard'))}
        {_nav('/admin/ui/users', t('nav_users'))}
        {_nav('/admin/ui/devices', t('nav_devices'))}
        <span class="nav-label">{t('nav_section_scheduling')}</span>
        {_nav('/admin/ui/scheduled-wakes', t('nav_scheduled_wakes'))}
        {_nav('/admin/ui/device-memberships', t('nav_device_access'))}
        <span class="nav-label">{t('nav_section_logs')}</span>
        {_nav('/admin/ui/wake-logs', t('nav_wake_logs'))}
        {_nav('/admin/ui/power-check-logs', t('nav_power_logs'))}
        {_nav('/admin/ui/audit-logs', t('nav_audit_logs'))}
        <span class="nav-label">{t('nav_section_system')}</span>
        {_nav('/admin/ui/diagnostics', t('nav_diagnostics'))}
        {_nav('/admin/ui/discovery', t('nav_discovery'))}
        {_nav('/admin/ui/metrics', t('nav_metrics'))}
        {_nav('/admin/ui/mfa', t('nav_mfa'))}
      </nav>
      <div class="sidebar-footer">Admin Panel</div>
    </aside>"""

    css = """
:root{
  --sidebar-w:220px;--sidebar-bg:#1a1f2e;--sidebar-text:#b8c0d0;--sidebar-active:#fff;--sidebar-active-bg:rgba(255,255,255,.12);--topbar-h:56px;
  --bg:#f8f9fc;--fg:#1a1d26;--card-bg:#fff;--card-border:#e2e5ed;
  --topbar-bg:#fff;--topbar-border:#e2e5ed;
  --input-bg:#fff;--input-border:#e2e5ed;--input-fg:#1a1d26;
  --table-bg:#fff;--table-border:#e2e5ed;--thead-bg:#f1f3f8;--row-border:#eef0f5;
  --muted:#8b92a8;--link:#4f6ef7;--code-bg:#f1f3f8;--code-border:#e2e5ed;
  --btn-bg:#4f6ef7;--btn-border:#4f6ef7;--btn2-bg:#fff;--btn2-fg:#5a6178;--btn2-border:#e2e5ed;
  --surface-alt:#f1f3f8;--accent:#4f6ef7;--accent-hover:#3b5ae0;--accent-subtle:#eef1fe;
  --success:#22a55a;--success-bg:#edfbf3;--warning:#e5930a;--warning-bg:#fef8ec;--danger:#e53535;--danger-bg:#fef0f0;--info:#3b82f6;--info-bg:#eff6ff;
  --space-1:.25rem;--space-2:.5rem;--space-3:.75rem;--space-4:1rem;--space-5:1.5rem;--space-6:2rem;--space-8:3rem;
  --text-xs:.75rem;--text-sm:.8125rem;--text-base:.875rem;--text-md:1rem;--text-lg:1.125rem;--text-xl:1.5rem;--text-2xl:2rem;
}
[data-theme="dark"]{
  --bg:#0c0e14;--fg:#e8eaf0;--card-bg:#181c28;--card-border:#2a3045;
  --topbar-bg:#181c28;--topbar-border:#2a3045;
  --input-bg:#1e2333;--input-border:#2a3045;--input-fg:#e8eaf0;
  --table-bg:#181c28;--table-border:#2a3045;--thead-bg:#1e2333;--row-border:#232840;
  --muted:#6b7290;--link:#6b8aff;--code-bg:#1e2333;--code-border:#2a3045;
  --btn-bg:#6b8aff;--btn-border:#6b8aff;--btn2-bg:#1e2333;--btn2-fg:#9da3b8;--btn2-border:#2a3045;
  --surface-alt:#1e2333;--accent:#6b8aff;--accent-hover:#8da4ff;--accent-subtle:#1e2545;
  --success:#34d17a;--success-bg:rgba(52,209,122,.12);--warning:#f5a623;--warning-bg:rgba(245,166,35,.12);--danger:#f05555;--danger-bg:rgba(240,85,85,.12);--info:#60a5fa;--info-bg:rgba(96,165,250,.12);
  --space-1:.25rem;--space-2:.5rem;--space-3:.75rem;--space-4:1rem;--space-5:1.5rem;--space-6:2rem;--space-8:3rem;
  --text-xs:.75rem;--text-sm:.8125rem;--text-base:.875rem;--text-md:1rem;--text-lg:1.125rem;--text-xl:1.5rem;--text-2xl:2rem;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--fg);line-height:1.45;transition:background .2s,color .2s}
a{color:var(--link)}
h1,h2,h3{margin:0 0 .8rem}
h2{font-size:var(--text-lg);margin:0 0 var(--space-3)}
p{margin:.35rem 0 .75rem}
article{background:var(--card-bg);border:1px solid var(--card-border);border-radius:10px;padding:1rem;margin:0 0 1rem;transition:border-color .2s,box-shadow .2s}
button,input,select{font:inherit}
input,select{width:100%;max-width:100%;padding:.45rem .6rem;border:1px solid var(--input-border);border-radius:8px;background:var(--input-bg);color:var(--input-fg);transition:border-color .2s,box-shadow .2s}
input[type="checkbox"]{width:auto}
button{padding:.45rem .85rem;border:1px solid var(--btn-border);border-radius:8px;background:var(--btn-bg);color:#fff;cursor:pointer;transition:background .15s,border-color .15s,filter .15s,color .15s}
button:hover{filter:brightness(.9)}
input:focus,select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-subtle)}
button.secondary{background:var(--btn2-bg);color:var(--btn2-fg);border-color:var(--btn2-border)}
.btn-primary{background:var(--accent);color:#fff;border:1px solid var(--accent)}
.btn-primary:hover{background:var(--accent-hover);border-color:var(--accent-hover)}
.btn-danger{background:transparent;color:var(--danger);border:1px solid var(--danger)}
.btn-danger:hover{background:var(--danger);color:#fff}
.btn-sm{padding:.3rem .6rem;font-size:var(--text-xs)}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,Liberation Mono,monospace;font-size:.85em;background:var(--code-bg);border:1px solid var(--code-border);border-radius:6px;padding:.1rem .3rem}
table{width:100%;font-size:.875rem;border-collapse:collapse;background:var(--table-bg);border:1px solid var(--table-border)}
th,td{padding:.5rem .55rem;text-align:left;vertical-align:top;border-bottom:1px solid var(--row-border)}
thead th{background:var(--thead-bg);font-weight:600}
tr:last-child td{border-bottom:none}
tbody tr:nth-child(even){background:var(--surface-alt)}
tbody tr:hover{background:var(--accent-subtle)}
article:has(>table){padding:0;overflow-x:auto;overflow-y:hidden;-webkit-overflow-scrolling:touch}
article:has(>table) table{border:none}
.admin-shell{display:grid;grid-template-columns:var(--sidebar-w) 1fr;min-height:100vh}
.sidebar{background:var(--sidebar-bg);color:var(--sidebar-text);position:sticky;top:0;height:100vh;overflow-y:auto;display:flex;flex-direction:column}
.sidebar-brand{padding:1rem 1.25rem;font-weight:700;font-size:1rem;color:#fff;letter-spacing:.02em;border-bottom:1px solid rgba(255,255,255,.08)}
.sidebar nav{display:flex;flex-direction:column;padding:.5rem 0;flex:1}
.sidebar nav a{display:block;padding:.5rem 1.25rem;color:var(--sidebar-text);text-decoration:none;font-size:.875rem;transition:background .15s,color .15s}
.sidebar nav a:hover{background:rgba(255,255,255,.07);color:#fff}
.sidebar nav a[aria-current="page"]{background:var(--sidebar-active-bg);color:var(--sidebar-active);font-weight:600;border-left:3px solid var(--accent)}
.nav-sep{height:1px;background:rgba(255,255,255,.08);margin:.4rem .75rem}
.nav-label{padding:.6rem 1.25rem .2rem;font-size:.65rem;text-transform:uppercase;letter-spacing:.1em;color:rgba(255,255,255,.35);font-weight:600}
.sidebar-footer{padding:.75rem 1.25rem;font-size:.7rem;color:rgba(255,255,255,.25);border-top:1px solid rgba(255,255,255,.08);margin-top:auto}
.main-area{display:flex;flex-direction:column;min-height:100vh;min-width:0}
.topbar{height:var(--topbar-h);display:flex;align-items:center;padding:0 1.5rem;gap:1rem;background:var(--topbar-bg);border-bottom:1px solid var(--topbar-border);position:sticky;top:0;z-index:10;transition:background .2s,border-color .2s}
.topbar-title{font-weight:600;font-size:1rem;flex:1;min-width:0}
.topbar-right{display:flex;align-items:center;gap:1rem;flex-wrap:wrap;min-width:0}
.topbar-user{font-size:.875rem;color:var(--muted)}
.lang-switch{font-size:.8rem;color:var(--muted)}
.lang-switch a{color:inherit}
.theme-toggle{background:none;border:1px solid var(--input-border);border-radius:8px;color:var(--fg);padding:.3rem .6rem;font-size:.85rem;cursor:pointer;line-height:1}
.theme-toggle:hover{background:var(--input-bg)}
main.container-fluid{padding:1.5rem;flex:1;min-width:0}
.flash{display:flex;align-items:center;justify-content:space-between;padding:var(--space-3) var(--space-4);border-radius:8px;margin-bottom:var(--space-4);font-size:var(--text-base)}
.flash-ok{background:var(--success-bg);color:#1a5e2e;border:1px solid var(--success);border-left:4px solid var(--success)}
.flash-err{background:var(--danger-bg);color:#7b1a1a;border:1px solid var(--danger);border-left:4px solid var(--danger)}
[data-theme="dark"] .flash-ok{color:#a3e4b8}
[data-theme="dark"] .flash-err{color:#f5a5a5}
.flash-close{background:none;border:none;font-size:1.2rem;cursor:pointer;color:inherit;padding:0 .25rem;line-height:1}
.stat-cards{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:1.5rem}
.stat-card{text-align:center;padding:var(--space-5);position:relative}
.stat-card::before{content:'';position:absolute;left:0;top:0;bottom:0;width:4px;border-radius:10px 0 0 10px}
.stat-card:nth-child(1)::before{background:var(--accent)}
.stat-card:nth-child(2)::before{background:var(--success)}
.stat-card:nth-child(3)::before{background:var(--warning)}
.stat-card:nth-child(4)::before{background:var(--info)}
.stat-icon{font-size:1.5rem;margin-bottom:var(--space-1)}
.stat-number{display:block;font-size:2rem;font-weight:700;line-height:1.1}
.stat-label{display:block;font-size:.8rem;color:var(--muted);margin-top:.25rem;text-transform:uppercase;letter-spacing:.05em}
.badge{display:inline-block;padding:.2em .55em;border-radius:99px;font-size:.75rem;font-weight:600;color:#fff;white-space:nowrap}
form{margin-bottom:0}
figure{overflow-x:auto;margin:0 0 1rem}
.form-inline{display:flex;gap:var(--space-2);flex-wrap:wrap;margin-bottom:var(--space-5)}
.form-grid{display:grid;gap:var(--space-2);margin-bottom:var(--space-5)}
.form-grid-2{grid-template-columns:repeat(2,minmax(160px,1fr))}
.form-grid-4{grid-template-columns:repeat(4,minmax(160px,1fr))}
.checkbox-group{display:flex;gap:.75rem;flex-wrap:wrap}
.checkbox-item{display:flex;align-items:center;gap:.35rem;white-space:nowrap}
.membership-create-form{display:grid;grid-template-columns:repeat(2,minmax(220px,1fr));gap:.85rem;margin-bottom:1.5rem}
.membership-table form{display:grid;gap:.5rem}
.membership-permissions{display:grid;grid-template-columns:repeat(2,minmax(150px,1fr));gap:.35rem .75rem}
.stacked-cell{display:grid;gap:.2rem}
.muted{color:var(--muted);font-size:.85em}
.hamburger{display:none;background:none;border:none;color:var(--fg);font-size:1.3rem;cursor:pointer;padding:.2rem .5rem;line-height:1}
.hamburger:hover{background:var(--input-bg);border-radius:6px}
@media(max-width:768px){
  .admin-shell{grid-template-columns:1fr}
  .sidebar{display:none;position:fixed;top:0;left:0;width:260px;height:100vh;z-index:50;box-shadow:4px 0 20px rgba(0,0,0,.25)}
  .sidebar.open{display:flex}
  .sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:40}
  .sidebar-overlay.open{display:block}
  .hamburger{display:block}
  .topbar{height:auto;min-height:var(--topbar-h);padding:var(--space-3) var(--space-4);display:grid;grid-template-columns:auto minmax(0,1fr);align-items:center}
  .topbar-right{grid-column:1/-1;display:grid;grid-template-columns:minmax(0,1fr) auto auto;align-items:center;width:auto;justify-content:normal;gap:var(--space-2)}
  .topbar-user{display:none}
  .lang-switch{font-size:var(--text-xs)}
  .lang-switch{min-width:0;overflow-wrap:anywhere}
  .theme-toggle,.topbar-right>a:last-child{justify-self:end}
  main.container-fluid{padding:var(--space-4)}
  article:has(>table) table{min-width:760px}
  .stat-cards{grid-template-columns:repeat(2,1fr)}
  .membership-create-form,.membership-permissions{grid-template-columns:1fr}
  .form-grid-3,.form-grid-4{grid-template-columns:1fr}
  table{font-size:.8rem}
  .form-inline{flex-direction:column}
  .form-inline>input,.form-inline>select{width:100%}
}
@media(max-width:480px){
  .topbar{padding:var(--space-2) var(--space-3)}
  main.container-fluid{padding:var(--space-3)}
  .stat-cards{grid-template-columns:1fr}
  .form-grid-2{grid-template-columns:1fr}
}
.edit-row td{background:var(--thead-bg);padding:var(--space-4)}
.form-grid-3{grid-template-columns:repeat(3,1fr)}
.btn-toggle-on{background:transparent;color:var(--success);border:1px solid var(--success);padding:.3rem .6rem;font-size:var(--text-xs);border-radius:8px}
.btn-toggle-on:hover{background:var(--success);color:#fff}
.btn-toggle-off{background:transparent;color:var(--muted);border:1px solid var(--muted);padding:.3rem .6rem;font-size:var(--text-xs);border-radius:8px}
.btn-toggle-off:hover{background:var(--muted);color:#fff}
details{margin-bottom:var(--space-4)}
details>summary{cursor:pointer;list-style:none;display:flex;align-items:center;gap:var(--space-2)}
details>summary::-webkit-details-marker{display:none}
details>summary::before{content:'▶';font-size:.7rem;transition:transform .2s}
details[open]>summary::before{transform:rotate(90deg)}
details>summary h2{margin:0}"""

    js = """function toggleSidebar(){var s=document.querySelector('.sidebar'),o=document.getElementById('sidebar-overlay');s.classList.toggle('open');o.classList.toggle('open');}
function toggleEdit(id){var row=document.getElementById('edit-'+id);if(row)row.style.display=row.style.display==='none'?'table-row':'none';}
document.querySelectorAll('form[data-confirm]').forEach(function(f){
  f.addEventListener('submit',function(e){if(!confirm(f.dataset.confirm))e.preventDefault()});
});
document.querySelectorAll('.flash').forEach(function(el){
  var btn=el.querySelector('.flash-close');
  if(btn)btn.addEventListener('click',function(){el.remove()});
});
document.querySelectorAll('.flash-ok').forEach(function(el){
  setTimeout(function(){if(el.parentNode)el.remove()},5000);
});
(function(){
  var root=document.documentElement;
  var btn=document.getElementById('theme-toggle');
  var stored=localStorage.getItem('wff-theme');
  var dark=stored?stored==='dark':window.matchMedia('(prefers-color-scheme: dark)').matches;
  function apply(d){
    root.dataset.theme=d?'dark':'light';
    if(btn)btn.textContent=d?'☀️':'🌙';
  }
  apply(dark);
  if(btn)btn.addEventListener('click',function(){
    dark=!dark;
    localStorage.setItem('wff-theme',dark?'dark':'light');
    apply(dark);
  });
})();"""

    page = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{_esc(title)} — WakeFromFar Admin</title>
  <link rel="icon" type="image/png" href="/admin/ui/favicon.png">
  <script>document.documentElement.dataset.theme=localStorage.getItem('wff-theme')||(window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');</script>
  <style>{css}</style>
</head>
<body>
  <div class="admin-shell">
    {sidebar}
    <div class="main-area">
      <div class="sidebar-overlay" id="sidebar-overlay" onclick="toggleSidebar()"></div>
      <header class="topbar">
        <button class="hamburger" id="hamburger" onclick="toggleSidebar()" aria-label="Menu">&#9776;</button>
        <span class="topbar-title">{_esc(title)}</span>
        <div class="topbar-right">
          <span class="topbar-user">{t("signed_in_as")} <strong>{_esc(admin_username)}</strong></span>
          <span class="lang-switch"><a href="{_esc(_lang_switch_url(request, 'en'))}">{t("lang_en")}</a> | <a href="{_esc(_lang_switch_url(request, 'de'))}">{t("lang_de")}</a></span>
          <button class="theme-toggle" id="theme-toggle" title="Toggle dark mode" aria-label="Toggle dark mode">🌙</button>
          <a href="{_with_lang('/admin/ui/logout', lang)}">{t("nav_logout")}</a>
        </div>
      </header>
      <main class="container-fluid">
        {flashes}
        {body}
      </main>
    </div>
  </div>
  <script>{js}</script>
</body>
</html>"""
    response = HTMLResponse(page)
    _apply_csrf_cookie(request, response)
    _apply_lang_cookie(request, response, lang)
    return response


def _redirect(path: str, message: str | None = None, error: str | None = None, request: Request | None = None) -> RedirectResponse:
    parsed = urlparse(path)
    base_path = parsed.path or path
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if message:
        params["message"] = message
    if error:
        params["error"] = error
    if request is not None:
        params["lang"] = _lang(request)
    location = base_path if not params else f"{base_path}?{urlencode(params)}"
    response = RedirectResponse(location, status_code=303)
    if request is not None:
        _apply_lang_cookie(request, response)
    return response


def _msg(request: Request) -> tuple[str | None, str | None]:
    return request.query_params.get("message"), request.query_params.get("error")


def _parse_csv(text: str) -> list[str]:
    return [part.strip() for part in text.split(",") if part.strip()]


def _parse_ports(text: str, fallback: list[int]) -> list[int]:
    ports: list[int] = []
    for part in _parse_csv(text):
        try:
            value = int(part)
        except ValueError:
            continue
        if 1 <= value <= 65535:
            ports.append(value)
    if not ports:
        return fallback
    return sorted(set(ports))


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


def _execute_discovery_run_ui(run_id: str) -> None:
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
        complete_discovery_run(run_id, json.dumps(summarize_candidates(candidates, warnings)))
        log_discovery_event(run_id=run_id, event_type="probe", detail=f"completed candidates={len(candidates)}")
    except Exception as exc:
        fail_discovery_run(run_id, json.dumps({"error": str(exc)}))
        log_discovery_event(run_id=run_id, event_type="error", detail=str(exc))


@router.get("/favicon.png", include_in_schema=False)
def favicon():
    return FileResponse(_FAVICON_PATH, media_type="image/png")


def _candidate_default_name_ui(candidate: dict, prefix: str | None = None) -> str:
    base = str(candidate.get("hostname") or "").strip()
    if base:
        return base
    ip_text = str(candidate.get("ip") or "").strip().replace(".", "-")
    if ip_text:
        return f"{prefix or 'discovered'}-{ip_text}"
    return f"{prefix or 'discovered'}-{str(candidate.get('id') or '')[:8]}"


def _import_discovery_candidate_ui(
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
    existing_by_mac = get_host_by_mac(candidate["mac"]) if candidate.get("mac") else None
    effective_mode = mode
    resolved_target = target_host_id
    if mode == "auto_merge_by_mac":
        if existing_by_mac:
            effective_mode = "update_existing"
            resolved_target = str(existing_by_mac["id"])
        else:
            effective_mode = "create_new"

    if effective_mode == "create_new":
        if not candidate.get("mac"):
            raise ValueError("candidate has no mac")
        resolved_name = (name or "").strip() or _candidate_default_name_ui(candidate, prefix=name_prefix)
        host_id = create_host(
            host_id=None,
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
        raise ValueError("invalid import mode")
    if not resolved_target:
        raise ValueError("target_host_id required")
    existing = get_host_by_id(resolved_target)
    if not existing:
        raise ValueError("target host not found")
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


def _auth_card_page(
    request: Request,
    *,
    title: str,
    subtitle: str,
    body: str,
    error: str | None = None,
    message: str | None = None,
) -> HTMLResponse:
    flashes = ""
    if error:
        flashes += f'<p class="login-error">{_esc(error)}</p>'
    if message:
        flashes += f'<p class="login-ok">{_esc(message)}</p>'
    page = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{_esc(title)}</title>
  <link rel="icon" type="image/png" href="/admin/ui/favicon.png">
  <script>document.documentElement.dataset.theme=localStorage.getItem('wff-theme')||(window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');</script>
  <style>
:root{{--bg:#f8f9fc;--fg:#1a1d26;--card-bg:#fff;--card-border:#e2e5ed;--input-bg:#fff;--input-border:#e2e5ed;--input-fg:#1a1d26;--muted:#8b92a8;--btn-bg:#4f6ef7;--btn-border:#4f6ef7;--accent:#4f6ef7;--accent-subtle:#eef1fe}}
[data-theme="dark"]{{--bg:#0c0e14;--fg:#e8eaf0;--card-bg:#181c28;--card-border:#2a3045;--input-bg:#1e2333;--input-border:#2a3045;--input-fg:#e8eaf0;--muted:#6b7290;--btn-bg:#6b8aff;--btn-border:#6b8aff;--accent:#6b8aff;--accent-subtle:#1e2545}}
*{{box-sizing:border-box}}
html,body{{margin:0;padding:0}}
body{{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:1rem;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--fg)}}
.login-card{{width:100%;max-width:520px;background:var(--card-bg);border:1px solid var(--card-border);border-radius:12px;padding:1.5rem;box-shadow:0 4px 24px rgba(0,0,0,.08)}}
.login-brand{{text-align:center;margin-bottom:1.5rem}}
.login-brand img{{width:48px;height:48px;margin-bottom:.5rem}}
.login-brand h1{{font-size:1.5rem;margin:0}}
.login-brand p{{color:var(--muted);font-size:.875rem;margin:.25rem 0 0}}
.login-error,.login-ok{{border-radius:8px;padding:.6rem .9rem;font-size:.875rem;margin-bottom:.75rem}}
.login-error{{color:#7b1a1a;background:#fef0f0;border:1px solid #e53535;border-left:4px solid #e53535}}
.login-ok{{color:#1a5e2e;background:#edfbf3;border:1px solid #22a55a;border-left:4px solid #22a55a}}
label{{display:block;margin:.45rem 0 .2rem;font-size:.875rem;color:var(--muted)}}
input,textarea{{width:100%;max-width:100%;padding:.5rem .6rem;border:1px solid var(--input-border);border-radius:8px;background:var(--input-bg);color:var(--input-fg);font:inherit;transition:border-color .2s,box-shadow .2s}}
textarea{{min-height:104px;resize:vertical}}
button{{margin-top:.65rem;width:100%;padding:.5rem .85rem;border:1px solid var(--btn-border);border-radius:8px;background:var(--btn-bg);color:#fff;cursor:pointer;font:inherit;transition:filter .15s}}
button:hover{{filter:brightness(.9)}}
input:focus,textarea:focus{{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-subtle)}}
.lang-footer{{text-align:center;margin-top:1rem;font-size:.8rem;color:var(--muted)}}
.lang-footer a{{color:inherit}}
.stack{{display:grid;gap:.75rem}}
.muted{{color:var(--muted);font-size:.875rem}}
code{{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,Liberation Mono,monospace;font-size:.85em}}
  </style>
</head>
<body>
  <article class="login-card">
    <div class="login-brand">
      <img src="/admin/ui/favicon.png" alt="" width="48" height="48" />
      <h1>WakeFromFar</h1>
      <p>{_esc(subtitle)}</p>
    </div>
    {flashes}
    {body}
    <div class="lang-footer">
      <a href="{_esc(_lang_switch_url(request, 'en'))}">{_tr(request, "lang_en")}</a> |
      <a href="{_esc(_lang_switch_url(request, 'de'))}">{_tr(request, "lang_de")}</a>
    </div>
  </article>
</body>
</html>"""
    response = HTMLResponse(page)
    _apply_csrf_cookie(request, response)
    _apply_lang_cookie(request, response)
    return response


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/admin/ui", error: str | None = None):
    user = _admin_from_cookie(request)
    safe_next = _safe_next_path(next)
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    if user:
        return RedirectResponse(safe_next, status_code=303)
    pending_state = _pending_admin_from_cookie(request)
    if pending_state:
        return _pending_redirect(request, pending_state)
    body = f"""
    <form method="post" action="/admin/ui/login" autocomplete="off">
      {_csrf_form_input(request)}
      <input type="hidden" name="next" value="{_esc(safe_next)}" />
      <input type="hidden" name="lang" value="{_esc(_lang(request))}" />
      <label for="login-username">{t("label_username")}</label>
      <input id="login-username" required name="username" autocomplete="username" />
      <label for="login-password">{t("label_password")}</label>
      <input id="login-password" required type="password" name="password" autocomplete="current-password" />
      <button type="submit">{t("action_login")}</button>
    </form>
    """
    return _auth_card_page(
        request,
        title=t("title_admin_login"),
        subtitle=t("title_admin_login"),
        body=body,
        error=error,
    )


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form("/admin/ui"),
    lang: str = Form(""),
):
    if not is_auth_transport_allowed(request, get_settings()):
        _security_ui_event(
            request,
            counter="security.transport_auth.blocked",
            event="security.transport_auth.blocked",
            reason="https_required",
            detail=LOGIN_TLS_REQUIRED_DETAIL,
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=LOGIN_TLS_REQUIRED_DETAIL)
    resolved_lang = lang if lang in _SUPPORTED_LANGS else _lang(request)
    safe_next = _safe_next_path(next)
    if _is_login_rate_limited(request):
        error_message = _I18N.get(resolved_lang, _I18N["en"])["error_too_many_login_attempts"]
        return RedirectResponse(
            f"/admin/ui/login?{urlencode({'next': safe_next, 'error': error_message, 'lang': resolved_lang})}",
            status_code=303,
        )
    user = get_user_by_username(username)
    if not user or user["role"] != "admin" or not verify_password(password, user["password_hash"]):
        _record_failed_login_attempt(request)
        error_message = _I18N.get(resolved_lang, _I18N["en"])["error_invalid_admin_credentials"]
        return RedirectResponse(
            f"/admin/ui/login?{urlencode({'next': safe_next, 'error': error_message, 'lang': resolved_lang})}",
            status_code=303,
        )
    settings = get_settings()
    if _is_user_mfa_enabled(user):
        _security_ui_event(
            request,
            counter="security.admin_ui.mfa.verify_started",
            event="security.admin_ui.mfa.verify_started",
            reason="mfa_enabled_admin_login",
            username=str(user["username"]),
        )
        pending_token = _build_pending_admin_state(
            user,
            purpose=_ADMIN_PENDING_PURPOSE_VERIFY,
            next_path=safe_next,
        )
        response = RedirectResponse(_with_lang("/admin/ui/mfa/verify", resolved_lang), status_code=303)
        _set_admin_cookie(request, response, _ADMIN_UI_PENDING_COOKIE, pending_token)
        _apply_csrf_cookie(request, response, rotate=True)
        _apply_lang_cookie(request, response, resolved_lang)
        return response
    if settings.admin_mfa_required:
        _security_ui_event(
            request,
            counter="security.admin_ui.mfa.setup_started",
            event="security.admin_ui.mfa.setup_started",
            reason="mfa_required_admin_login",
            username=str(user["username"]),
        )
        pending_token = _build_pending_admin_state(
            user,
            purpose=_ADMIN_PENDING_PURPOSE_SETUP,
            next_path=safe_next,
            encrypted_secret=encrypt_secret_value(generate_totp_secret()),
        )
        response = RedirectResponse(_with_lang("/admin/ui/mfa/setup", resolved_lang), status_code=303)
        _set_admin_cookie(request, response, _ADMIN_UI_PENDING_COOKIE, pending_token)
        _apply_csrf_cookie(request, response, rotate=True)
        _apply_lang_cookie(request, response, resolved_lang)
        return response
    return _issue_full_admin_session_response(
        request,
        user=user,
        next_path=safe_next,
        lang=resolved_lang,
    )


@router.get("/logout")
def logout(request: Request):
    response = RedirectResponse(_with_lang("/admin/ui/login", _lang(request)), status_code=303)
    _delete_admin_cookie(response, _ADMIN_UI_SESSION_COOKIE)
    _delete_admin_cookie(response, _ADMIN_UI_PENDING_COOKIE)
    _delete_csrf_cookie(response)
    _apply_lang_cookie(request, response)
    return response


def _mfa_rate_limit_key(request: Request, username: str) -> str:
    return f"{username}:{_login_ip_key(request)}"


def _mfa_verify_limited(request: Request, username: str) -> bool:
    settings = get_settings()
    return get_rate_limiter().check_and_record(
        scope="admin_ui_mfa_verify",
        key=_mfa_rate_limit_key(request, username),
        limit=settings.admin_mfa_verify_rate_limit_per_minute,
        window_seconds=60,
    )


def _mfa_setup_body(request: Request, *, username: str, encrypted_secret: str, submit_path: str) -> str:
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    secret = decrypt_secret_value(encrypted_secret)
    issuer = get_settings().admin_mfa_issuer
    otpauth_uri = build_totp_otpauth_uri(secret=secret, issuer=issuer, account_name=username)
    return f"""
    <div class="stack">
      <p class="muted">{t("text_mfa_setup_intro")}</p>
      <p class="muted">{t("text_mfa_required_rollout")}</p>
      <label>{t("label_mfa_issuer")}<input value="{_esc(issuer)}" readonly /></label>
      <label>{t("label_mfa_account")}<input value="{_esc(username)}" readonly /></label>
      <label>{t("label_mfa_secret")}<input value="{_esc(secret)}" readonly /></label>
      <label>{t("label_mfa_otpauth_uri")}<textarea readonly>{_esc(otpauth_uri)}</textarea></label>
      <form method="post" action="{_esc(submit_path)}" autocomplete="off">
        {_csrf_form_input(request)}
        <input type="hidden" name="encrypted_secret" value="{_esc(encrypted_secret)}" />
        <label for="mfa-code">{t("label_totp_code")}</label>
        <input id="mfa-code" required name="code" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" maxlength="6" />
        <button type="submit">{t("action_enable_mfa")}</button>
      </form>
    </div>
    """


@router.get("/mfa", response_class=HTMLResponse)
def mfa_page(request: Request):
    user = _require_admin_or_redirect(request)
    if isinstance(user, RedirectResponse):
        return user
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    message, error = _msg(request)
    if _is_user_mfa_enabled(user):
        body = f"""
        <article>
          <h2>{t("heading_mfa_status")}</h2>
          <p>{t("text_mfa_enabled")}</p>
          <p class="muted">{t("text_mfa_enabled_at", enabled_at=str(user["mfa_enabled_at"] or "unknown"))}</p>
          <p class="muted">{t("text_mfa_recovery_hint", username=str(user["username"]))}</p>
        </article>
        """
    else:
        body = f"""
        <article>
          <h2>{t("heading_mfa_status")}</h2>
          <p>{t("text_mfa_not_enabled")}</p>
        </article>
        <article>
          <h2>{t("heading_mfa_setup")}</h2>
          {_mfa_setup_body(
              request,
              username=str(user["username"]),
              encrypted_secret=encrypt_secret_value(generate_totp_secret()),
              submit_path="/admin/ui/mfa/setup",
          )}
        </article>
        """
    return _layout(
        request,
        t("title_admin_mfa"),
        body,
        str(user["username"]),
        message=message,
        error=error,
    )


@router.get("/mfa/verify", response_class=HTMLResponse)
def mfa_verify_page(request: Request, error: str | None = None):
    pending_state = _require_pending_admin(request, purpose=_ADMIN_PENDING_PURPOSE_VERIFY)
    if isinstance(pending_state, RedirectResponse):
        return pending_state
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    body = f"""
    <div class="stack">
      <p class="muted">{t("text_mfa_verify_intro")}</p>
      <form method="post" action="/admin/ui/mfa/verify" autocomplete="off">
        {_csrf_form_input(request)}
        <label for="verify-code">{t("label_totp_code")}</label>
        <input id="verify-code" required name="code" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" maxlength="6" />
        <button type="submit">{t("action_verify_mfa")}</button>
      </form>
    </div>
    """
    return _auth_card_page(
        request,
        title=t("title_admin_mfa_verify"),
        subtitle=t("title_admin_mfa_verify"),
        body=body,
        error=error,
    )


@router.post("/mfa/verify")
def mfa_verify_submit(request: Request, code: str = Form(...)):
    pending_state = _require_pending_admin(request, purpose=_ADMIN_PENDING_PURPOSE_VERIFY)
    if isinstance(pending_state, RedirectResponse):
        return pending_state
    user = pending_state["user"]
    if _mfa_verify_limited(request, str(user["username"])):
        _security_ui_event(
            request,
            counter="security.admin_ui.mfa.verify_failed",
            event="security.admin_ui.mfa.verify_failed",
            reason="rate_limited",
            username=str(user["username"]),
        )
        return RedirectResponse(
            f"/admin/ui/mfa/verify?{urlencode({'error': _tr(request, 'error_too_many_mfa_attempts'), 'lang': _lang(request)})}",
            status_code=303,
        )
    encrypted_secret = str(user["mfa_totp_secret_encrypted"] or "")
    if not encrypted_secret or not verify_totp_code(decrypt_secret_value(encrypted_secret), code):
        _security_ui_event(
            request,
            counter="security.admin_ui.mfa.verify_failed",
            event="security.admin_ui.mfa.verify_failed",
            reason="invalid_code",
            username=str(user["username"]),
        )
        return RedirectResponse(
            f"/admin/ui/mfa/verify?{urlencode({'error': _tr(request, 'error_invalid_mfa_code'), 'lang': _lang(request)})}",
            status_code=303,
        )
    _security_ui_event(
        request,
        counter="security.admin_ui.mfa.verify_success",
        event="security.admin_ui.mfa.verify_success",
        reason="valid_code",
        username=str(user["username"]),
    )
    return _issue_full_admin_session_response(
        request,
        user=user,
        next_path=str(pending_state["next"]),
        lang=_lang(request),
    )


@router.get("/mfa/setup", response_class=HTMLResponse)
def mfa_setup_page(request: Request, error: str | None = None):
    authenticated_user = _admin_from_cookie(request)
    if authenticated_user:
        if _is_user_mfa_enabled(authenticated_user):
            return _redirect("/admin/ui/mfa", request=request)
        body = _mfa_setup_body(
            request,
            username=str(authenticated_user["username"]),
            encrypted_secret=encrypt_secret_value(generate_totp_secret()),
            submit_path="/admin/ui/mfa/setup",
        )
        return _auth_card_page(
            request,
            title=_tr(request, "title_admin_mfa_setup"),
            subtitle=_tr(request, "title_admin_mfa_setup"),
            body=body,
            error=error,
        )

    pending_state = _require_pending_admin(request, purpose=_ADMIN_PENDING_PURPOSE_SETUP)
    if isinstance(pending_state, RedirectResponse):
        return pending_state
    encrypted_secret = str(pending_state["pending_secret"] or "")
    if not encrypted_secret:
        return _redirect_to_login(request, error=_tr(request, "error_mfa_pending_expired"), next_path="/admin/ui/login")
    body = _mfa_setup_body(
        request,
        username=str(pending_state["user"]["username"]),
        encrypted_secret=encrypted_secret,
        submit_path="/admin/ui/mfa/setup",
    )
    return _auth_card_page(
        request,
        title=_tr(request, "title_admin_mfa_setup"),
        subtitle=_tr(request, "title_admin_mfa_setup"),
        body=body,
        error=error,
    )


@router.post("/mfa/setup")
def mfa_setup_submit(
    request: Request,
    encrypted_secret: str = Form(...),
    code: str = Form(...),
):
    authenticated_user = _admin_from_cookie(request)
    pending_state: dict[str, object] | None = None
    if authenticated_user:
        user = authenticated_user
    else:
        pending_result = _require_pending_admin(request, purpose=_ADMIN_PENDING_PURPOSE_SETUP)
        if isinstance(pending_result, RedirectResponse):
            return pending_result
        pending_state = pending_result
        user = pending_result["user"]

    if _is_user_mfa_enabled(user):
        return _redirect("/admin/ui/mfa", request=request)
    if _mfa_verify_limited(request, str(user["username"])):
        _security_ui_event(
            request,
            counter="security.admin_ui.mfa.verify_failed",
            event="security.admin_ui.mfa.verify_failed",
            reason="setup_rate_limited",
            username=str(user["username"]),
        )
        return RedirectResponse(
            f"/admin/ui/mfa/setup?{urlencode({'error': _tr(request, 'error_too_many_mfa_attempts'), 'lang': _lang(request)})}",
            status_code=303,
        )
    secret = decrypt_secret_value(encrypted_secret)
    if not verify_totp_code(secret, code):
        _security_ui_event(
            request,
            counter="security.admin_ui.mfa.verify_failed",
            event="security.admin_ui.mfa.verify_failed",
            reason="setup_invalid_code",
            username=str(user["username"]),
        )
        return RedirectResponse(
            f"/admin/ui/mfa/setup?{urlencode({'error': _tr(request, 'error_invalid_mfa_code'), 'lang': _lang(request)})}",
            status_code=303,
        )
    enable_user_mfa(int(user["id"]), encrypt_secret_value(secret))
    log_admin_action(str(user["username"]), "enable_mfa", "user", str(user["id"]), "totp")
    _security_ui_event(
        request,
        counter="security.admin_ui.mfa.setup_completed",
        event="security.admin_ui.mfa.setup_completed",
        reason="valid_code",
        username=str(user["username"]),
    )
    refreshed_user = get_user_by_username(str(user["username"]))
    if refreshed_user is None:
        return _redirect_to_login(request, error=_tr(request, "error_mfa_pending_expired"))
    if pending_state is not None:
        return _issue_full_admin_session_response(
            request,
            user=refreshed_user,
            next_path=str(pending_state["next"]),
            lang=_lang(request),
            message=_tr(request, "text_mfa_enabled"),
        )
    return _redirect("/admin/ui/mfa", message=_tr(request, "text_mfa_enabled"), request=request)


@router.get("", response_class=HTMLResponse)
def dashboard(request: Request):
    user = _require_admin_or_redirect(request)
    if isinstance(user, RedirectResponse):
        return user
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    csrf_input = _csrf_form_input(request)
    users = list_users()
    devices = list_hosts()
    scheduled_wakes = list_scheduled_wake_jobs(limit=200)
    memberships = list_device_memberships()
    wake_logs = list_wake_logs(limit=10)
    power_logs = list_power_check_logs(limit=10)
    device_name_map = {str(h["id"]): str(h["name"]) for h in devices}
    message, error = _msg(request)
    selected_run_id = request.query_params.get("run_id")
    bulk_form = ""
    if selected_run_id:
        bulk_form = f"""
    <form method="post" action="/admin/ui/discovery/runs/{_esc(selected_run_id)}/import-bulk" class="form-inline" style="margin-bottom:.8rem;">
      {csrf_input}
      <label>{t("label_import_mode")}
        <select name="mode">
          <option value="auto_merge_by_mac">{t("option_auto_merge_by_mac")}</option>
          <option value="create_new">{t("option_create_new")}</option>
        </select>
      </label>
      <input name="name_prefix" placeholder="discovered" />
      <label class="checkbox-item"><input type="checkbox" name="apply_power_settings" value="1" checked />power settings</label>
      <label class="checkbox-item"><input type="checkbox" name="skip_without_mac" value="1" checked />skip without mac</label>
      <button type="submit">{t("action_bulk_import")}</button>
    </form>
        """

    wake_log_rows = "".join(f"<tr><td>{_short_id(row['id'])}</td><td>{_device_cell(row['host_id'], device_name_map)}</td><td>{_esc(row['actor_username'])}</td><td>{_badge(str(row['result']))}</td><td>{_esc(row['created_at'])}</td></tr>" for row in wake_logs)
    power_log_rows = "".join(f"<tr><td>{_short_id(row['id'])}</td><td>{_device_cell(row['device_id'], device_name_map)}</td><td>{_badge(str(row['method']))}</td><td>{_badge(str(row['result']))}</td><td>{_esc(row['created_at'])}</td></tr>" for row in power_logs)
    body = f"""
    <div class="stat-cards">
      <article class="stat-card"><div class="stat-icon">\U0001F465</div><strong class="stat-number">{len(users)}</strong><span class="stat-label">{t("card_users")}</span></article>
      <article class="stat-card"><div class="stat-icon">\U0001F4BB</div><strong class="stat-number">{len(devices)}</strong><span class="stat-label">{t("card_devices")}</span></article>
      <article class="stat-card"><div class="stat-icon">\u23F0</div><strong class="stat-number">{len(scheduled_wakes)}</strong><span class="stat-label">{t("card_scheduled_wakes")}</span></article>
      <article class="stat-card"><div class="stat-icon">\U0001F511</div><strong class="stat-number">{len(memberships)}</strong><span class="stat-label">{t("card_device_access")}</span></article>
    </div>
    <h2>{t("heading_recent_wake_logs")}</h2>
    <article><table>
      <thead><tr><th>{t("col_id")}</th><th>{t("col_device")}</th><th>{t("col_actor")}</th><th>{t("col_result")}</th><th>{t("col_time")}</th></tr></thead>
      <tbody>{wake_log_rows or _empty_row(request, 5)}</tbody>
    </table></article>
    <h2>{t("heading_recent_power_checks")}</h2>
    <article><table>
      <thead><tr><th>{t("col_id")}</th><th>{t("col_device")}</th><th>{t("col_method")}</th><th>{t("col_result")}</th><th>{t("col_time")}</th></tr></thead>
      <tbody>{power_log_rows or _empty_row(request, 5)}</tbody>
    </table></article>
    """
    return _layout(request, t("title_admin_dashboard"), body, user["username"], message=message, error=error)


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request):
    user = _require_admin_or_redirect(request)
    if isinstance(user, RedirectResponse):
        return user
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    csrf_input = _csrf_form_input(request)
    rows = list_users()
    message, error = _msg(request)
    table_rows = "".join(
        f"""
        <tr>
          <td>{_short_id(row['id'])}</td><td>{_esc(row['username'])}</td><td>{_badge(str(row['role']))}</td><td>{_esc(row['created_at'])}</td>
          <td>
            <form method="post" action="/admin/ui/users/{row['id']}/update" class="form-inline">
              {csrf_input}
              <select name="role">
                <option value="user" {"selected" if row['role']=="user" else ""}>user</option>
                <option value="admin" {"selected" if row['role']=="admin" else ""}>admin</option>
              </select>
              <input name="password" type="password" placeholder="{t("placeholder_new_password_optional")}" />
              <button type="submit">{t("action_save")}</button>
            </form>
          </td>
          <td>
            <form method="post" action="/admin/ui/users/{row['id']}/delete" data-confirm="{_esc(t('confirm_delete_user', username=str(row['username'])))}">
              {csrf_input}
              <button type="submit" class="btn-danger btn-sm">{t("action_delete")}</button>
            </form>
          </td>
        </tr>
        """
        for row in rows
    )
    body = f"""
    <article>
    <h2>{t("heading_create_user")}</h2>
    <form method="post" action="/admin/ui/users/create" autocomplete="off" class="form-inline">
      {csrf_input}
      <input required name="username" placeholder="{t("placeholder_username")}" />
      <input required name="password" type="password" placeholder="{t("placeholder_password_min12")}" />
      <select name="role"><option value="user">user</option><option value="admin">admin</option></select>
      <button type="submit">{t("action_create")}</button>
    </form>
    </article>
    <h2>{t("heading_users")}</h2>
    <article><table>
      <thead><tr><th>{t("col_id")}</th><th>{t("col_username")}</th><th>{t("col_role")}</th><th>{t("col_created")}</th><th>{t("col_update")}</th><th>{t("col_delete")}</th></tr></thead>
      <tbody>{table_rows or _empty_row(request, 6)}</tbody>
    </table></article>
    """
    return _layout(request, t("title_users"), body, user["username"], message=message, error=error)


@router.post("/users/create")
def users_create(request: Request, username: str = Form(...), password: str = Form(...), role: str = Form("user")):
    user = _require_admin_or_redirect(request)
    if isinstance(user, RedirectResponse):
        return user
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    if role not in {"admin", "user"}:
        return _redirect("/admin/ui/users", error=t("error_invalid_role"), request=request)
    required_len = min_password_length_for_role(role)
    if len(password) < required_len:
        error_key = "error_password_min_length_admin" if role == "admin" else "error_password_min_length_user"
        return _redirect("/admin/ui/users", error=t(error_key), request=request)
    if get_user_by_username(username):
        return _redirect("/admin/ui/users", error=t("error_username_exists"), request=request)
    user_id = create_user(username=username, password_hash=hash_password(password), role=role)
    log_admin_action(
        actor_username=user["username"],
        action="ui_create_user",
        target_type="user",
        target_id=str(user_id),
        detail=f"username={username}",
    )
    return _redirect("/admin/ui/users", message=t("msg_user_created", username=username), request=request)


@router.post("/users/{user_id}/update")
def users_update(request: Request, user_id: int, role: str = Form(...), password: str = Form("")):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    target = get_user_by_id(user_id)
    if not target:
        return _redirect("/admin/ui/users", error=t("error_user_not_found"), request=request)
    if role not in {"admin", "user"}:
        return _redirect("/admin/ui/users", error=t("error_invalid_role"), request=request)
    if target["role"] == "admin" and role != "admin" and count_admin_users() <= 1:
        return _redirect("/admin/ui/users", error=t("error_cannot_demote_last_admin"), request=request)
    if target["role"] != "admin" and role == "admin" and not password:
        return _redirect("/admin/ui/users", error=t("error_admin_promotion_requires_password"), request=request)
    update_user_role(user_id, role)
    if password:
        required_len = min_password_length_for_role(role)
        if len(password) < required_len:
            error_key = "error_password_min_length_admin" if role == "admin" else "error_password_min_length_user"
            return _redirect("/admin/ui/users", error=t(error_key), request=request)
        update_user_password_by_id(user_id, hash_password(password))
    log_admin_action(
        actor_username=admin["username"],
        action="ui_update_user",
        target_type="user",
        target_id=str(user_id),
        detail=f"role={role}",
    )
    return _redirect("/admin/ui/users", message=t("msg_user_updated", username=str(target["username"])), request=request)


@router.post("/users/{user_id}/delete")
def users_delete(request: Request, user_id: int):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    target = get_user_by_id(user_id)
    if not target:
        return _redirect("/admin/ui/users", error=t("error_user_not_found"), request=request)
    if target["role"] == "admin" and count_admin_users() <= 1:
        return _redirect("/admin/ui/users", error=t("error_cannot_delete_last_admin"), request=request)
    delete_user(user_id)
    log_admin_action(
        actor_username=admin["username"],
        action="ui_delete_user",
        target_type="user",
        target_id=str(user_id),
        detail=f"username={target['username']}",
    )
    return _redirect("/admin/ui/users", message=t("msg_user_deleted", username=str(target["username"])), request=request)


@router.get("/devices", response_class=HTMLResponse)
def devices_page(request: Request):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    csrf_input = _csrf_form_input(request)
    rows = list_hosts()
    message, error = _msg(request)
    table_rows = "".join(
        f"""
        <tr>
          <td>{_short_id(row['id'])}</td><td>{_esc(row['name'])}</td><td>{_esc(row['display_name'])}</td><td>{_esc(row['mac'])}</td>
          <td>{_esc(row['check_method'])}</td><td>{_esc(row['check_target'])}</td><td>{_esc(row['check_port'])}</td>
          <td>{_esc(row['last_power_state'])}</td><td>{_esc(row['last_power_checked_at'])}</td>
          <td>{"<br/>".join(_esc(hint) for hint in device_diagnostic_hints(dict(row)))}</td>
          <td>
            <div class="stacked-cell">
              <span>{_esc(_schedule_summary_text(request, dict(row)))}</span>
              <a href="{_esc(_schedule_filter_path(request, device_id=str(row['id'])))}">{t("action_manage_schedules")}</a>
              <a href="{_esc(_schedule_form_path(request, device_id=str(row['id'])))}">{t("action_add_schedule")}</a>
            </div>
          </td>
          <td>
            <div style="display:flex;gap:4px;flex-wrap:wrap">
              <button type="button" class="secondary btn-sm" onclick="toggleEdit('{_esc(row['id'])}')">{t("action_edit")}</button>
              <form method="post" action="/admin/ui/devices/{_esc(row['id'])}/test-power-check" style="display:inline">{csrf_input}<button type="submit" class="secondary btn-sm">{t("action_test_power_check")}</button></form>
              <form method="post" action="/admin/ui/devices/{_esc(row['id'])}/delete" data-confirm="{_esc(t('confirm_delete_device', device=str(row['name'])))}" style="display:inline">{csrf_input}<button type="submit" class="btn-danger btn-sm">{t("action_delete")}</button></form>
            </div>
          </td>
        </tr>
        <tr class="edit-row" id="edit-{_esc(row['id'])}" style="display:none">
          <td colspan="12">
            <form method="post" action="/admin/ui/devices/{_esc(row['id'])}/update" class="form-grid form-grid-3">
              {csrf_input}
              <label>{t("col_name")}<input name="name" value="{_esc(row['name'])}" /></label>
              <label>{t("col_display")}<input name="display_name" value="{_esc(row['display_name'])}" placeholder="{t("placeholder_display_name")}" /></label>
              <label>{t("col_mac")}<input name="mac" value="{_esc(row['mac'])}" /></label>
              <label>{t("col_interface")}<input name="interface" value="{_esc(row['interface'])}" placeholder="{t("placeholder_interface")}" /></label>
              <label>Source IP<input name="source_ip" value="{_esc(row['source_ip'])}" placeholder="source ip (optional)" /></label>
              <label>{t("placeholder_subnet_cidr")}<input name="source_network_cidr" value="{_esc(row['source_network_cidr'])}" placeholder="{t("placeholder_subnet_cidr")}" /></label>
              <label>{t("col_method")}<select name="check_method"><option value="tcp" {"selected" if row['check_method']=="tcp" else ""}>tcp</option><option value="icmp" {"selected" if row['check_method']=="icmp" else ""}>icmp</option></select></label>
              <label>{t("col_target")}<input name="check_target" value="{_esc(row['check_target'])}" placeholder="{t("placeholder_check_target")}" /></label>
              <label>{t("col_port")}<input name="check_port" value="{_esc(row['check_port'])}" placeholder="{t("placeholder_check_port")}" /></label>
              <div style="grid-column:1/-1;display:flex;gap:var(--space-2);justify-content:flex-end">
                <button type="button" class="secondary btn-sm" onclick="toggleEdit('{_esc(row['id'])}')">{t("action_cancel")}</button>
                <button type="submit">{t("action_save")}</button>
              </div>
            </form>
          </td>
        </tr>
        """
        for row in rows
    )
    body = f"""
    <article>
    <h2>{t("heading_create_device")}</h2>
    <form method="post" action="/admin/ui/devices/create" autocomplete="off" class="form-grid form-grid-4">
      {csrf_input}
      <input required name="name" placeholder="{t("placeholder_name")}" />
      <input name="display_name" placeholder="{t("placeholder_display_name")}" />
      <input required name="mac" placeholder="AA:BB:CC:DD:EE:FF" />
      <input name="group_name" placeholder="{t("placeholder_group")}" />
      <input name="broadcast" placeholder="{t("placeholder_broadcast_ip")}" />
      <input name="subnet_cidr" placeholder="{t("placeholder_subnet_cidr")}" />
      <input name="udp_port" value="9" placeholder="{t("placeholder_udp_port")}" />
      <input name="interface" placeholder="{t("placeholder_interface")}" />
      <input name="source_ip" placeholder="source ip (optional)" />
      <input name="source_network_cidr" placeholder="{t("placeholder_subnet_cidr")}" />
      <select name="check_method"><option value="tcp">tcp</option><option value="icmp">icmp</option></select>
      <input name="check_target" placeholder="{t("placeholder_check_target")}" />
      <input name="check_port" placeholder="{t("placeholder_check_port")}" />
      <button type="submit">{t("action_create")}</button>
    </form>
    </article>
    <h2>{t("heading_devices")}</h2>
    <article><table>
      <thead><tr><th>{t("col_id")}</th><th>{t("col_name")}</th><th>{t("col_display")}</th><th>{t("col_mac")}</th><th>{t("col_method")}</th><th>{t("col_target")}</th><th>{t("col_port")}</th><th>{t("col_state")}</th><th>{t("col_checked_at")}</th><th>{t("col_diagnostics")}</th><th>{t("col_schedules")}</th><th>{t("col_actions")}</th></tr></thead>
      <tbody>{table_rows or _empty_row(request, 12)}</tbody>
    </table></article>
    """
    return _layout(request, t("title_devices"), body, admin["username"], message=message, error=error)


@router.post("/devices/create")
def devices_create(
    request: Request,
    name: str = Form(...),
    display_name: str = Form(""),
    mac: str = Form(...),
    group_name: str = Form(""),
    broadcast: str = Form(""),
    subnet_cidr: str = Form(""),
    udp_port: int = Form(9),
    interface: str = Form(""),
    source_ip: str = Form(""),
    source_network_cidr: str = Form(""),
    check_method: str = Form("tcp"),
    check_target: str = Form(""),
    check_port: str = Form(""),
):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    try:
        normalized_mac = normalize_mac(mac)
    except ValueError as exc:
        return _redirect("/admin/ui/devices", error=str(exc), request=request)
    if check_method not in {"tcp", "icmp"}:
        return _redirect("/admin/ui/devices", error=t("error_invalid_check_method"), request=request)
    port_value = int(check_port) if check_port.strip() else None
    device_id = create_host(
        host_id=None,
        name=name,
        display_name=display_name or None,
        mac=normalized_mac,
        group_name=group_name or None,
        broadcast=broadcast or None,
        subnet_cidr=subnet_cidr or None,
        udp_port=udp_port,
        interface=interface or None,
        source_ip=source_ip or None,
        source_network_cidr=source_network_cidr or None,
        check_method=check_method,
        check_target=check_target or None,
        check_port=port_value,
    )
    log_admin_action(
        actor_username=admin["username"],
        action="ui_create_device",
        target_type="device",
        target_id=device_id,
        detail=f"name={name}",
    )
    return _redirect("/admin/ui/devices", message=t("msg_device_created", device_id=device_id), request=request)


@router.post("/devices/{device_id}/update")
def devices_update(
    request: Request,
    device_id: str,
    name: str = Form(...),
    display_name: str = Form(""),
    mac: str = Form(...),
    interface: str = Form(""),
    source_ip: str = Form(""),
    source_network_cidr: str = Form(""),
    check_method: str = Form("tcp"),
    check_target: str = Form(""),
    check_port: str = Form(""),
):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    current = get_host_by_id(device_id)
    if not current:
        return _redirect("/admin/ui/devices", error=t("error_device_not_found"), request=request)
    try:
        normalized_mac = normalize_mac(mac)
    except ValueError as exc:
        return _redirect("/admin/ui/devices", error=str(exc), request=request)
    if check_method not in {"tcp", "icmp"}:
        return _redirect("/admin/ui/devices", error=t("error_invalid_check_method"), request=request)
    try:
        port_value = int(check_port) if check_port.strip() else None
    except ValueError:
        return _redirect("/admin/ui/devices", error=t("error_check_port_integer"), request=request)
    update_host(
        device_id,
        {
            "name": name,
            "display_name": display_name or None,
            "mac": normalized_mac,
            "interface": interface or None,
            "source_ip": source_ip or None,
            "source_network_cidr": source_network_cidr or None,
            "check_method": check_method,
            "check_target": check_target or None,
            "check_port": port_value,
        },
    )
    log_admin_action(
        actor_username=admin["username"],
        action="ui_update_device",
        target_type="device",
        target_id=device_id,
        detail=f"name={name}",
    )
    return _redirect("/admin/ui/devices", message=t("msg_device_updated", device_id=device_id), request=request)


@router.post("/devices/{device_id}/delete")
def devices_delete(request: Request, device_id: str):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    existing = get_host_by_id(device_id)
    if not delete_host(device_id):
        return _redirect("/admin/ui/devices", error=t("error_device_not_found"), request=request)
    log_admin_action(
        actor_username=admin["username"],
        action="ui_delete_device",
        target_type="device",
        target_id=device_id,
        detail=f"name={existing['name']}" if existing else None,
    )
    return _redirect("/admin/ui/devices", message=t("msg_device_deleted", device_id=device_id), request=request)


@router.post("/devices/{device_id}/test-power-check")
def devices_test_power_check(request: Request, device_id: str):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    host = get_host_by_id(device_id)
    if not host:
        return _redirect("/admin/ui/devices", error=t("error_device_not_found"), request=request)
    result = run_power_check(
        method=host["check_method"] or "tcp",
        target=host["check_target"],
        port=host["check_port"],
    )
    checked_at = datetime.now(UTC).isoformat()
    update_host_power_state(device_id, result.result, checked_at)
    log_power_check(
        device_id=device_id,
        method=result.method,
        result=result.result,
        detail=result.detail,
        latency_ms=result.latency_ms,
    )
    log_admin_action(
        actor_username=admin["username"],
        action="ui_test_power_check",
        target_type="device",
        target_id=device_id,
        detail=f"result={result.result}",
    )
    return _redirect(
        "/admin/ui/devices",
        message=t("msg_power_check_result", result=result.result, detail=result.detail),
        request=request,
    )


@router.get("/scheduled-wakes", response_class=HTMLResponse)
def scheduled_wakes_page(
    request: Request,
    device_id: str | None = None,
    enabled: str = "all",
):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    csrf_input = _csrf_form_input(request)
    selected_device_id = (device_id or "").strip()
    enabled_filter = enabled if enabled in {"all", "enabled", "disabled"} else "all"
    enabled_value = None if enabled_filter == "all" else enabled_filter == "enabled"
    devices = list_hosts()
    jobs = list_scheduled_wake_jobs(limit=200, device_id=selected_device_id or None, enabled=enabled_value)
    runs = list_scheduled_wake_runs(limit=20, device_id=selected_device_id or None)
    message, error = _msg(request)

    device_options = "".join(
        f'<option value="{_esc(row["id"])}" {"selected" if selected_device_id == str(row["id"]) else ""}>'
        f'{_esc(_device_display_label(dict(row)))}</option>'
        for row in devices
    )
    if device_options:
        device_options = f'<option value="">{t("option_all_devices")}</option>{device_options}'
    enabled_options = "".join(
        (
            f'<option value="all" {"selected" if enabled_filter == "all" else ""}>{t("option_enabled_all")}</option>',
            f'<option value="enabled" {"selected" if enabled_filter == "enabled" else ""}>{t("option_enabled_only")}</option>',
            f'<option value="disabled" {"selected" if enabled_filter == "disabled" else ""}>{t("option_disabled_only")}</option>',
        )
    )
    rows_html = "".join(
        f"""
        <tr>
          <td>{_esc(row['label'])}</td>
          <td>{_esc(_device_membership_device_label(dict(row)))}</td>
          <td>{_badge('yes' if row['enabled'] else 'no')}</td>
          <td>{_esc(row['timezone'])}</td>
          <td>{_esc(_format_schedule_days(request, parse_days_of_week_json(str(row['days_of_week_json']))))}</td>
          <td>{_esc(row['local_time'])}</td>
          <td>{_esc(row['next_run_at'])}</td>
          <td>{_esc(row['last_run_at'])}</td>
          <td>{_esc(row['recent_run_result'])}{f"<br><span class='muted'>{_esc(row['recent_run_started_at'])}</span>" if row['recent_run_started_at'] else ""}</td>
          <td>
            <div class="stacked-cell">
              <a href="{_esc(_with_lang(f"/admin/ui/scheduled-wakes/{row['id']}/edit", _lang(request)))}">{t("action_edit")}</a>
              <form method="post" action="/admin/ui/scheduled-wakes/{_esc(row['id'])}/toggle">
                {csrf_input}
                <input type="hidden" name="return_to" value="{_esc(_schedule_filter_path(request, device_id=selected_device_id or None, enabled=enabled_filter))}" />
                <button type="submit" class="{"btn-toggle-on" if row["enabled"] else "btn-toggle-off"}">{t("action_disable") if row['enabled'] else t("action_enable")}</button>
              </form>
              <form method="post" action="/admin/ui/scheduled-wakes/{_esc(row['id'])}/delete" data-confirm="{_esc(t('confirm_delete_schedule', label=str(row['label'])))}">
                {csrf_input}
                <input type="hidden" name="return_to" value="{_esc(_schedule_filter_path(request, device_id=selected_device_id or None, enabled=enabled_filter))}" />
                <button type="submit" class="btn-danger">{t("action_delete")}</button>
              </form>
            </div>
          </td>
        </tr>
        """
        for row in jobs
    ) or f'<tr><td colspan="10">{t("text_no_schedules")}</td></tr>'
    runs_html = "".join(
        f"""
        <tr>
          <td>{_esc(row['job_label'])}</td>
          <td>{_esc(_device_membership_device_label(dict(row)))}</td>
          <td>{_badge(str(row['result']))}</td>
          <td>{_esc(row['detail'])}</td>
          <td>{_esc(row['started_at'])}</td>
          <td>{_esc(row['finished_at'])}</td>
        </tr>
        """
        for row in runs
    ) or f'<tr><td colspan="6">{t("text_no_schedule_runs")}</td></tr>'
    body = f"""
    <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;flex-wrap:wrap;">
      <h2>{t("heading_scheduled_wakes")}</h2>
      <a href="{_esc(_schedule_form_path(request, device_id=selected_device_id or None))}">{t("action_create_schedule")}</a>
    </div>
    <article>
      <h2>{t("heading_schedule_filters")}</h2>
      <form method="get" action="/admin/ui/scheduled-wakes" class="form-inline" style="align-items:end;">
        <input type="hidden" name="lang" value="{_esc(_lang(request))}" />
        <label class="stacked-cell">{t("col_device")}
          <select name="device_id">{device_options}</select>
        </label>
        <label class="stacked-cell">{t("label_filter_enabled")}
          <select name="enabled">{enabled_options}</select>
        </label>
        <button type="submit">{t("action_filter")}</button>
      </form>
    </article>
    <article><table>
      <thead><tr><th>{t("col_label")}</th><th>{t("col_device")}</th><th>{t("col_enabled")}</th><th>{t("col_timezone")}</th><th>{t("col_days")}</th><th>{t("col_local_time")}</th><th>{t("col_next_run")}</th><th>{t("col_last_run")}</th><th>{t("col_recent_result")}</th><th>{t("col_actions")}</th></tr></thead>
      <tbody>{rows_html}</tbody>
    </table></article>
    <h2>{t("heading_recent_scheduled_wake_runs")}</h2>
    <article><table>
      <thead><tr><th>{t("col_label")}</th><th>{t("col_device")}</th><th>{t("col_result")}</th><th>{t("col_detail")}</th><th>{t("col_started_at")}</th><th>{t("col_finished_at")}</th></tr></thead>
      <tbody>{runs_html}</tbody>
    </table></article>
    """
    return _layout(request, t("title_scheduled_wakes"), body, admin["username"], message=message, error=error)


@router.get("/scheduled-wakes/new", response_class=HTMLResponse)
def scheduled_wakes_new_page(request: Request, device_id: str | None = None):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    devices = list_hosts()
    message, error = _msg(request)
    default_days = list(DAY_ORDER[:5])
    values = {
        "device_id": (device_id or "").strip(),
        "label": "",
        "enabled": True,
        "timezone": "UTC",
        "days_of_week": default_days,
        "local_time": "07:30",
    }
    body = _scheduled_wake_form_body(
        request,
        title=t("heading_create_scheduled_wake"),
        action_path="/admin/ui/scheduled-wakes/create",
        submit_label=t("action_create_schedule"),
        devices=[dict(row) for row in devices],
        values=values,
        return_to=_schedule_filter_path(request, device_id=(device_id or "").strip() or None),
    )
    return _layout(request, t("title_new_scheduled_wake"), body, admin["username"], message=message, error=error)


@router.post("/scheduled-wakes/create")
def scheduled_wakes_create(
    request: Request,
    device_id: str = Form(""),
    label: str = Form(""),
    enabled: str = Form(""),
    timezone: str = Form(""),
    days_of_week: list[str] = Form([]),
    local_time: str = Form(""),
    return_to: str = Form("/admin/ui/scheduled-wakes"),
):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    safe_return_to = _safe_next_path(return_to)
    try:
        resolved = _resolve_scheduled_wake_form_values(
            request,
            device_id=device_id,
            label=label,
            enabled=_form_checkbox(enabled),
            timezone_name=timezone,
            days_of_week=days_of_week,
            local_time=local_time,
        )
    except ValueError as exc:
        return _redirect(_schedule_form_path(request, device_id=device_id.strip() or None), error=str(exc), request=request)

    row = create_scheduled_wake_job(
        device_id=str(resolved["device_id"]),
        created_by_user_id=int(admin["id"]),
        label=str(resolved["label"]),
        enabled=bool(resolved["enabled"]),
        timezone=str(resolved["timezone"]),
        days_of_week=[str(day) for day in resolved["days_of_week"]],
        local_time=str(resolved["local_time"]),
        next_run_at=str(resolved["next_run_at"]) if resolved["next_run_at"] is not None else None,
    )
    log_admin_action(
        actor_username=admin["username"],
        action="ui_create_scheduled_wake",
        target_type="scheduled_wake_job",
        target_id=str(row["id"]),
        detail=json.dumps(
            {
                "device_id": resolved["device_id"],
                "enabled": resolved["enabled"],
                "timezone": resolved["timezone"],
                "days_of_week": resolved["days_of_week"],
                "local_time": resolved["local_time"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
    )
    return _redirect(safe_return_to, message=t("msg_schedule_created", label=str(row["label"])), request=request)


@router.get("/scheduled-wakes/{job_id}/edit", response_class=HTMLResponse)
def scheduled_wakes_edit_page(request: Request, job_id: str):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    job = get_scheduled_wake_job(job_id)
    if not job:
        return _redirect("/admin/ui/scheduled-wakes", error=t("error_schedule_not_found"), request=request)
    devices = list_hosts()
    message, error = _msg(request)
    values = {
        "device_id": job["device_id"],
        "label": job["label"],
        "enabled": bool(job["enabled"]),
        "timezone": job["timezone"],
        "days_of_week": parse_days_of_week_json(str(job["days_of_week_json"])),
        "local_time": job["local_time"],
    }
    body = _scheduled_wake_form_body(
        request,
        title=t("heading_edit_scheduled_wake"),
        action_path=f"/admin/ui/scheduled-wakes/{job_id}/update",
        submit_label=t("action_update_schedule"),
        devices=[dict(row) for row in devices],
        values=values,
        return_to=_schedule_filter_path(request, device_id=str(job["device_id"])),
    )
    return _layout(request, t("title_edit_scheduled_wake"), body, admin["username"], message=message, error=error)


@router.post("/scheduled-wakes/{job_id}/update")
def scheduled_wakes_update(
    request: Request,
    job_id: str,
    device_id: str = Form(""),
    label: str = Form(""),
    enabled: str = Form(""),
    timezone: str = Form(""),
    days_of_week: list[str] = Form([]),
    local_time: str = Form(""),
    return_to: str = Form("/admin/ui/scheduled-wakes"),
):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    current = get_scheduled_wake_job(job_id)
    if not current:
        return _redirect("/admin/ui/scheduled-wakes", error=t("error_schedule_not_found"), request=request)
    safe_return_to = _safe_next_path(return_to)
    try:
        resolved = _resolve_scheduled_wake_form_values(
            request,
            device_id=device_id,
            label=label,
            enabled=_form_checkbox(enabled),
            timezone_name=timezone,
            days_of_week=days_of_week,
            local_time=local_time,
            current_job=dict(current),
        )
    except ValueError as exc:
        return _redirect(f"/admin/ui/scheduled-wakes/{job_id}/edit", error=str(exc), request=request)

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
        return _redirect("/admin/ui/scheduled-wakes", error=t("error_schedule_not_found"), request=request)
    log_admin_action(
        actor_username=admin["username"],
        action="ui_update_scheduled_wake",
        target_type="scheduled_wake_job",
        target_id=job_id,
        detail=json.dumps(
            {
                "device_id": resolved["device_id"],
                "enabled": resolved["enabled"],
                "timezone": resolved["timezone"],
                "days_of_week": resolved["days_of_week"],
                "local_time": resolved["local_time"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
    )
    return _redirect(safe_return_to, message=t("msg_schedule_updated", label=str(row["label"])), request=request)


@router.post("/scheduled-wakes/{job_id}/toggle")
def scheduled_wakes_toggle(
    request: Request,
    job_id: str,
    return_to: str = Form("/admin/ui/scheduled-wakes"),
):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    current = get_scheduled_wake_job(job_id)
    if not current:
        return _redirect("/admin/ui/scheduled-wakes", error=t("error_schedule_not_found"), request=request)
    next_enabled = not bool(current["enabled"])
    resolved = _resolve_scheduled_wake_form_values(
        request,
        device_id=str(current["device_id"]),
        label=str(current["label"]),
        enabled=next_enabled,
        timezone_name=str(current["timezone"]),
        days_of_week=parse_days_of_week_json(str(current["days_of_week_json"])),
        local_time=str(current["local_time"]),
        current_job=dict(current),
    )
    row = update_scheduled_wake_job(
        job_id,
        {
            "enabled": int(next_enabled),
            "next_run_at": resolved["next_run_at"],
        },
    )
    if row is None:
        return _redirect("/admin/ui/scheduled-wakes", error=t("error_schedule_not_found"), request=request)
    log_admin_action(
        actor_username=admin["username"],
        action="ui_update_scheduled_wake",
        target_type="scheduled_wake_job",
        target_id=job_id,
        detail=json.dumps({"enabled": next_enabled}, sort_keys=True, separators=(",", ":")),
    )
    message_key = "msg_schedule_enabled" if next_enabled else "msg_schedule_disabled"
    return _redirect(_safe_next_path(return_to), message=t(message_key, label=str(row["label"])), request=request)


@router.post("/scheduled-wakes/{job_id}/delete")
def scheduled_wakes_delete(
    request: Request,
    job_id: str,
    return_to: str = Form("/admin/ui/scheduled-wakes"),
):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    current = get_scheduled_wake_job(job_id)
    if not current:
        return _redirect("/admin/ui/scheduled-wakes", error=t("error_schedule_not_found"), request=request)
    if not delete_scheduled_wake_job(job_id):
        return _redirect("/admin/ui/scheduled-wakes", error=t("error_schedule_not_found"), request=request)
    log_admin_action(
        actor_username=admin["username"],
        action="ui_delete_scheduled_wake",
        target_type="scheduled_wake_job",
        target_id=job_id,
        detail=json.dumps(
            {"device_id": current["device_id"], "label": current["label"]},
            sort_keys=True,
            separators=(",", ":"),
        ),
    )
    return _redirect(
        _safe_next_path(return_to),
        message=t("msg_schedule_deleted", label=str(current["label"])),
        request=request,
    )


@router.get("/device-memberships", response_class=HTMLResponse)
def device_memberships_page(request: Request):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    csrf_input = _csrf_form_input(request)
    users = list_users()
    devices = list_hosts()
    memberships = list_device_memberships()
    message, error = _msg(request)
    user_opts = "".join(
        f'<option value="{row["id"]}">{_esc(row["username"])} ({row["id"]})</option>'
        for row in users
    )
    device_opts = "".join(
        f'<option value="{_esc(row["id"])}">{_esc(row["display_name"] or row["name"])} ({_esc(row["id"])})</option>'
        for row in devices
    )
    rows = "".join(
        f"""
        <tr>
          <td>
            <div class="stacked-cell">
              <strong>{_esc(row['username'])}</strong>
              <span class="muted">#{row['user_id']}</span>
            </div>
          </td>
          <td>
            <div class="stacked-cell">
              <strong>{_esc(_device_membership_device_label(dict(row)))}</strong>
              <span class="muted">{_esc(row['device_id'])}</span>
            </div>
          </td>
          <td>{_bool_icon(row['can_view_status'])}</td>
          <td>{_bool_icon(row['can_wake'])}</td>
          <td>{_bool_icon(row['can_request_shutdown'])}</td>
          <td>{_bool_icon(row['can_manage_schedule'])}</td>
          <td>{_bool_icon(row['is_favorite'])}</td>
          <td>{_esc(row['sort_order'])}</td>
          <td>{_esc(row['created_at'])}</td>
          <td>{_esc(row['updated_at'])}</td>
          <td>
            <form method="post" action="/admin/ui/device-memberships/{_esc(row['id'])}/update">
              {csrf_input}
              <div class="membership-permissions">
                <label class="checkbox-item"><input type="checkbox" name="can_view_status" value="1" {_checkbox_checked(row['can_view_status'])} /> {t("label_can_view_status")}</label>
                <label class="checkbox-item"><input type="checkbox" name="can_wake" value="1" {_checkbox_checked(row['can_wake'])} /> {t("label_can_wake")}</label>
                <label class="checkbox-item"><input type="checkbox" name="can_request_shutdown" value="1" {_checkbox_checked(row['can_request_shutdown'])} /> {t("label_can_request_shutdown")}</label>
                <label class="checkbox-item"><input type="checkbox" name="can_manage_schedule" value="1" {_checkbox_checked(row['can_manage_schedule'])} /> {t("label_can_manage_schedule")}</label>
                <label class="checkbox-item"><input type="checkbox" name="is_favorite" value="1" {_checkbox_checked(row['is_favorite'])} /> {t("label_is_favorite")}</label>
                <label class="stacked-cell">{t("label_sort_order")}<input name="sort_order" value="{_esc(row['sort_order'])}" placeholder="{t("placeholder_sort_order")}" /></label>
              </div>
              <button type="submit">{t("action_save")}</button>
            </form>
          </td>
          <td>
            <form method="post" action="/admin/ui/device-memberships/{_esc(row['id'])}/delete" data-confirm="{_esc(t('confirm_remove_device_access', username=str(row['username']), device=_device_membership_device_label(dict(row))))}">
              {csrf_input}
              <button type="submit" class="btn-danger">{t("action_remove")}</button>
            </form>
          </td>
        </tr>
        """
        for row in memberships
    )
    body = f"""
    <article>
    <h2>{t("heading_grant_device_access")}</h2>
    <form method="post" action="/admin/ui/device-memberships/create" class="membership-create-form">
      {csrf_input}
      <label class="stacked-cell">{t("col_user")}<select name="user_id">{user_opts}</select></label>
      <label class="stacked-cell">{t("col_device")}<select name="device_id">{device_opts}</select></label>
      <div class="checkbox-group" style="grid-column:1 / -1;">
        <label class="checkbox-item"><input type="checkbox" name="can_view_status" value="1" checked /> {t("label_can_view_status")}</label>
        <label class="checkbox-item"><input type="checkbox" name="can_wake" value="1" checked /> {t("label_can_wake")}</label>
        <label class="checkbox-item"><input type="checkbox" name="can_request_shutdown" value="1" checked /> {t("label_can_request_shutdown")}</label>
        <label class="checkbox-item"><input type="checkbox" name="can_manage_schedule" value="1" /> {t("label_can_manage_schedule")}</label>
        <label class="checkbox-item"><input type="checkbox" name="is_favorite" value="1" /> {t("label_is_favorite")}</label>
      </div>
      <label class="stacked-cell">{t("label_sort_order")}<input name="sort_order" value="0" placeholder="{t("placeholder_sort_order")}" /></label>
      <div style="display:flex;align-items:end;">
        <button type="submit">{t("action_grant_access")}</button>
      </div>
    </form>
    </article>
    <h2>{t("heading_device_access")}</h2>
    <article><table class="membership-table">
      <thead>
        <tr>
          <th>{t("col_user")}</th>
          <th>{t("col_device")}</th>
          <th>{t("col_view_status")}</th>
          <th>{t("col_wake")}</th>
          <th>{t("col_request_shutdown")}</th>
          <th>{t("col_manage_schedule")}</th>
          <th>{t("col_favorite")}</th>
          <th>{t("col_sort_order")}</th>
          <th>{t("col_created")}</th>
          <th>{t("col_updated")}</th>
          <th>{t("col_update")}</th>
          <th>{t("col_delete")}</th>
        </tr>
      </thead>
      <tbody>{rows or _empty_row(request, 12)}</tbody>
    </table></article>
    """
    return _layout(request, t("title_device_access"), body, admin["username"], message=message, error=error)


@router.post("/device-memberships/create")
def device_memberships_create(
    request: Request,
    user_id: int = Form(...),
    device_id: str = Form(...),
    can_view_status: str = Form(""),
    can_wake: str = Form(""),
    can_request_shutdown: str = Form(""),
    can_manage_schedule: str = Form(""),
    is_favorite: str = Form(""),
    sort_order: str = Form("0"),
):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    if not get_user_by_id(user_id):
        return _redirect("/admin/ui/device-memberships", error=t("error_user_not_found"), request=request)
    device = get_host_by_id(device_id)
    if not device:
        return _redirect("/admin/ui/device-memberships", error=t("error_device_not_found"), request=request)
    try:
        sort_order_value = int(sort_order.strip() or "0")
    except ValueError:
        return _redirect("/admin/ui/device-memberships", error=t("error_sort_order_integer"), request=request)
    existing = get_device_membership_for_user_device(user_id, device_id)
    if existing:
        updated_existing = update_device_membership(
            str(existing["id"]),
            {
                "can_view_status": int(_form_checkbox(can_view_status)),
                "can_wake": int(_form_checkbox(can_wake)),
                "can_request_shutdown": int(_form_checkbox(can_request_shutdown)),
                "can_manage_schedule": int(_form_checkbox(can_manage_schedule)),
                "is_favorite": int(_form_checkbox(is_favorite)),
                "sort_order": sort_order_value,
            },
        )
        resolved = updated_existing or existing
        username = str(resolved["username"])
        device_label = _device_membership_device_label(dict(resolved))
        log_admin_action(
            actor_username=admin["username"],
            action="ui_update_device_membership",
            target_type="device_membership",
            target_id=str(resolved["id"]),
            detail=(
                f"user={username} device={device_label} "
                f"view={int(bool(resolved['can_view_status']))} "
                f"wake={int(bool(resolved['can_wake']))} "
                f"shutdown={int(bool(resolved['can_request_shutdown']))} "
                f"schedule={int(bool(resolved['can_manage_schedule']))} "
                f"favorite={int(bool(resolved['is_favorite']))} "
                f"sort_order={resolved['sort_order']}"
            ),
        )
        return _redirect(
            "/admin/ui/device-memberships",
            message=t(
                "msg_membership_updated",
                username=username,
                device=device_label,
            ),
            request=request,
        )
    membership = create_device_membership(
        user_id=user_id,
        device_id=device_id,
        can_view_status=_form_checkbox(can_view_status),
        can_wake=_form_checkbox(can_wake),
        can_request_shutdown=_form_checkbox(can_request_shutdown),
        can_manage_schedule=_form_checkbox(can_manage_schedule),
        is_favorite=_form_checkbox(is_favorite),
        sort_order=sort_order_value,
    )
    username = str(membership["username"])
    device_label = _device_membership_device_label(dict(membership))
    log_admin_action(
        actor_username=admin["username"],
        action="ui_create_device_membership",
        target_type="device_membership",
        target_id=str(membership["id"]),
        detail=(
            f"user={username} device={device_label} "
            f"view={int(bool(membership['can_view_status']))} "
            f"wake={int(bool(membership['can_wake']))} "
            f"shutdown={int(bool(membership['can_request_shutdown']))} "
            f"schedule={int(bool(membership['can_manage_schedule']))} "
            f"favorite={int(bool(membership['is_favorite']))} "
            f"sort_order={membership['sort_order']}"
        ),
    )
    return _redirect(
        "/admin/ui/device-memberships",
        message=t("msg_membership_created", username=username, device=device_label),
        request=request,
    )


@router.post("/device-memberships/{membership_id}/update")
def device_memberships_update(
    request: Request,
    membership_id: str,
    can_view_status: str = Form(""),
    can_wake: str = Form(""),
    can_request_shutdown: str = Form(""),
    can_manage_schedule: str = Form(""),
    is_favorite: str = Form(""),
    sort_order: str = Form("0"),
):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    membership = get_device_membership_by_id(membership_id)
    if not membership:
        return _redirect("/admin/ui/device-memberships", error=t("error_device_access_not_found"), request=request)
    try:
        sort_order_value = int(sort_order.strip() or "0")
    except ValueError:
        return _redirect("/admin/ui/device-memberships", error=t("error_sort_order_integer"), request=request)
    updated = update_device_membership(
        membership_id,
        {
            "can_view_status": int(_form_checkbox(can_view_status)),
            "can_wake": int(_form_checkbox(can_wake)),
            "can_request_shutdown": int(_form_checkbox(can_request_shutdown)),
            "can_manage_schedule": int(_form_checkbox(can_manage_schedule)),
            "is_favorite": int(_form_checkbox(is_favorite)),
            "sort_order": sort_order_value,
        },
    )
    if not updated:
        return _redirect("/admin/ui/device-memberships", error=t("error_device_access_not_found"), request=request)
    username = str(updated["username"])
    device_label = _device_membership_device_label(dict(updated))
    log_admin_action(
        actor_username=admin["username"],
        action="ui_update_device_membership",
        target_type="device_membership",
        target_id=str(updated["id"]),
        detail=(
            f"user={username} device={device_label} "
            f"view={int(bool(updated['can_view_status']))} "
            f"wake={int(bool(updated['can_wake']))} "
            f"shutdown={int(bool(updated['can_request_shutdown']))} "
            f"schedule={int(bool(updated['can_manage_schedule']))} "
            f"favorite={int(bool(updated['is_favorite']))} "
            f"sort_order={updated['sort_order']}"
        ),
    )
    return _redirect(
        "/admin/ui/device-memberships",
        message=t("msg_membership_updated", username=username, device=device_label),
        request=request,
    )


@router.post("/device-memberships/{membership_id}/delete")
def device_memberships_delete(request: Request, membership_id: str):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    membership = get_device_membership_by_id(membership_id)
    if not membership or not delete_device_membership(str(membership["id"])):
        return _redirect("/admin/ui/device-memberships", error=t("error_device_access_not_found"), request=request)
    username = str(membership["username"])
    device_label = _device_membership_device_label(dict(membership))
    log_admin_action(
        actor_username=admin["username"],
        action="ui_delete_device_membership",
        target_type="device_membership",
        target_id=str(membership["id"]),
        detail=f"user={username} device={device_label}",
    )
    return _redirect(
        "/admin/ui/device-memberships",
        message=t("msg_membership_deleted", username=username, device=device_label),
        request=request,
    )


@router.get("/invites", response_class=HTMLResponse)
def invites_page(request: Request):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    return _redirect(
        "/admin/ui/users",
        error="Invite workflow is disabled. Create users manually and share credentials securely.",
        request=request,
    )


@router.post("/invites/create", response_class=HTMLResponse)
def invites_create(
    request: Request,
    username: str = Form(...),
):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    del username
    return _redirect(
        "/admin/ui/users",
        error="Invite workflow is disabled. Create users manually and share credentials securely.",
        request=request,
    )


@router.post("/invites/{invite_id}/revoke")
def invites_revoke(request: Request, invite_id: str):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    del invite_id
    return _redirect(
        "/admin/ui/users",
        error="Invite workflow is disabled. Create users manually and share credentials securely.",
        request=request,
    )


@router.get("/wake-logs", response_class=HTMLResponse)
def wake_logs_page(
    request: Request,
    limit: int = 100,
    result: str = "",
    actor: str = "",
    host_id: str = "",
):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    limit = max(1, min(limit, 500))
    rows = list_wake_logs(limit=limit)
    if result:
        rows = [row for row in rows if row["result"] == result]
    if actor:
        rows = [row for row in rows if actor.lower() in str(row["actor_username"]).lower()]
    if host_id:
        rows = [row for row in rows if host_id.lower() in str(row["host_id"]).lower()]
    device_name_map = {str(h["id"]): str(h["name"]) for h in list_hosts()}
    message, error = _msg(request)
    body_rows = "".join(
        f"<tr><td>{_short_id(row['id'])}</td><td>{_device_cell(row['host_id'], device_name_map)}</td><td>{_esc(row['actor_username'])}</td><td>{_badge(str(row['result']))}</td><td>{_esc(row['precheck_state'])}</td><td>{_esc(row['error_detail'])}</td><td>{_esc(row['created_at'])}</td></tr>"
        for row in rows
    )
    body = f"""
    <article>
    <h2>{t("heading_wake_logs")}</h2>
    <form method="get" class="form-inline">
      <input name="host_id" value="{_esc(host_id)}" placeholder="{t("placeholder_host_id_filter")}" />
      <input name="actor" value="{_esc(actor)}" placeholder="{t("placeholder_actor_filter")}" />
      <select name="result">
        <option value="" {"selected" if not result else ""}>{t("option_all_results")}</option>
        <option value="sent" {"selected" if result=="sent" else ""}>sent</option>
        <option value="already_on" {"selected" if result=="already_on" else ""}>already_on</option>
        <option value="failed" {"selected" if result=="failed" else ""}>failed</option>
      </select>
      <input name="limit" value="{limit}" style="width:80px" />
      <button type="submit">{t("action_filter")}</button>
    </form>
    </article>
    <article><table>
      <thead><tr><th>{t("col_id")}</th><th>{t("col_host_id")}</th><th>{t("col_actor")}</th><th>{t("col_result")}</th><th>{t("col_precheck")}</th><th>{t("col_error")}</th><th>{t("col_created")}</th></tr></thead>
      <tbody>{body_rows or _empty_row(request, 7)}</tbody>
    </table></article>
    """
    return _layout(request, t("title_wake_logs"), body, admin["username"], message=message, error=error)


@router.get("/power-check-logs", response_class=HTMLResponse)
def power_logs_page(
    request: Request,
    limit: int = 100,
    result: str = "",
    method: str = "",
    device_id: str = "",
):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    limit = max(1, min(limit, 500))
    rows = list_power_check_logs(limit=limit)
    if result:
        rows = [row for row in rows if row["result"] == result]
    if method:
        rows = [row for row in rows if row["method"] == method]
    if device_id:
        rows = [row for row in rows if device_id.lower() in str(row["device_id"]).lower()]
    device_name_map = {str(h["id"]): str(h["name"]) for h in list_hosts()}
    message, error = _msg(request)
    body_rows = "".join(
        f"<tr><td>{_short_id(row['id'])}</td><td>{_device_cell(row['device_id'], device_name_map)}</td><td>{_badge(str(row['method']))}</td><td>{_badge(str(row['result']))}</td><td>{_esc(row['detail'])}</td><td>{_esc(row['latency_ms'])}</td><td>{_esc(row['created_at'])}</td></tr>"
        for row in rows
    )
    body = f"""
    <article>
    <h2>{t("heading_power_check_logs")}</h2>
    <form method="get" class="form-inline">
      <input name="device_id" value="{_esc(device_id)}" placeholder="{t("placeholder_device_id_filter")}" />
      <select name="method">
        <option value="" {"selected" if not method else ""}>{t("option_all_methods")}</option>
        <option value="tcp" {"selected" if method=="tcp" else ""}>tcp</option>
        <option value="icmp" {"selected" if method=="icmp" else ""}>icmp</option>
      </select>
      <select name="result">
        <option value="" {"selected" if not result else ""}>{t("option_all_results")}</option>
        <option value="on" {"selected" if result=="on" else ""}>on</option>
        <option value="off" {"selected" if result=="off" else ""}>off</option>
        <option value="unknown" {"selected" if result=="unknown" else ""}>unknown</option>
      </select>
      <input name="limit" value="{limit}" style="width:80px" />
      <button type="submit">{t("action_filter")}</button>
    </form>
    </article>
    <article><table>
      <thead><tr><th>{t("col_id")}</th><th>{t("col_device_id")}</th><th>{t("col_method")}</th><th>{t("col_result")}</th><th>{t("col_detail")}</th><th>{t("col_latency_ms")}</th><th>{t("col_created")}</th></tr></thead>
      <tbody>{body_rows or _empty_row(request, 7)}</tbody>
    </table></article>
    """
    return _layout(request, t("title_power_check_logs"), body, admin["username"], message=message, error=error)


@router.get("/diagnostics", response_class=HTMLResponse)
def diagnostics_page(request: Request):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    network_diag = build_network_diagnostics_snapshot()
    network_rows = []
    for row in network_diag["interfaces"]:
        network_rows.append(
            "<tr>"
            f"<td>{_esc(str(row['name']))}</td>"
            f"<td>{_esc(str(row['ipv4']))}</td>"
            f"<td>{_esc(str(row['netmask']))}</td>"
            f"<td>{_esc(str(row['network_cidr']))}</td>"
            f"<td>{_esc(str(row['broadcast']))}</td>"
            f"<td>{t('value_yes') if row['is_up'] else t('value_no')}</td>"
            f"<td>{t('value_yes') if row['is_loopback'] else t('value_no')}</td>"
            "</tr>"
        )
    rows = []
    for host in list_hosts():
        rows.append(
            f"<tr><td>{_short_id(host['id'])}</td><td>{_esc(host['name'])}</td><td>{'<br/>'.join(_esc(h) for h in device_diagnostic_hints(dict(host)))}</td></tr>"
        )
    networks = ", ".join(str(row) for row in network_diag["detected_ipv4_networks"]) or "-"
    body = f"""
    <h2>{t("heading_network_interfaces")}</h2>
    <p>{t("text_detected_networks")}: <strong>{_esc(networks)}</strong></p>
    <p>{t("text_multiple_networks_available")}: <strong>{t("value_yes") if network_diag["has_multiple_active_networks"] else t("value_no")}</strong></p>
    <article><table>
      <thead><tr><th>{t("col_interface")}</th><th>{t("col_ipv4")}</th><th>{t("col_netmask")}</th><th>{t("col_network")}</th><th>{t("col_broadcast")}</th><th>{t("col_up")}</th><th>{t("col_loopback")}</th></tr></thead>
      <tbody>{''.join(network_rows) or _empty_row(request, 7)}</tbody>
    </table></article>
    <h2>{t("heading_device_diagnostics_hints")}</h2>
    <article><table>
      <thead><tr><th>{t("col_device_id")}</th><th>{t("col_name")}</th><th>{t("col_hints")}</th></tr></thead>
      <tbody>{''.join(rows) or _empty_row(request, 3)}</tbody>
    </table></article>
    """
    message, error = _msg(request)
    return _layout(request, t("title_diagnostics"), body, admin["username"], message=message, error=error)


def _is_docker_candidate(row: sqlite3.Row) -> bool:
    iface = str(row["source_interface"] or "")
    return iface.startswith("br-") or iface in {"docker0", "veth"}


@router.get("/discovery", response_class=HTMLResponse)
def discovery_page(request: Request, run_id: str = "", show_docker: str = ""):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    csrf_input = _csrf_form_input(request)
    settings = get_settings()
    if not settings.discovery_enabled:
        body = f"<article><p>{t('error_discovery_disabled')}</p></article>"
        message, error = _msg(request)
        return _layout(request, t("title_discovery"), body, admin["username"], message=message, error=error)

    bindings = discover_sender_bindings()
    runs = list_discovery_runs(limit=30)
    selected_run_id = run_id.strip() or (str(runs[0]["id"]) if runs else "")
    all_candidates = list_discovery_candidates(selected_run_id) if selected_run_id else []
    show_docker_flag = show_docker.strip() == "1"
    docker_count = sum(1 for c in all_candidates if _is_docker_candidate(c))
    candidates = all_candidates if show_docker_flag else [c for c in all_candidates if not _is_docker_candidate(c)]
    events = list_discovery_events(selected_run_id, limit=30) if selected_run_id else []
    mac_map: dict[str, tuple[str, str]] = {}
    for host in list_hosts():
        mac = str(host["mac"] or "")
        if mac and mac not in mac_map:
            mac_map[mac] = (str(host["id"]), str(host["name"]))

    run_rows = []
    for row in runs:
        summary = _parse_json_dict(row["summary_json"])
        summary_text = (
            f"candidates={summary.get('candidate_count', 0)}, "
            f"high={summary.get('wol_high_confidence_count', 0)}, "
            f"warnings={len(summary.get('warnings', []))}"
        )
        run_rows.append(
            "<tr>"
            f"<td><a href=\"{_with_lang(f'/admin/ui/discovery?run_id={_esc(row['id'])}', _lang(request))}\">{_short_id(row['id'])}</a></td>"
            f"<td>{_badge(str(row['status']))}</td>"
            f"<td>{_esc(summary_text)}</td>"
            f"<td>{_esc(row['created_at'])}</td>"
            "</tr>"
        )

    candidate_rows = []
    for row in candidates:
        suggested = mac_map.get(str(row["mac"] or ""))
        suggested_host_id = suggested[0] if suggested else ""
        suggested_host_name = suggested[1] if suggested else ""
        suggested_cell = _esc(f"{suggested_host_name} ({suggested_host_id})") if suggested else "-"
        suggested_action = ""
        if suggested and not row["imported_host_id"]:
            suggested_action = (
                f'<form method="post" action="/admin/ui/discovery/candidates/{_esc(row["id"])}/import" style="display:inline;">'
                f"{csrf_input}"
                '<input type="hidden" name="mode" value="auto_merge_by_mac" />'
                '<input type="hidden" name="apply_power_settings" value="1" />'
                f'<button type="submit" class="secondary">{t("action_merge_suggested")}</button>'
                "</form>"
            )
        candidate_rows.append(
            f"""
            <tr>
              <td>{_short_id(row['id'])}</td>
              <td>{_esc(row['hostname'])}</td>
              <td>{_esc(row['mac'])}</td>
              <td>{_esc(row['ip'])}</td>
              <td>{_badge(str(row['wol_confidence']))}</td>
              <td>{_esc(row['source_network_cidr'])}</td>
              <td>{_short_id(row['imported_host_id'])}</td>
              <td>{suggested_cell}</td>
              <td>
                {suggested_action}
                <form method="post" action="/admin/ui/discovery/candidates/{_esc(row['id'])}/validate-wake" style="display:inline;">
                  {csrf_input}
                  <button type="submit" class="secondary">{t("action_validate_wake")}</button>
                </form>
                <form method="post" action="/admin/ui/discovery/candidates/{_esc(row['id'])}/import" style="display:inline-flex;gap:6px;align-items:center;">
                  {csrf_input}
                  <input name="mode" type="hidden" value="create_new" />
                  <input name="apply_power_settings" type="hidden" value="1" />
                  <input name="name" placeholder="{t("placeholder_name")}" style="max-width:180px" />
                  <button type="submit">{t("action_import_candidate")}</button>
                </form>
              </td>
            </tr>
            """
        )

    event_rows = "".join(
        f"<tr><td>{_short_id(row['id'])}</td><td>{_esc(row['event_type'])}</td><td>{_short_id(row['candidate_id'])}</td><td>{_esc(row['detail'])}</td><td>{_esc(row['created_at'])}</td></tr>"
        for row in events
    )
    binding_text = ", ".join(
        f"{_esc(row.get('network_cidr'))} via {_esc(row.get('source_ip'))}"
        for row in bindings
    ) or "-"
    bulk_form = ""
    if selected_run_id:
        bulk_form = f"""
    <form method="post" action="/admin/ui/discovery/runs/{_esc(selected_run_id)}/import-bulk" class="form-inline" style="margin-bottom:.8rem;">
      {csrf_input}
      <label>{t("label_import_mode")}
        <select name="mode">
          <option value="auto_merge_by_mac">{t("option_auto_merge_by_mac")}</option>
          <option value="create_new">{t("option_create_new")}</option>
        </select>
      </label>
      <input name="name_prefix" placeholder="discovered" />
      <label class="checkbox-item"><input type="checkbox" name="apply_power_settings" value="1" checked />power settings</label>
      <label class="checkbox-item"><input type="checkbox" name="skip_without_mac" value="1" checked />skip without mac</label>
      <button type="submit">{t("action_bulk_import")}</button>
    </form>
        """

    body = f"""
    <article>
    <h2>{t("heading_discovery_scan")}</h2>
    <p>{t("text_active_sender_bindings")}: <strong>{binding_text}</strong></p>
    <form method="post" action="/admin/ui/discovery/run" class="form-grid form-grid-4">
      {csrf_input}
      <input name="network_cidrs" placeholder="{t("placeholder_network_cidrs")}" />
      <input name="power_ports" placeholder="{t("placeholder_power_ports")}" />
      <input name="power_timeout_ms" value="200" />
      <label class="checkbox-item"><input type="checkbox" name="host_probe_enabled" value="1" /> host probe</label>
      <input name="host_probe_timeout_ms" value="200" />
      <input name="max_hosts_per_network" value="{settings.discovery_default_host_cap}" />
      <button type="submit">{t("action_run_discovery")}</button>
    </form>
    </article>
    <details open>
    <summary><h2>{t("heading_discovery_runs")}</h2></summary>
    <article><table>
      <thead><tr><th>{t("col_run_id")}</th><th>{t("col_status")}</th><th>{t("col_summary")}</th><th>{t("col_created")}</th></tr></thead>
      <tbody>{''.join(run_rows) or _empty_row(request, 4)}</tbody>
    </table></article>
    </details>
    <details open>
    <summary><h2>{t("heading_discovery_candidates")}</h2></summary>
    {bulk_form}
    <p style="margin-bottom:.5rem;font-size:.875rem;">
      {"" if not docker_count else (
        f'<a href="{_with_lang(f"/admin/ui/discovery?run_id={_esc(selected_run_id)}", _lang(request))}">'
        f"Show real devices only</a>" if show_docker_flag else
        f'<a href="{_with_lang(f"/admin/ui/discovery?run_id={_esc(selected_run_id)}&show_docker=1", _lang(request))}">'
        f"Show all ({docker_count} Docker containers hidden)</a>"
      )}
    </p>
    <article><table>
      <thead><tr><th>{t("col_id")}</th><th>{t("col_name")}</th><th>{t("col_mac")}</th><th>{t("col_ipv4")}</th><th>{t("col_wol_confidence")}</th><th>{t("col_source_network")}</th><th>{t("col_imported_host")}</th><th>{t("col_suggested_host")}</th><th>{t("col_actions")}</th></tr></thead>
      <tbody>{''.join(candidate_rows) or _empty_row(request, 9)}</tbody>
    </table></article>
    </details>
    <details>
    <summary><h2>{t("heading_discovery_events")}</h2></summary>
    <article><table>
      <thead><tr><th>{t("col_id")}</th><th>{t("col_action")}</th><th>{t("col_device_id")}</th><th>{t("col_detail")}</th><th>{t("col_created")}</th></tr></thead>
      <tbody>{event_rows or _empty_row(request, 5)}</tbody>
    </table></article>
    </details>
    """
    message, error = _msg(request)
    return _layout(request, t("title_discovery"), body, admin["username"], message=message, error=error)


@router.post("/discovery/run")
def discovery_run(
    request: Request,
    background_tasks: BackgroundTasks,
    network_cidrs: str = Form(""),
    power_ports: str = Form("22,80,443,445"),
    power_timeout_ms: int = Form(200),
    host_probe_enabled: str = Form(""),
    host_probe_timeout_ms: int = Form(200),
    max_hosts_per_network: int = Form(256),
):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    settings = get_settings()
    if not settings.discovery_enabled:
        return _redirect("/admin/ui/discovery", error=t("error_discovery_disabled"), request=request)

    selected_networks = set(_parse_csv(network_cidrs))
    source_bindings = normalize_source_bindings(source_bindings=[], fallback_bindings=discover_sender_bindings())
    if selected_networks:
        source_bindings = [row for row in source_bindings if str(row.get("network_cidr") or "") in selected_networks]
    if not source_bindings:
        return _redirect("/admin/ui/discovery", error=t("error_no_discovery_bindings"), request=request)

    options = {
        "network_cidrs": sorted(selected_networks),
        "source_bindings": source_bindings,
        "host_probe": {
            "enabled": bool(host_probe_enabled.strip()),
            "timeout_ms": max(50, min(host_probe_timeout_ms, 5000)),
            "max_hosts_per_network": max(1, min(max_hosts_per_network, 4096)),
        },
        "power_probe": {
            "ports": _parse_ports(power_ports, settings.discovery_default_tcp_ports_list),
            "timeout_ms": max(50, min(power_timeout_ms, 5000)),
        },
    }
    run_id = create_discovery_run(requested_by=admin["username"], options_json=json.dumps(options))
    log_admin_action(
        actor_username=admin["username"],
        action="ui_start_discovery_run",
        target_type="discovery",
        target_id=run_id,
        detail=f"networks={len(source_bindings)}",
    )
    background_tasks.add_task(_execute_discovery_run_ui, run_id)
    return _redirect(
        f"/admin/ui/discovery?run_id={run_id}",
        message=t("msg_discovery_run_started", run_id=run_id),
        request=request,
    )


@router.post("/discovery/candidates/{candidate_id}/validate-wake")
def discovery_validate_candidate(request: Request, candidate_id: str):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    candidate = get_discovery_candidate(candidate_id)
    if not candidate:
        return _redirect("/admin/ui/discovery", error=t("error_device_not_found"), request=request)

    result = "failed"
    detail = "missing_mac"
    if candidate["mac"]:
        target_ip = resolve_target(broadcast=candidate["broadcast_ip"], subnet_cidr=candidate["source_network_cidr"])
        try:
            send_magic_packet(
                mac=candidate["mac"],
                target_ip=target_ip,
                udp_port=9,
                interface=candidate["source_interface"],
                source_ip=candidate["source_ip"],
            )
            result = "sent"
            detail = "magic_packet_sent"
            if candidate["power_check_target"] and candidate["power_check_port"]:
                check = run_power_check(
                    method="tcp",
                    target=candidate["power_check_target"],
                    port=candidate["power_check_port"],
                )
                if check.result == "on":
                    result = "validated"
                detail = check.detail
        except Exception as exc:
            result = "failed"
            detail = str(exc)

    log_discovery_event(
        run_id=candidate["run_id"],
        candidate_id=candidate_id,
        event_type="validation",
        detail=f"{result}:{detail}",
    )
    log_admin_action(
        actor_username=admin["username"],
        action="ui_validate_discovery_candidate",
        target_type="discovery",
        target_id=candidate_id,
        detail=f"result={result}",
    )
    return _redirect(
        f"/admin/ui/discovery?run_id={candidate['run_id']}",
        message=t("msg_discovery_validate_result", result=result, detail=detail),
        request=request,
    )


@router.post("/discovery/candidates/{candidate_id}/import")
def discovery_import_candidate(
    request: Request,
    candidate_id: str,
    mode: str = Form("create_new"),
    name: str = Form(""),
    display_name: str = Form(""),
    target_host_id: str = Form(""),
    apply_power_settings: str = Form(""),
    group_name: str = Form(""),
):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    candidate = get_discovery_candidate(candidate_id)
    if not candidate:
        return _redirect("/admin/ui/discovery", error="candidate not found", request=request)

    use_power = bool(apply_power_settings.strip())
    try:
        host_id, effective_mode = _import_discovery_candidate_ui(
            dict(candidate),
            mode=mode,
            name=name.strip() or None,
            display_name=display_name.strip() or None,
            target_host_id=target_host_id.strip() or None,
            apply_power_settings=use_power,
            group_name=group_name.strip() or None,
        )
    except Exception as exc:
        return _redirect(f"/admin/ui/discovery?run_id={candidate['run_id']}", error=str(exc), request=request)

    mark_discovery_candidate_imported(candidate_id, host_id)
    log_discovery_event(
        run_id=candidate["run_id"],
        candidate_id=candidate_id,
        event_type="import",
        detail=f"mode={mode} effective_mode={effective_mode} host_id={host_id}",
    )
    log_admin_action(
        actor_username=admin["username"],
        action="ui_import_discovery_candidate",
        target_type="discovery",
        target_id=candidate_id,
        detail=f"mode={mode} effective_mode={effective_mode} host_id={host_id}",
    )
    return _redirect(
        f"/admin/ui/discovery?run_id={candidate['run_id']}",
        message=_tr(request, "msg_discovery_candidate_imported", host_id=host_id),
        request=request,
    )


@router.post("/discovery/runs/{run_id}/import-bulk")
def discovery_bulk_import_run(
    request: Request,
    run_id: str,
    mode: str = Form("auto_merge_by_mac"),
    name_prefix: str = Form(""),
    apply_power_settings: str = Form(""),
    group_name: str = Form(""),
    skip_without_mac: str = Form(""),
):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    run = get_discovery_run(run_id)
    if not run:
        return _redirect("/admin/ui/discovery", error="run not found", request=request)
    candidates = list_discovery_candidates(run_id=run_id, only_unimported=True)
    processed = 0
    imported = 0
    merged = 0
    created = 0
    skipped = 0
    failed = 0
    use_power = bool(apply_power_settings.strip())
    skip_missing_mac = bool(skip_without_mac.strip())
    for row in candidates:
        candidate = dict(row)
        processed += 1
        candidate_id = str(candidate["id"])
        if not candidate.get("mac") and skip_missing_mac:
            skipped += 1
            continue
        try:
            host_id, effective_mode = _import_discovery_candidate_ui(
                candidate,
                mode=mode,
                name=None,
                display_name=None,
                target_host_id=None,
                apply_power_settings=use_power,
                group_name=group_name.strip() or None,
                name_prefix=name_prefix.strip() or None,
            )
            mark_discovery_candidate_imported(candidate_id, host_id)
            log_discovery_event(
                run_id=run_id,
                candidate_id=candidate_id,
                event_type="import",
                detail=f"ui bulk mode={mode} effective_mode={effective_mode} host_id={host_id}",
            )
            imported += 1
            if effective_mode == "update_existing":
                merged += 1
            else:
                created += 1
        except Exception as exc:
            failed += 1
            log_discovery_event(
                run_id=run_id,
                candidate_id=candidate_id,
                event_type="error",
                detail=f"ui bulk import failed: {exc}",
            )
    log_admin_action(
        actor_username=admin["username"],
        action="ui_bulk_import_discovery_run",
        target_type="discovery",
        target_id=run_id,
        detail=f"mode={mode} processed={processed} imported={imported} merged={merged} created={created} skipped={skipped} failed={failed}",
    )
    return _redirect(
        f"/admin/ui/discovery?run_id={run_id}",
        message=_tr(
            request,
            "msg_discovery_bulk_imported",
            imported=imported,
            merged=merged,
            created=created,
            skipped=skipped,
            failed=failed,
        ),
        request=request,
    )


@router.get("/audit-logs", response_class=HTMLResponse)
def audit_logs_page(request: Request):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    rows = list_admin_audit_logs(limit=500)
    body_rows = "".join(
        f"<tr><td>{_short_id(row['id'])}</td><td>{_esc(row['actor_username'])}</td><td>{_esc(row['action'])}</td><td>{_esc(row['target_type'])}</td><td>{_short_id(row['target_id'])}</td><td>{_esc(row['detail'])}</td><td>{_esc(row['created_at'])}</td></tr>"
        for row in rows
    )
    body = f"""
    <h2>{t("heading_admin_audit_logs")}</h2>
    <article><table>
      <thead><tr><th>{t("col_id")}</th><th>{t("col_actor")}</th><th>{t("col_action")}</th><th>{t("col_target_type")}</th><th>{t("col_target_id")}</th><th>{t("col_detail")}</th><th>{t("col_created")}</th></tr></thead>
      <tbody>{body_rows or _empty_row(request, 7)}</tbody>
    </table></article>
    """
    message, error = _msg(request)
    return _layout(request, t("title_audit_logs"), body, admin["username"], message=message, error=error)


@router.get("/metrics", response_class=HTMLResponse)
def metrics_page(request: Request):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    counters = get_counters()
    security_status = build_security_status(
        settings=get_settings(),
        counters=counters,
        installation_rows=[dict(row) for row in list_app_installations(limit=200)],
        recent_events=get_recent_events(limit=200),
    ).model_dump(mode="json")
    rows = "".join(
        f"<tr><td>{_esc(name)}</td><td>{value}</td></tr>" for name, value in sorted(counters.items(), key=lambda kv: kv[0])
    )
    warning_rows = "".join(
        f"<li><strong>{_esc(item['code'])}</strong>: {_esc(item['message'])}</li>"
        for item in security_status["warnings"]
    )
    deferral_rows = "".join(
        f"<li><strong>{_esc(item['code'])}</strong>: {_esc(item['message'])}</li>"
        for item in security_status["deferrals"]
    )
    failure_rows = "".join(
        f"<tr><td>{_esc(item['category'])}</td><td>{_esc(item['count'])}</td><td>{_esc(item['last_seen_at'])}</td></tr>"
        for item in security_status["recent_app_proof_failures"]
    )
    installation_rows = "".join(
        f"<tr><td>{_esc(platform)}</td><td>{_esc(data['total'])}</td><td>{_esc(json.dumps(data['by_status'], sort_keys=True))}</td></tr>"
        for platform, data in security_status["app_proof_installations"].items()
    )
    body = f"""
    <h2>Security Status</h2>
    <article>
      <p><strong>Hardening mode:</strong> {_esc(security_status["hardening_mode"])}</p>
      <p><strong>App proof mode:</strong> {_esc(security_status["app_proof_mode"])}</p>
      <p><strong>Admin bearer login app proof deferred:</strong> {_esc(security_status["admin_bearer_login_app_proof_deferred"])}</p>
      <p><strong>Admin MFA required:</strong> {_esc(security_status["admin_mfa_required"])}</p>
      <p><strong>Admin UI enabled:</strong> {_esc(security_status["admin_ui_enabled"])}</p>
    </article>
    <article>
      <h3>Warnings</h3>
      <ul>{warning_rows or '<li>none</li>'}</ul>
      <h3>Deferrals</h3>
      <ul>{deferral_rows}</ul>
    </article>
    <article><table>
      <thead><tr><th>Platform</th><th>Total</th><th>Status Counts</th></tr></thead>
      <tbody>{installation_rows or _empty_row(request, 3)}</tbody>
    </table></article>
    <article><table>
      <thead><tr><th>Recent App-Proof Failure</th><th>Count</th><th>Last Seen</th></tr></thead>
      <tbody>{failure_rows or _empty_row(request, 3)}</tbody>
    </table></article>
    <h2>{t("heading_runtime_counters")}</h2>
    <article><table>
      <thead><tr><th>{t("col_counter")}</th><th>{t("col_value")}</th></tr></thead>
      <tbody>{rows or _empty_row(request, 2)}</tbody>
    </table></article>
    """
    message, error = _msg(request)
    return _layout(request, t("title_metrics"), body, admin["username"], message=message, error=error)


@router.get("/pilot-metrics", response_class=HTMLResponse)
def pilot_metrics_page(request: Request):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    return _redirect(
        "/admin/ui/users",
        error="Pilot metrics are unavailable because invite onboarding was removed.",
        request=request,
    )
