from __future__ import annotations

import hashlib
import html
import ipaddress
import secrets
from datetime import UTC, datetime, timedelta
from urllib.parse import quote_plus, urlencode, urlparse

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .config import get_settings
from .diagnostics import device_diagnostic_hints
from .network import build_network_diagnostics_snapshot
from .db import (
    assign_device_to_user,
    count_admin_users,
    create_host,
    create_invite_token,
    create_user,
    delete_host,
    delete_user,
    get_host_by_id,
    get_user_by_id,
    get_user_by_username,
    list_admin_audit_logs,
    list_assignments,
    list_hosts,
    list_invite_tokens,
    list_power_check_logs,
    list_successful_wakes,
    list_users,
    list_wake_logs,
    log_admin_action,
    log_power_check,
    remove_assignment,
    revoke_invite,
    update_host,
    update_host_power_state,
    update_user_password_by_id,
    update_user_role,
)
from .power import run_power_check
from .rate_limit import get_rate_limiter
from .security import create_token, decode_token, hash_password, verify_password
from .telemetry import get_counters
from .wol import normalize_mac

router = APIRouter(prefix="/admin/ui", tags=["admin-ui"])

_SUPPORTED_LANGS = {"en", "de"}

_I18N = {
    "en": {
        "nav_dashboard": "Dashboard",
        "nav_users": "Users",
        "nav_devices": "Devices",
        "nav_assignments": "Assignments",
        "nav_invites": "Invites",
        "nav_diagnostics": "Diagnostics",
        "nav_wake_logs": "Wake Logs",
        "nav_power_logs": "Power Logs",
        "nav_audit_logs": "Audit Logs",
        "nav_metrics": "Metrics",
        "nav_pilot_metrics": "Pilot Metrics",
        "nav_logout": "Logout",
        "signed_in_as": "Signed in as",
        "language": "Language",
        "lang_en": "English",
        "lang_de": "Deutsch",
        "title_admin_login": "Admin Login",
        "label_username": "Username",
        "label_password": "Password",
        "action_login": "Login",
        "error_invalid_admin_credentials": "Invalid admin credentials",
        "error_too_many_login_attempts": "Too many login attempts. Please try again in a minute.",
        "title_admin_dashboard": "Admin Dashboard",
        "title_users": "Users",
        "title_devices": "Devices",
        "title_assignments": "Assignments",
        "title_invites": "Invites",
        "title_wake_logs": "Wake Logs",
        "title_power_check_logs": "Power Check Logs",
        "title_diagnostics": "Diagnostics",
        "title_audit_logs": "Audit Logs",
        "title_metrics": "Metrics",
        "title_pilot_metrics": "Pilot Metrics",
        "card_users": "Users",
        "card_devices": "Devices",
        "card_assignments": "Assignments",
        "card_invites": "Invites",
        "heading_recent_wake_logs": "Recent Wake Logs",
        "heading_recent_power_checks": "Recent Power Checks",
        "heading_create_user": "Create User",
        "heading_users": "Users",
        "heading_create_device": "Create Device",
        "heading_devices": "Devices",
        "heading_create_assignment": "Create Assignment",
        "heading_assignments": "Assignments",
        "heading_new_invite": "New Invite",
        "heading_create_invite": "Create Invite",
        "heading_invites": "Invites",
        "heading_wake_logs": "Wake Logs",
        "heading_power_check_logs": "Power Check Logs",
        "heading_network_interfaces": "Network Interfaces",
        "heading_device_diagnostics_hints": "Device Diagnostics Hints",
        "heading_admin_audit_logs": "Admin Audit Logs",
        "heading_runtime_counters": "Runtime Counters",
        "heading_pilot_metrics": "Pilot Metrics",
        "col_id": "ID",
        "col_user_id": "User ID",
        "col_username": "Username",
        "col_role": "Role",
        "col_created": "Created",
        "col_created_by": "Created By",
        "col_update": "Update",
        "col_delete": "Delete",
        "col_name": "Name",
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
        "col_first_successful_wake": "First Successful Wake",
        "col_seconds": "Seconds",
        "col_within_2m": "Within 2m",
        "placeholder_new_password_optional": "new password (optional)",
        "placeholder_username": "username",
        "placeholder_password_min12": "password (>=12)",
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
        "placeholder_actor_filter": "actor filter",
        "placeholder_device_id_filter": "device id filter",
        "option_all_results": "all results",
        "option_all_methods": "all methods",
        "action_save": "Save",
        "action_delete": "Delete",
        "action_create": "Create",
        "action_test_power_check": "Test Power Check",
        "action_assign": "Assign",
        "action_remove": "Remove",
        "action_create_invite": "Create Invite",
        "action_revoke": "Revoke",
        "action_filter": "Filter",
        "label_token": "Token",
        "label_link": "Link",
        "alt_invite_qr_code": "Invite QR Code",
        "error_invalid_role": "Invalid role",
        "error_password_min_length": "Password must be at least 12 characters",
        "error_username_exists": "Username already exists",
        "error_user_not_found": "User not found",
        "error_cannot_demote_last_admin": "Cannot demote last admin",
        "error_cannot_delete_last_admin": "Cannot delete last admin",
        "error_invalid_check_method": "Invalid check_method",
        "error_check_port_integer": "check_port must be integer",
        "error_device_not_found": "Device not found",
        "error_assignment_not_found": "Assignment not found",
        "error_username_not_found": "Username not found",
        "error_expires_in_hours_range": "expires_in_hours out of range",
        "error_invite_not_found_or_claimed": "Invite not found or already claimed",
        "msg_user_created": "User '{username}' created",
        "msg_user_updated": "Updated user '{username}'",
        "msg_user_deleted": "Deleted user '{username}'",
        "msg_device_created": "Created device {device_id}",
        "msg_device_updated": "Updated device {device_id}",
        "msg_device_deleted": "Deleted device {device_id}",
        "msg_power_check_result": "Power check {result} ({detail})",
        "msg_assignment_saved": "Assignment saved",
        "msg_assignment_removed": "Assignment removed",
        "msg_invite_created_for": "Invite created for {username}",
        "msg_invite_revoked": "Invite revoked",
        "text_total_claimed_users": "Total claimed users",
        "text_detected_networks": "Detected IPv4 networks",
        "text_multiple_networks_available": "Multiple active networks available",
        "text_users_first_success_2m": "Users with first successful wake within 2 min",
        "text_completion_rate_2m": "Completion rate within 2 min",
        "text_target_90": "target: 90%",
        "value_yes": "yes",
        "value_no": "no",
    },
    "de": {
        "nav_dashboard": "Dashboard",
        "nav_users": "Benutzer",
        "nav_devices": "Gerate",
        "nav_assignments": "Zuweisungen",
        "nav_invites": "Einladungen",
        "nav_diagnostics": "Diagnose",
        "nav_wake_logs": "Wake-Logs",
        "nav_power_logs": "Power-Logs",
        "nav_audit_logs": "Audit-Logs",
        "nav_metrics": "Metriken",
        "nav_pilot_metrics": "Pilot-Metriken",
        "nav_logout": "Abmelden",
        "signed_in_as": "Angemeldet als",
        "language": "Sprache",
        "lang_en": "English",
        "lang_de": "Deutsch",
        "title_admin_login": "Admin-Login",
        "label_username": "Benutzername",
        "label_password": "Passwort",
        "action_login": "Anmelden",
        "error_invalid_admin_credentials": "Ungultige Admin-Zugangsdaten",
        "error_too_many_login_attempts": "Zu viele Login-Versuche. Bitte in einer Minute erneut versuchen.",
        "title_admin_dashboard": "Admin-Dashboard",
        "title_users": "Benutzer",
        "title_devices": "Gerate",
        "title_assignments": "Zuweisungen",
        "title_invites": "Einladungen",
        "title_wake_logs": "Wake-Logs",
        "title_power_check_logs": "Power-Check-Logs",
        "title_diagnostics": "Diagnose",
        "title_audit_logs": "Audit-Logs",
        "title_metrics": "Metriken",
        "title_pilot_metrics": "Pilot-Metriken",
        "card_users": "Benutzer",
        "card_devices": "Gerate",
        "card_assignments": "Zuweisungen",
        "card_invites": "Einladungen",
        "heading_recent_wake_logs": "Letzte Wake-Logs",
        "heading_recent_power_checks": "Letzte Power-Checks",
        "heading_create_user": "Benutzer erstellen",
        "heading_users": "Benutzer",
        "heading_create_device": "Gerat erstellen",
        "heading_devices": "Gerate",
        "heading_create_assignment": "Zuweisung erstellen",
        "heading_assignments": "Zuweisungen",
        "heading_new_invite": "Neue Einladung",
        "heading_create_invite": "Einladung erstellen",
        "heading_invites": "Einladungen",
        "heading_wake_logs": "Wake-Logs",
        "heading_power_check_logs": "Power-Check-Logs",
        "heading_network_interfaces": "Netzwerk-Interfaces",
        "heading_device_diagnostics_hints": "Diagnosehinweise fur Gerate",
        "heading_admin_audit_logs": "Admin-Audit-Logs",
        "heading_runtime_counters": "Runtime-Zahler",
        "heading_pilot_metrics": "Pilot-Metriken",
        "col_id": "ID",
        "col_user_id": "Benutzer-ID",
        "col_username": "Benutzername",
        "col_role": "Rolle",
        "col_created": "Erstellt",
        "col_created_by": "Erstellt von",
        "col_update": "Aktualisieren",
        "col_delete": "Loschen",
        "col_name": "Name",
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
        "col_checked_at": "Gepruft am",
        "col_diagnostics": "Diagnose",
        "col_actions": "Aktionen",
        "col_device_id": "Gerate-ID",
        "col_device": "Gerat",
        "col_action": "Aktion",
        "col_backend_hint": "Backend-Hinweis",
        "col_expires_at": "Lauft ab",
        "col_claimed_at": "Eingelost am",
        "col_host_id": "Host-ID",
        "col_actor": "Ausloser",
        "col_result": "Ergebnis",
        "col_time": "Zeit",
        "col_precheck": "Precheck",
        "col_error": "Fehler",
        "col_detail": "Detail",
        "col_latency_ms": "Latenz ms",
        "col_hints": "Hinweise",
        "col_target_type": "Zieltyp",
        "col_target_id": "Ziel-ID",
        "col_counter": "Zahler",
        "col_value": "Wert",
        "col_first_successful_wake": "Erster erfolgreicher Wake",
        "col_seconds": "Sekunden",
        "col_within_2m": "Innerhalb 2m",
        "placeholder_new_password_optional": "neues Passwort (optional)",
        "placeholder_username": "benutzername",
        "placeholder_password_min12": "passwort (>=12)",
        "placeholder_display_name": "anzeige name",
        "placeholder_check_target": "check ziel",
        "placeholder_check_port": "check port",
        "placeholder_group": "gruppe",
        "placeholder_broadcast_ip": "broadcast ip",
        "placeholder_subnet_cidr": "subnet cidr",
        "placeholder_udp_port": "udp port",
        "placeholder_interface": "interface",
        "placeholder_name": "name",
        "placeholder_backend_url_hint_optional": "backend url hinweis (optional)",
        "placeholder_hours": "stunden",
        "placeholder_host_id_filter": "host-id filter",
        "placeholder_actor_filter": "ausloser filter",
        "placeholder_device_id_filter": "gerate-id filter",
        "option_all_results": "alle ergebnisse",
        "option_all_methods": "alle methoden",
        "action_save": "Speichern",
        "action_delete": "Loschen",
        "action_create": "Erstellen",
        "action_test_power_check": "Power-Check testen",
        "action_assign": "Zuweisen",
        "action_remove": "Entfernen",
        "action_create_invite": "Einladung erstellen",
        "action_revoke": "Widerrufen",
        "action_filter": "Filtern",
        "label_token": "Token",
        "label_link": "Link",
        "alt_invite_qr_code": "Einladungs-QR-Code",
        "error_invalid_role": "Ungultige Rolle",
        "error_password_min_length": "Passwort muss mindestens 12 Zeichen haben",
        "error_username_exists": "Benutzername existiert bereits",
        "error_user_not_found": "Benutzer nicht gefunden",
        "error_cannot_demote_last_admin": "Letzter Admin kann nicht herabgestuft werden",
        "error_cannot_delete_last_admin": "Letzter Admin kann nicht geloscht werden",
        "error_invalid_check_method": "Ungultige check_method",
        "error_check_port_integer": "check_port muss eine Zahl sein",
        "error_device_not_found": "Gerat nicht gefunden",
        "error_assignment_not_found": "Zuweisung nicht gefunden",
        "error_username_not_found": "Benutzername nicht gefunden",
        "error_expires_in_hours_range": "expires_in_hours auerhalb des Bereichs",
        "error_invite_not_found_or_claimed": "Einladung nicht gefunden oder bereits eingelost",
        "msg_user_created": "Benutzer '{username}' erstellt",
        "msg_user_updated": "Benutzer '{username}' aktualisiert",
        "msg_user_deleted": "Benutzer '{username}' geloscht",
        "msg_device_created": "Gerat {device_id} erstellt",
        "msg_device_updated": "Gerat {device_id} aktualisiert",
        "msg_device_deleted": "Gerat {device_id} geloscht",
        "msg_power_check_result": "Power-Check {result} ({detail})",
        "msg_assignment_saved": "Zuweisung gespeichert",
        "msg_assignment_removed": "Zuweisung entfernt",
        "msg_invite_created_for": "Einladung fur {username} erstellt",
        "msg_invite_revoked": "Einladung widerrufen",
        "text_total_claimed_users": "Insgesamt eingeloste Benutzer",
        "text_detected_networks": "Erkannte IPv4-Netze",
        "text_multiple_networks_available": "Mehrere aktive Netzwerke verfugbar",
        "text_users_first_success_2m": "Benutzer mit erstem erfolgreichen Wake in 2 Min",
        "text_completion_rate_2m": "Abschlussrate innerhalb 2 Min",
        "text_target_90": "Ziel: 90%",
        "value_yes": "ja",
        "value_no": "nein",
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
        response.set_cookie(
            "admin_ui_lang",
            resolved,
            max_age=60 * 60 * 24 * 365,
            samesite="lax",
            secure=request.url.scheme == "https",
            path="/admin/ui",
        )


def _esc(value: object | None) -> str:
    if value is None:
        return ""
    return html.escape(str(value))


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


def _parse_ip(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not value:
        return None
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
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


def _login_ip_key(request: Request) -> str:
    settings = get_settings()
    peer_ip = request.client.host if request.client else None
    if settings.trust_proxy_headers and peer_ip and _is_in_networks(peer_ip, settings.trusted_proxy_cidrs_list):
        forwarded = _extract_forwarded_ip(request)
        if forwarded:
            return forwarded
    if peer_ip and _parse_ip(peer_ip):
        return peer_ip
    return "unknown"


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
    token = request.cookies.get("admin_session")
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
    return user


def _require_admin_or_redirect(request: Request):
    user = _admin_from_cookie(request)
    if user:
        return user
    next_path = request.url.path
    if request.url.query:
        next_path = f"{next_path}?{request.url.query}"
    return RedirectResponse(f"/admin/ui/login?{urlencode({'next': next_path, 'lang': _lang(request)})}", status_code=303)


def _layout(request: Request, title: str, body: str, admin_username: str, message: str | None = None, error: str | None = None) -> HTMLResponse:
    lang = _lang(request)
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    notice = ""
    if message:
        notice = f'<div style="padding:10px;border:1px solid #5aa469;background:#edf9ef;margin-bottom:12px;">{_esc(message)}</div>'
    if error:
        notice = f'{notice}<div style="padding:10px;border:1px solid #b74a4a;background:#fdeeee;margin-bottom:12px;">{_esc(error)}</div>'
    nav = f"""
    <nav style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px;">
      <a href="{_with_lang('/admin/ui', lang)}">{t("nav_dashboard")}</a>
      <a href="{_with_lang('/admin/ui/users', lang)}">{t("nav_users")}</a>
      <a href="{_with_lang('/admin/ui/devices', lang)}">{t("nav_devices")}</a>
      <a href="{_with_lang('/admin/ui/assignments', lang)}">{t("nav_assignments")}</a>
      <a href="{_with_lang('/admin/ui/invites', lang)}">{t("nav_invites")}</a>
      <a href="{_with_lang('/admin/ui/diagnostics', lang)}">{t("nav_diagnostics")}</a>
      <a href="{_with_lang('/admin/ui/wake-logs', lang)}">{t("nav_wake_logs")}</a>
      <a href="{_with_lang('/admin/ui/power-check-logs', lang)}">{t("nav_power_logs")}</a>
      <a href="{_with_lang('/admin/ui/audit-logs', lang)}">{t("nav_audit_logs")}</a>
      <a href="{_with_lang('/admin/ui/metrics', lang)}">{t("nav_metrics")}</a>
      <a href="{_with_lang('/admin/ui/pilot-metrics', lang)}">{t("nav_pilot_metrics")}</a>
      <a href="{_with_lang('/admin/ui/logout', lang)}">{t("nav_logout")}</a>
    </nav>
    """
    page = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{_esc(title)}</title></head>
<body style="font-family:ui-sans-serif,system-ui,sans-serif;max-width:1200px;margin:20px auto;padding:0 16px;">
  <header style="display:flex;justify-content:space-between;align-items:center;">
    <h1 style="margin:0 0 12px 0;">{_esc(title)}</h1>
    <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;">
      <div>{t("signed_in_as")} <strong>{_esc(admin_username)}</strong></div>
      <div>{t("language")}: <a href="{_esc(_lang_switch_url(request, 'en'))}">{t("lang_en")}</a> | <a href="{_esc(_lang_switch_url(request, 'de'))}">{t("lang_de")}</a></div>
    </div>
  </header>
  {nav}
  {notice}
  {body}
</body></html>"""
    response = HTMLResponse(page)
    _apply_lang_cookie(request, response, lang)
    return response


def _redirect(path: str, message: str | None = None, error: str | None = None, request: Request | None = None) -> RedirectResponse:
    params: dict[str, str] = {}
    if message:
        params["message"] = message
    if error:
        params["error"] = error
    if request is not None:
        params["lang"] = _lang(request)
    location = path if not params else f"{path}?{urlencode(params)}"
    response = RedirectResponse(location, status_code=303)
    if request is not None:
        _apply_lang_cookie(request, response)
    return response


def _msg(request: Request) -> tuple[str | None, str | None]:
    return request.query_params.get("message"), request.query_params.get("error")


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/admin/ui", error: str | None = None):
    user = _admin_from_cookie(request)
    lang = _lang(request)
    safe_next = _safe_next_path(next)
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    if user:
        return RedirectResponse(safe_next, status_code=303)
    page = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{t("title_admin_login")}</title></head>
<body style="font-family:ui-sans-serif,system-ui,sans-serif;max-width:480px;margin:40px auto;padding:0 16px;">
  <h1>{t("title_admin_login")}</h1>
  <div style="margin-bottom:12px;">{t("language")}: <a href="{_esc(_lang_switch_url(request, 'en'))}">{t("lang_en")}</a> | <a href="{_esc(_lang_switch_url(request, 'de'))}">{t("lang_de")}</a></div>
  {"<div style='padding:10px;border:1px solid #b74a4a;background:#fdeeee;margin-bottom:12px;'>" + _esc(error) + "</div>" if error else ""}
  <form method="post" action="/admin/ui/login" style="display:grid;gap:10px;">
    <input type="hidden" name="next" value="{_esc(safe_next)}" />
    <input type="hidden" name="lang" value="{_esc(lang)}" />
    <label>{t("label_username")} <input required name="username" /></label>
    <label>{t("label_password")} <input required type="password" name="password" /></label>
    <button type="submit">{t("action_login")}</button>
  </form>
</body></html>"""
    response = HTMLResponse(page)
    _apply_lang_cookie(request, response, lang)
    return response


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form("/admin/ui"),
    lang: str = Form(""),
):
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
    token, _ = create_token(username=user["username"], role=user["role"])
    response = RedirectResponse(safe_next, status_code=303)
    response.set_cookie(
        "admin_session",
        token,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/admin/ui",
    )
    _apply_lang_cookie(request, response, resolved_lang)
    return response


@router.get("/logout")
def logout(request: Request):
    response = RedirectResponse(_with_lang("/admin/ui/login", _lang(request)), status_code=303)
    response.delete_cookie("admin_session", path="/admin/ui")
    _apply_lang_cookie(request, response)
    return response


@router.get("", response_class=HTMLResponse)
def dashboard(request: Request):
    user = _require_admin_or_redirect(request)
    if isinstance(user, RedirectResponse):
        return user
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    users = list_users()
    devices = list_hosts()
    assignments = list_assignments()
    wake_logs = list_wake_logs(limit=10)
    power_logs = list_power_check_logs(limit=10)
    message, error = _msg(request)
    body = f"""
    <section style="display:grid;grid-template-columns:repeat(4,minmax(120px,1fr));gap:12px;margin-bottom:16px;">
      <div style="padding:12px;border:1px solid #ddd;"><div>{t("card_users")}</div><strong>{len(users)}</strong></div>
      <div style="padding:12px;border:1px solid #ddd;"><div>{t("card_devices")}</div><strong>{len(devices)}</strong></div>
      <div style="padding:12px;border:1px solid #ddd;"><div>{t("card_assignments")}</div><strong>{len(assignments)}</strong></div>
      <div style="padding:12px;border:1px solid #ddd;"><div>{t("card_invites")}</div><strong>{len(list_invite_tokens(limit=500))}</strong></div>
    </section>
    <h2>{t("heading_recent_wake_logs")}</h2>
    <table border="1" cellpadding="6" cellspacing="0"><tr><th>{t("col_id")}</th><th>{t("col_device")}</th><th>{t("col_actor")}</th><th>{t("col_result")}</th><th>{t("col_time")}</th></tr>
      {"".join(f"<tr><td>{row['id']}</td><td>{_esc(row['host_id'])}</td><td>{_esc(row['actor_username'])}</td><td>{_esc(row['result'])}</td><td>{_esc(row['created_at'])}</td></tr>" for row in wake_logs)}
    </table>
    <h2>{t("heading_recent_power_checks")}</h2>
    <table border="1" cellpadding="6" cellspacing="0"><tr><th>{t("col_id")}</th><th>{t("col_device")}</th><th>{t("col_method")}</th><th>{t("col_result")}</th><th>{t("col_time")}</th></tr>
      {"".join(f"<tr><td>{row['id']}</td><td>{_esc(row['device_id'])}</td><td>{_esc(row['method'])}</td><td>{_esc(row['result'])}</td><td>{_esc(row['created_at'])}</td></tr>" for row in power_logs)}
    </table>
    """
    return _layout(request, t("title_admin_dashboard"), body, user["username"], message=message, error=error)


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request):
    user = _require_admin_or_redirect(request)
    if isinstance(user, RedirectResponse):
        return user
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    rows = list_users()
    message, error = _msg(request)
    table_rows = "".join(
        f"""
        <tr>
          <td>{row['id']}</td><td>{_esc(row['username'])}</td><td>{_esc(row['role'])}</td><td>{_esc(row['created_at'])}</td>
          <td>
            <form method="post" action="/admin/ui/users/{row['id']}/update" style="display:flex;gap:6px;flex-wrap:wrap;">
              <select name="role">
                <option value="user" {"selected" if row['role']=="user" else ""}>user</option>
                <option value="admin" {"selected" if row['role']=="admin" else ""}>admin</option>
              </select>
              <input name="password" type="password" placeholder="{t("placeholder_new_password_optional")}" />
              <button type="submit">{t("action_save")}</button>
            </form>
          </td>
          <td>
            <form method="post" action="/admin/ui/users/{row['id']}/delete">
              <button type="submit">{t("action_delete")}</button>
            </form>
          </td>
        </tr>
        """
        for row in rows
    )
    body = f"""
    <h2>{t("heading_create_user")}</h2>
    <form method="post" action="/admin/ui/users/create" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;">
      <input required name="username" placeholder="{t("placeholder_username")}" />
      <input required name="password" type="password" placeholder="{t("placeholder_password_min12")}" />
      <select name="role"><option value="user">user</option><option value="admin">admin</option></select>
      <button type="submit">{t("action_create")}</button>
    </form>
    <h2>{t("heading_users")}</h2>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr><th>{t("col_id")}</th><th>{t("col_username")}</th><th>{t("col_role")}</th><th>{t("col_created")}</th><th>{t("col_update")}</th><th>{t("col_delete")}</th></tr>
      {table_rows}
    </table>
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
    if len(password) < 12:
        return _redirect("/admin/ui/users", error=t("error_password_min_length"), request=request)
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
    update_user_role(user_id, role)
    if password:
        if len(password) < 12:
            return _redirect("/admin/ui/users", error=t("error_password_min_length"), request=request)
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
    rows = list_hosts()
    message, error = _msg(request)
    table_rows = "".join(
        f"""
        <tr>
          <td>{_esc(row['id'])}</td><td>{_esc(row['name'])}</td><td>{_esc(row['display_name'])}</td><td>{_esc(row['mac'])}</td>
          <td>{_esc(row['check_method'])}</td><td>{_esc(row['check_target'])}</td><td>{_esc(row['check_port'])}</td>
          <td>{_esc(row['last_power_state'])}</td><td>{_esc(row['last_power_checked_at'])}</td>
          <td>{"<br/>".join(_esc(hint) for hint in device_diagnostic_hints(dict(row)))}</td>
          <td>
            <form method="post" action="/admin/ui/devices/{_esc(row['id'])}/update" style="display:grid;gap:4px;">
              <input name="name" value="{_esc(row['name'])}" />
              <input name="display_name" value="{_esc(row['display_name'])}" placeholder="{t("placeholder_display_name")}" />
              <input name="mac" value="{_esc(row['mac'])}" />
              <input name="interface" value="{_esc(row['interface'])}" placeholder="{t("placeholder_interface")}" />
              <input name="source_ip" value="{_esc(row['source_ip'])}" placeholder="source ip (optional)" />
              <input name="check_target" value="{_esc(row['check_target'])}" placeholder="{t("placeholder_check_target")}" />
              <input name="check_port" value="{_esc(row['check_port'])}" placeholder="{t("placeholder_check_port")}" />
              <select name="check_method">
                <option value="tcp" {"selected" if row['check_method']=="tcp" else ""}>tcp</option>
                <option value="icmp" {"selected" if row['check_method']=="icmp" else ""}>icmp</option>
              </select>
              <button type="submit">{t("action_save")}</button>
            </form>
          </td>
          <td>
            <form method="post" action="/admin/ui/devices/{_esc(row['id'])}/test-power-check"><button type="submit">{t("action_test_power_check")}</button></form>
            <form method="post" action="/admin/ui/devices/{_esc(row['id'])}/delete"><button type="submit">{t("action_delete")}</button></form>
          </td>
        </tr>
        """
        for row in rows
    )
    body = f"""
    <h2>{t("heading_create_device")}</h2>
    <form method="post" action="/admin/ui/devices/create" style="display:grid;grid-template-columns:repeat(4,minmax(160px,1fr));gap:8px;margin-bottom:16px;">
      <input required name="name" placeholder="{t("placeholder_name")}" />
      <input name="display_name" placeholder="{t("placeholder_display_name")}" />
      <input required name="mac" placeholder="AA:BB:CC:DD:EE:FF" />
      <input name="group_name" placeholder="{t("placeholder_group")}" />
      <input name="broadcast" placeholder="{t("placeholder_broadcast_ip")}" />
      <input name="subnet_cidr" placeholder="{t("placeholder_subnet_cidr")}" />
      <input name="udp_port" value="9" placeholder="{t("placeholder_udp_port")}" />
      <input name="interface" placeholder="{t("placeholder_interface")}" />
      <input name="source_ip" placeholder="source ip (optional)" />
      <select name="check_method"><option value="tcp">tcp</option><option value="icmp">icmp</option></select>
      <input name="check_target" placeholder="{t("placeholder_check_target")}" />
      <input name="check_port" placeholder="{t("placeholder_check_port")}" />
      <button type="submit">{t("action_create")}</button>
    </form>
    <h2>{t("heading_devices")}</h2>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr><th>{t("col_id")}</th><th>{t("col_name")}</th><th>{t("col_display")}</th><th>{t("col_mac")}</th><th>{t("col_method")}</th><th>{t("col_target")}</th><th>{t("col_port")}</th><th>{t("col_state")}</th><th>{t("col_checked_at")}</th><th>{t("col_diagnostics")}</th><th>{t("col_update")}</th><th>{t("col_actions")}</th></tr>
      {table_rows}
    </table>
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


@router.get("/assignments", response_class=HTMLResponse)
def assignments_page(request: Request):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    users = list_users()
    devices = list_hosts()
    assignments = list_assignments()
    message, error = _msg(request)
    user_opts = "".join(f'<option value="{row["id"]}">{_esc(row["username"])} ({row["id"]})</option>' for row in users)
    device_opts = "".join(f'<option value="{_esc(row["id"])}">{_esc(row["name"])} ({_esc(row["id"])})</option>' for row in devices)
    rows = "".join(
        f"""
        <tr>
          <td>{row['user_id']}</td><td>{_esc(row['username'])}</td><td>{_esc(row['device_id'])}</td><td>{_esc(row['device_name'])}</td><td>{_esc(row['created_at'])}</td>
          <td><form method="post" action="/admin/ui/assignments/{row['user_id']}/{_esc(row['device_id'])}/delete"><button type="submit">{t("action_remove")}</button></form></td>
        </tr>
        """
        for row in assignments
    )
    body = f"""
    <h2>{t("heading_create_assignment")}</h2>
    <form method="post" action="/admin/ui/assignments/create" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;">
      <select name="user_id">{user_opts}</select>
      <select name="device_id">{device_opts}</select>
      <button type="submit">{t("action_assign")}</button>
    </form>
    <h2>{t("heading_assignments")}</h2>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr><th>{t("col_user_id")}</th><th>{t("col_username")}</th><th>{t("col_device_id")}</th><th>{t("col_device")}</th><th>{t("col_created")}</th><th>{t("col_action")}</th></tr>
      {rows}
    </table>
    """
    return _layout(request, t("title_assignments"), body, admin["username"], message=message, error=error)


@router.post("/assignments/create")
def assignments_create(request: Request, user_id: int = Form(...), device_id: str = Form(...)):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    if not get_user_by_id(user_id):
        return _redirect("/admin/ui/assignments", error=t("error_user_not_found"), request=request)
    if not get_host_by_id(device_id):
        return _redirect("/admin/ui/assignments", error=t("error_device_not_found"), request=request)
    assign_device_to_user(user_id, device_id)
    log_admin_action(
        actor_username=admin["username"],
        action="ui_create_assignment",
        target_type="assignment",
        target_id=f"{user_id}:{device_id}",
        detail=None,
    )
    return _redirect("/admin/ui/assignments", message=t("msg_assignment_saved"), request=request)


@router.post("/assignments/{user_id}/{device_id}/delete")
def assignments_delete(request: Request, user_id: int, device_id: str):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    if not remove_assignment(user_id, device_id):
        return _redirect("/admin/ui/assignments", error=t("error_assignment_not_found"), request=request)
    log_admin_action(
        actor_username=admin["username"],
        action="ui_delete_assignment",
        target_type="assignment",
        target_id=f"{user_id}:{device_id}",
        detail=None,
    )
    return _redirect("/admin/ui/assignments", message=t("msg_assignment_removed"), request=request)


def _render_invites_page(
    request: Request,
    admin_username: str,
    message: str | None,
    error: str | None,
    created_token: str | None = None,
    created_link: str | None = None,
):
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    invites = list_invite_tokens(limit=300)
    rows = "".join(
        f"""
        <tr>
          <td>{_esc(row['id'])}</td><td>{_esc(row['username'])}</td><td>{_esc(row['backend_url_hint'])}</td>
          <td>{_esc(row['expires_at'])}</td><td>{_esc(row['claimed_at'])}</td><td>{_esc(row['created_by'])}</td>
          <td><form method="post" action="/admin/ui/invites/{_esc(row['id'])}/revoke"><button type="submit">{t("action_revoke")}</button></form></td>
        </tr>
        """
        for row in invites
    )
    created_section = ""
    if created_token and created_link:
        qr_url = f"https://quickchart.io/qr?size=240&text={quote_plus(created_link)}"
        created_section = f"""
        <section style="padding:12px;border:1px solid #ddd;margin-bottom:16px;">
          <h3>{t("heading_new_invite")}</h3>
          <div><strong>{t("label_token")}:</strong> <code>{_esc(created_token)}</code></div>
          <div><strong>{t("label_link")}:</strong> <code>{_esc(created_link)}</code></div>
          <div style="margin-top:8px;"><img src="{_esc(qr_url)}" alt="{t("alt_invite_qr_code")}" /></div>
        </section>
        """
    users = list_users()
    user_opts = "".join(f'<option value="{_esc(row["username"])}">{_esc(row["username"])}</option>' for row in users)
    body = f"""
    {created_section}
    <h2>{t("heading_create_invite")}</h2>
    <form method="post" action="/admin/ui/invites/create" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;">
      <select name="username">{user_opts}</select>
      <input name="backend_url_hint" placeholder="{t("placeholder_backend_url_hint_optional")}" />
      <input name="expires_in_hours" value="72" placeholder="{t("placeholder_hours")}" />
      <button type="submit">{t("action_create_invite")}</button>
    </form>
    <h2>{t("heading_invites")}</h2>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr><th>{t("col_id")}</th><th>{t("col_username")}</th><th>{t("col_backend_hint")}</th><th>{t("col_expires_at")}</th><th>{t("col_claimed_at")}</th><th>{t("col_created_by")}</th><th>{t("col_action")}</th></tr>
      {rows}
    </table>
    """
    return _layout(request, t("title_invites"), body, admin_username, message=message, error=error)


@router.get("/invites", response_class=HTMLResponse)
def invites_page(request: Request):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    message, error = _msg(request)
    return _render_invites_page(request, admin["username"], message, error)


@router.post("/invites/create", response_class=HTMLResponse)
def invites_create(
    request: Request,
    username: str = Form(...),
    backend_url_hint: str = Form(""),
    expires_in_hours: int = Form(72),
):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    user = get_user_by_username(username)
    if not user:
        return _render_invites_page(request, admin["username"], None, t("error_username_not_found"))
    if expires_in_hours < 1 or expires_in_hours > 24 * 30:
        return _render_invites_page(request, admin["username"], None, t("error_expires_in_hours_range"))
    raw_token = secrets.token_urlsafe(24)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    invite_id = secrets.token_hex(16)
    expires_at = datetime.now(UTC) + timedelta(hours=expires_in_hours)
    create_invite_token(
        invite_id=invite_id,
        token_hash=token_hash,
        username=username,
        backend_url_hint=backend_url_hint or None,
        expires_at=expires_at.isoformat(),
        created_by=admin["username"],
    )
    log_admin_action(
        actor_username=admin["username"],
        action="ui_create_invite",
        target_type="invite",
        target_id=invite_id,
        detail=f"username={username}",
    )
    hint = backend_url_hint.strip() or f"{request.url.scheme}://{request.url.netloc}"
    link = f"wakefromfar://claim?token={quote_plus(raw_token)}&backend_url_hint={quote_plus(hint)}"
    return _render_invites_page(
        request,
        admin["username"],
        message=t("msg_invite_created_for", username=username),
        error=None,
        created_token=raw_token,
        created_link=link,
    )


@router.post("/invites/{invite_id}/revoke")
def invites_revoke(request: Request, invite_id: str):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    if not revoke_invite(invite_id):
        return _redirect("/admin/ui/invites", error=t("error_invite_not_found_or_claimed"), request=request)
    log_admin_action(
        actor_username=admin["username"],
        action="ui_revoke_invite",
        target_type="invite",
        target_id=invite_id,
        detail=None,
    )
    return _redirect("/admin/ui/invites", message=t("msg_invite_revoked"), request=request)


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
    message, error = _msg(request)
    body_rows = "".join(
        f"<tr><td>{row['id']}</td><td>{_esc(row['host_id'])}</td><td>{_esc(row['actor_username'])}</td><td>{_esc(row['result'])}</td><td>{_esc(row['precheck_state'])}</td><td>{_esc(row['error_detail'])}</td><td>{_esc(row['created_at'])}</td></tr>"
        for row in rows
    )
    body = f"""
    <h2>{t("heading_wake_logs")}</h2>
    <form method="get" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;">
      <input name="host_id" value="{_esc(host_id)}" placeholder="{t("placeholder_host_id_filter")}" />
      <input name="actor" value="{_esc(actor)}" placeholder="{t("placeholder_actor_filter")}" />
      <select name="result">
        <option value="" {"selected" if not result else ""}>{t("option_all_results")}</option>
        <option value="sent" {"selected" if result=="sent" else ""}>sent</option>
        <option value="already_on" {"selected" if result=="already_on" else ""}>already_on</option>
        <option value="failed" {"selected" if result=="failed" else ""}>failed</option>
      </select>
      <input name="limit" value="{limit}" />
      <button type="submit">{t("action_filter")}</button>
    </form>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr><th>{t("col_id")}</th><th>{t("col_host_id")}</th><th>{t("col_actor")}</th><th>{t("col_result")}</th><th>{t("col_precheck")}</th><th>{t("col_error")}</th><th>{t("col_created")}</th></tr>
      {body_rows}
    </table>
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
    message, error = _msg(request)
    body_rows = "".join(
        f"<tr><td>{row['id']}</td><td>{_esc(row['device_id'])}</td><td>{_esc(row['method'])}</td><td>{_esc(row['result'])}</td><td>{_esc(row['detail'])}</td><td>{_esc(row['latency_ms'])}</td><td>{_esc(row['created_at'])}</td></tr>"
        for row in rows
    )
    body = f"""
    <h2>{t("heading_power_check_logs")}</h2>
    <form method="get" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;">
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
      <input name="limit" value="{limit}" />
      <button type="submit">{t("action_filter")}</button>
    </form>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr><th>{t("col_id")}</th><th>{t("col_device_id")}</th><th>{t("col_method")}</th><th>{t("col_result")}</th><th>{t("col_detail")}</th><th>{t("col_latency_ms")}</th><th>{t("col_created")}</th></tr>
      {body_rows}
    </table>
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
            f"<tr><td>{_esc(host['id'])}</td><td>{_esc(host['name'])}</td><td>{'<br/>'.join(_esc(h) for h in device_diagnostic_hints(dict(host)))}</td></tr>"
        )
    networks = ", ".join(str(row) for row in network_diag["detected_ipv4_networks"]) or "-"
    body = f"""
    <h2>{t("heading_network_interfaces")}</h2>
    <p>{t("text_detected_networks")}: <strong>{_esc(networks)}</strong></p>
    <p>{t("text_multiple_networks_available")}: <strong>{t("value_yes") if network_diag["has_multiple_active_networks"] else t("value_no")}</strong></p>
    <table border="1" cellpadding="6" cellspacing="0" style="margin-bottom:16px;">
      <tr><th>{t("col_interface")}</th><th>{t("col_ipv4")}</th><th>{t("col_netmask")}</th><th>{t("col_network")}</th><th>{t("col_broadcast")}</th><th>{t("col_up")}</th><th>{t("col_loopback")}</th></tr>
      {''.join(network_rows)}
    </table>
    <h2>{t("heading_device_diagnostics_hints")}</h2>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr><th>{t("col_device_id")}</th><th>{t("col_name")}</th><th>{t("col_hints")}</th></tr>
      {''.join(rows)}
    </table>
    """
    message, error = _msg(request)
    return _layout(request, t("title_diagnostics"), body, admin["username"], message=message, error=error)


@router.get("/audit-logs", response_class=HTMLResponse)
def audit_logs_page(request: Request):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    rows = list_admin_audit_logs(limit=500)
    body_rows = "".join(
        f"<tr><td>{row['id']}</td><td>{_esc(row['actor_username'])}</td><td>{_esc(row['action'])}</td><td>{_esc(row['target_type'])}</td><td>{_esc(row['target_id'])}</td><td>{_esc(row['detail'])}</td><td>{_esc(row['created_at'])}</td></tr>"
        for row in rows
    )
    body = f"""
    <h2>{t("heading_admin_audit_logs")}</h2>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr><th>{t("col_id")}</th><th>{t("col_actor")}</th><th>{t("col_action")}</th><th>{t("col_target_type")}</th><th>{t("col_target_id")}</th><th>{t("col_detail")}</th><th>{t("col_created")}</th></tr>
      {body_rows}
    </table>
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
    rows = "".join(
        f"<tr><td>{_esc(name)}</td><td>{value}</td></tr>" for name, value in sorted(counters.items(), key=lambda kv: kv[0])
    )
    body = f"""
    <h2>{t("heading_runtime_counters")}</h2>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr><th>{t("col_counter")}</th><th>{t("col_value")}</th></tr>
      {rows}
    </table>
    """
    message, error = _msg(request)
    return _layout(request, t("title_metrics"), body, admin["username"], message=message, error=error)


@router.get("/pilot-metrics", response_class=HTMLResponse)
def pilot_metrics_page(request: Request):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    claimed_invites = [row for row in list_invite_tokens(limit=5000) if row["claimed_at"]]
    successful_wakes = list_successful_wakes(limit=20000)

    first_success_by_user: dict[str, str] = {}
    for row in successful_wakes:
        actor = str(row["actor_username"])
        if actor not in first_success_by_user:
            first_success_by_user[actor] = str(row["created_at"])

    total_claimed = len(claimed_invites)
    within_two_minutes = 0
    details_rows: list[str] = []
    for invite in claimed_invites:
        username = str(invite["username"])
        claimed_at = datetime.fromisoformat(str(invite["claimed_at"]))
        if claimed_at.tzinfo is None:
            claimed_at = claimed_at.replace(tzinfo=UTC)
        first_success_raw = first_success_by_user.get(username)
        duration = None
        within = False
        if first_success_raw:
            first_success = datetime.fromisoformat(first_success_raw)
            if first_success.tzinfo is None:
                first_success = first_success.replace(tzinfo=UTC)
            duration = (first_success - claimed_at).total_seconds()
            within = duration <= 120
            if within:
                within_two_minutes += 1
        details_rows.append(
            f"<tr><td>{_esc(username)}</td><td>{_esc(invite['claimed_at'])}</td><td>{_esc(first_success_raw)}</td><td>{_esc(duration)}</td><td>{t('value_yes') if within else t('value_no')}</td></tr>"
        )

    rate = (within_two_minutes / total_claimed) if total_claimed else 0.0
    body = f"""
    <h2>{t("heading_pilot_metrics")}</h2>
    <p>{t("text_total_claimed_users")}: <strong>{total_claimed}</strong></p>
    <p>{t("text_users_first_success_2m")}: <strong>{within_two_minutes}</strong></p>
    <p>{t("text_completion_rate_2m")}: <strong>{rate:.2%}</strong> ({t("text_target_90")})</p>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr><th>{t("col_username")}</th><th>{t("col_claimed_at")}</th><th>{t("col_first_successful_wake")}</th><th>{t("col_seconds")}</th><th>{t("col_within_2m")}</th></tr>
      {''.join(details_rows)}
    </table>
    """
    message, error = _msg(request)
    return _layout(request, t("title_pilot_metrics"), body, admin["username"], message=message, error=error)
