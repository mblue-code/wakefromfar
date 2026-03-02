from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote_plus, urlencode, urlparse

from fastapi import APIRouter, BackgroundTasks, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse

from .config import get_settings
from .discovery import collect_discovery_candidates, discover_sender_bindings, normalize_source_bindings, summarize_candidates
from .diagnostics import device_diagnostic_hints
from .network import build_network_diagnostics_snapshot
from .db import (
    assign_device_to_user,
    complete_discovery_run,
    count_admin_users,
    create_host,
    create_discovery_candidate,
    create_discovery_run,
    create_invite_token,
    create_user,
    delete_host,
    delete_user,
    fail_discovery_run,
    get_discovery_candidate,
    get_discovery_run,
    get_host_by_mac,
    get_host_by_id,
    get_user_by_id,
    get_user_by_username,
    list_discovery_candidates,
    list_discovery_events,
    list_discovery_runs,
    list_admin_audit_logs,
    list_assignments,
    list_hosts,
    list_invite_tokens,
    list_power_check_logs,
    list_successful_wakes,
    list_users,
    list_wake_logs,
    log_admin_action,
    log_discovery_event,
    log_power_check,
    mark_discovery_candidate_imported,
    mark_discovery_run_running,
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
from .wol import normalize_mac, resolve_target, send_magic_packet

router = APIRouter(prefix="/admin/ui", tags=["admin-ui"])
_STATIC_DIR = Path(__file__).with_name("static")
_FAVICON_PATH = _STATIC_DIR / "favicon.png"

_SUPPORTED_LANGS = {"en", "de"}

_I18N = {
    "en": {
        "nav_dashboard": "Dashboard",
        "nav_users": "Users",
        "nav_devices": "Devices",
        "nav_assignments": "Assignments",
        "nav_invites": "Invites",
        "nav_diagnostics": "Diagnostics",
        "nav_discovery": "Discovery",
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
        "title_discovery": "Discovery",
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
        "heading_discovery_scan": "Run Discovery Scan",
        "heading_discovery_runs": "Discovery Runs",
        "heading_discovery_candidates": "Discovery Candidates",
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
        "col_run_id": "Run ID",
        "col_status": "Status",
        "col_summary": "Summary",
        "col_wol_confidence": "WoL Confidence",
        "col_source_network": "Source Network",
        "col_imported_host": "Imported Host",
        "col_suggested_host": "Suggested Host",
        "col_first_successful_wake": "First Successful Wake",
        "col_seconds": "Seconds",
        "col_within_2m": "Within 2m",
        "placeholder_new_password_optional": "new password (optional)",
        "placeholder_username": "username",
        "placeholder_password_min12": "password (>=6)",
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
        "action_run_discovery": "Run Discovery",
        "action_validate_wake": "Validate Wake",
        "action_import_candidate": "Import",
        "action_merge_suggested": "Merge Suggested",
        "action_bulk_import": "Bulk Import",
        "confirm_delete_user": "Delete user '{username}'?",
        "confirm_delete_device": "Delete device '{device}'?",
        "confirm_remove_assignment": "Remove this assignment?",
        "confirm_revoke_invite": "Revoke this invite?",
        "label_token": "Token",
        "label_link": "Link",
        "alt_invite_qr_code": "Invite QR Code",
        "error_invalid_role": "Invalid role",
        "error_password_min_length": "Password must be at least 6 characters",
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
        "error_discovery_disabled": "Discovery feature is disabled",
        "error_no_discovery_bindings": "No valid discovery source bindings available",
        "text_active_sender_bindings": "Active sender bindings",
        "label_import_mode": "Import mode",
        "option_auto_merge_by_mac": "auto merge by MAC",
        "option_create_new": "create new only",
    },
    "de": {
        "nav_dashboard": "Dashboard",
        "nav_users": "Benutzer",
        "nav_devices": "Gerate",
        "nav_assignments": "Zuweisungen",
        "nav_invites": "Einladungen",
        "nav_diagnostics": "Diagnose",
        "nav_discovery": "Discovery",
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
        "title_discovery": "Discovery",
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
        "heading_discovery_scan": "Discovery-Scan starten",
        "heading_discovery_runs": "Discovery-Laufe",
        "heading_discovery_candidates": "Discovery-Kandidaten",
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
        "col_run_id": "Run-ID",
        "col_status": "Status",
        "col_summary": "Zusammenfassung",
        "col_wol_confidence": "WoL-Vertrauen",
        "col_source_network": "Quellnetz",
        "col_imported_host": "Importierter Host",
        "col_suggested_host": "Vorgeschlagener Host",
        "col_first_successful_wake": "Erster erfolgreicher Wake",
        "col_seconds": "Sekunden",
        "col_within_2m": "Innerhalb 2m",
        "placeholder_new_password_optional": "neues Passwort (optional)",
        "placeholder_username": "benutzername",
        "placeholder_password_min12": "passwort (>=6)",
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
        "placeholder_network_cidrs": "netz-cidrs (kommagetrennt, optional)",
        "placeholder_power_ports": "power probe ports, z. B. 22,80,443,445",
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
        "action_run_discovery": "Discovery starten",
        "action_validate_wake": "Wake validieren",
        "action_import_candidate": "Importieren",
        "action_merge_suggested": "Vorschlag mergen",
        "action_bulk_import": "Bulk-Import",
        "confirm_delete_user": "Benutzer '{username}' loschen?",
        "confirm_delete_device": "Gerat '{device}' loschen?",
        "confirm_remove_assignment": "Diese Zuweisung entfernen?",
        "confirm_revoke_invite": "Diese Einladung widerrufen?",
        "label_token": "Token",
        "label_link": "Link",
        "alt_invite_qr_code": "Einladungs-QR-Code",
        "error_invalid_role": "Ungultige Rolle",
        "error_password_min_length": "Passwort muss mindestens 6 Zeichen haben",
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
        "msg_discovery_run_started": "Discovery-Run gestartet: {run_id}",
        "msg_discovery_candidate_imported": "Kandidat in Host {host_id} importiert",
        "msg_discovery_validate_result": "Validierung: {result} ({detail})",
        "msg_discovery_bulk_imported": "Bulk-Import abgeschlossen: importiert={imported}, gemerged={merged}, erstellt={created}, ubersprungen={skipped}, fehlgeschlagen={failed}",
        "text_total_claimed_users": "Insgesamt eingeloste Benutzer",
        "text_detected_networks": "Erkannte IPv4-Netze",
        "text_multiple_networks_available": "Mehrere aktive Netzwerke verfugbar",
        "text_users_first_success_2m": "Benutzer mit erstem erfolgreichen Wake in 2 Min",
        "text_completion_rate_2m": "Abschlussrate innerhalb 2 Min",
        "text_target_90": "Ziel: 90%",
        "value_yes": "ja",
        "value_no": "nein",
        "error_discovery_disabled": "Discovery-Funktion ist deaktiviert",
        "error_no_discovery_bindings": "Keine gultigen Discovery-Quellbindungen verfugbar",
        "text_active_sender_bindings": "Aktive Sender-Bindings",
        "label_import_mode": "Import-Modus",
        "option_auto_merge_by_mac": "automatisch per MAC mergen",
        "option_create_new": "nur neu erstellen",
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


_BADGE_COLORS = {
    "sent": "#2d8a4e", "failed": "#c0392b",
    "already_on": "#2980b9", "on": "#2d8a4e", "off": "#888",
    "tcp": "#7d3c98", "icmp": "#1a6996",
    "admin": "#d35400", "user": "#555",
    "unknown": "#999",
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
    flashes = ""
    if message:
        flashes += f'<div class="flash flash-ok"><span>{_esc(message)}</span><button class="flash-close" aria-label="dismiss">×</button></div>'
    if error:
        flashes += f'<div class="flash flash-err"><span>{_esc(error)}</span><button class="flash-close" aria-label="dismiss">×</button></div>'
    cur = request.url.path

    def _nav(path: str, label: str) -> str:
        exact = path == "/admin/ui"
        is_active = (cur == path) if exact else (cur == path or cur.startswith(path + "/"))
        cur_attr = ' aria-current="page"' if is_active else ""
        return f'<a href="{_with_lang(path, lang)}"{cur_attr}>{label}</a>'

    sidebar = f"""<aside class="sidebar">
      <div class="sidebar-brand">WakeFromFar</div>
      <nav>
        {_nav('/admin/ui', t('nav_dashboard'))}
        {_nav('/admin/ui/users', t('nav_users'))}
        {_nav('/admin/ui/devices', t('nav_devices'))}
        {_nav('/admin/ui/assignments', t('nav_assignments'))}
        {_nav('/admin/ui/invites', t('nav_invites'))}
        <div class="nav-sep"></div>
        {_nav('/admin/ui/wake-logs', t('nav_wake_logs'))}
        {_nav('/admin/ui/power-check-logs', t('nav_power_logs'))}
        {_nav('/admin/ui/audit-logs', t('nav_audit_logs'))}
        <div class="nav-sep"></div>
        {_nav('/admin/ui/diagnostics', t('nav_diagnostics'))}
        {_nav('/admin/ui/discovery', t('nav_discovery'))}
        {_nav('/admin/ui/metrics', t('nav_metrics'))}
        {_nav('/admin/ui/pilot-metrics', t('nav_pilot_metrics'))}
      </nav>
    </aside>"""

    css = """
:root{
  --sidebar-w:220px;--sidebar-bg:#1a1f2e;--sidebar-text:#b8c0d0;--sidebar-active:#fff;--sidebar-active-bg:rgba(255,255,255,.12);--topbar-h:56px;
  --bg:#f5f7fb;--fg:#1f2937;--card-bg:#fff;--card-border:#d7dce3;
  --topbar-bg:#fff;--topbar-border:#d7dce3;
  --input-bg:#fff;--input-border:#cbd5e1;--input-fg:#111827;
  --table-bg:#fff;--table-border:#d7dce3;--thead-bg:#f8fafc;--row-border:#e5e7eb;
  --muted:#64748b;--link:#1d4ed8;--code-bg:#f2f4f8;--code-border:#d7dce3;
  --btn-bg:#0f172a;--btn-border:#0f172a;--btn2-bg:#fff;--btn2-fg:#334155;--btn2-border:#94a3b8;
}
[data-theme="dark"]{
  --bg:#0f1117;--fg:#e2e8f0;--card-bg:#1e2433;--card-border:#2d3748;
  --topbar-bg:#1a1f2e;--topbar-border:#2d3748;
  --input-bg:#2d3748;--input-border:#4a5568;--input-fg:#e2e8f0;
  --table-bg:#1e2433;--table-border:#2d3748;--thead-bg:#252d3d;--row-border:#2d3748;
  --muted:#94a3b8;--link:#60a5fa;--code-bg:#252d3d;--code-border:#374151;
  --btn-bg:#334155;--btn-border:#475569;--btn2-bg:#2d3748;--btn2-fg:#cbd5e1;--btn2-border:#4a5568;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--fg);line-height:1.45;transition:background .2s,color .2s}
a{color:var(--link)}
h1,h2,h3{margin:0 0 .8rem}
h2{font-size:1.1rem}
p{margin:.35rem 0 .75rem}
article{background:var(--card-bg);border:1px solid var(--card-border);border-radius:10px;padding:1rem;margin:0 0 1rem}
button,input,select{font:inherit}
input,select{width:100%;max-width:100%;padding:.45rem .6rem;border:1px solid var(--input-border);border-radius:8px;background:var(--input-bg);color:var(--input-fg)}
button{padding:.45rem .85rem;border:1px solid var(--btn-border);border-radius:8px;background:var(--btn-bg);color:#fff;cursor:pointer}
button:hover{filter:brightness(.95)}
button.secondary{background:var(--btn2-bg);color:var(--btn2-fg);border-color:var(--btn2-border)}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,Liberation Mono,monospace;font-size:.85em;background:var(--code-bg);border:1px solid var(--code-border);border-radius:6px;padding:.1rem .3rem}
table{width:100%;font-size:.875rem;border-collapse:collapse;background:var(--table-bg);border:1px solid var(--table-border)}
th,td{padding:.5rem .55rem;text-align:left;vertical-align:top;border-bottom:1px solid var(--row-border)}
thead th{background:var(--thead-bg);font-weight:600}
tr:last-child td{border-bottom:none}
.admin-shell{display:grid;grid-template-columns:var(--sidebar-w) 1fr;min-height:100vh}
.sidebar{background:var(--sidebar-bg);color:var(--sidebar-text);position:sticky;top:0;height:100vh;overflow-y:auto;display:flex;flex-direction:column}
.sidebar-brand{padding:1rem 1.25rem;font-weight:700;font-size:1rem;color:#fff;letter-spacing:.02em;border-bottom:1px solid rgba(255,255,255,.08)}
.sidebar nav{display:flex;flex-direction:column;padding:.5rem 0;flex:1}
.sidebar nav a{display:block;padding:.5rem 1.25rem;color:var(--sidebar-text);text-decoration:none;font-size:.875rem;transition:background .15s,color .15s}
.sidebar nav a:hover{background:rgba(255,255,255,.07);color:#fff}
.sidebar nav a[aria-current="page"]{background:var(--sidebar-active-bg);color:var(--sidebar-active);font-weight:600}
.nav-sep{height:1px;background:rgba(255,255,255,.08);margin:.4rem .75rem}
.main-area{display:flex;flex-direction:column;min-height:100vh}
.topbar{height:var(--topbar-h);display:flex;align-items:center;padding:0 1.5rem;gap:1rem;background:var(--topbar-bg);border-bottom:1px solid var(--topbar-border);position:sticky;top:0;z-index:10;transition:background .2s,border-color .2s}
.topbar-title{font-weight:600;font-size:1rem;flex:1}
.topbar-right{display:flex;align-items:center;gap:1rem;flex-wrap:wrap}
.topbar-user{font-size:.875rem;color:var(--muted)}
.lang-switch{font-size:.8rem;color:var(--muted)}
.lang-switch a{color:inherit}
.theme-toggle{background:none;border:1px solid var(--input-border);border-radius:8px;color:var(--fg);padding:.3rem .6rem;font-size:.85rem;cursor:pointer;line-height:1}
.theme-toggle:hover{background:var(--input-bg)}
main.container-fluid{padding:1.5rem;flex:1}
.flash{display:flex;align-items:center;justify-content:space-between;padding:.75rem 1rem;border-radius:8px;margin-bottom:1rem;font-size:.9rem}
.flash-ok{background:#d1f0da;color:#1a5e2e;border:1px solid #a8ddb5}
.flash-err{background:#fde8e8;color:#7b1a1a;border:1px solid #f5b7b7}
.flash-close{background:none;border:none;font-size:1.2rem;cursor:pointer;color:inherit;padding:0 .25rem;line-height:1}
.stat-cards{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:1.5rem}
.stat-card{text-align:center;padding:1.25rem}
.stat-number{display:block;font-size:2rem;font-weight:700;line-height:1.1}
.stat-label{display:block;font-size:.8rem;color:var(--muted);margin-top:.25rem;text-transform:uppercase;letter-spacing:.05em}
.badge{display:inline-block;padding:.2em .55em;border-radius:99px;font-size:.75rem;font-weight:600;color:#fff;white-space:nowrap}
form{margin-bottom:0}
figure{overflow-x:auto;margin:0 0 1rem}
@media(max-width:768px){
  .admin-shell{grid-template-columns:1fr}
  .sidebar{position:static;height:auto}
  .sidebar nav{flex-direction:row;flex-wrap:wrap;padding:.25rem}
  .sidebar nav a{padding:.35rem .6rem;font-size:.8rem}
  .stat-cards{grid-template-columns:repeat(2,1fr)}
}"""

    js = """document.querySelectorAll('form[data-confirm]').forEach(function(f){
  f.addEventListener('submit',function(e){if(!confirm(f.dataset.confirm))e.preventDefault()});
});
document.querySelectorAll('.flash').forEach(function(el){
  var btn=el.querySelector('.flash-close');
  if(btn)btn.addEventListener('click',function(){el.remove()});
  setTimeout(function(){if(el.parentNode)el.remove()},4000);
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
      <header class="topbar">
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


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/admin/ui", error: str | None = None):
    user = _admin_from_cookie(request)
    lang = _lang(request)
    safe_next = _safe_next_path(next)
    t = lambda key, **kwargs: _tr(request, key, **kwargs)
    if user:
        return RedirectResponse(safe_next, status_code=303)
    error_html = f'<p class="login-error">{_esc(error)}</p>' if error else ""
    page = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{t("title_admin_login")}</title>
  <link rel="icon" type="image/png" href="/admin/ui/favicon.png">
  <script>document.documentElement.dataset.theme=localStorage.getItem('wff-theme')||(window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');</script>
  <style>
:root{{--bg:#f5f7fb;--fg:#1f2937;--card-bg:#fff;--card-border:#d7dce3;--input-bg:#fff;--input-border:#cbd5e1;--input-fg:#111827;--muted:#64748b;--btn-bg:#0f172a;--btn-border:#0f172a}}
[data-theme="dark"]{{--bg:#0f1117;--fg:#e2e8f0;--card-bg:#1e2433;--card-border:#2d3748;--input-bg:#2d3748;--input-border:#4a5568;--input-fg:#e2e8f0;--muted:#94a3b8;--btn-bg:#334155;--btn-border:#475569}}
*{{box-sizing:border-box}}
html,body{{margin:0;padding:0}}
body{{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:1rem;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--fg)}}
.login-card{{width:100%;max-width:380px}}
.login-card{{background:var(--card-bg);border:1px solid var(--card-border);border-radius:12px;padding:1rem}}
.login-brand{{text-align:center;margin-bottom:1.5rem}}
.login-brand h1{{font-size:1.5rem;margin:0}}
.login-brand p{{color:var(--muted);font-size:.875rem;margin:.25rem 0 0}}
.login-error{{color:#7b1a1a;background:#fde8e8;border:1px solid #f5b7b7;border-radius:8px;padding:.6rem .9rem;font-size:.875rem}}
label{{display:block;margin:.45rem 0 .2rem}}
input{{width:100%;max-width:100%;padding:.5rem .6rem;border:1px solid var(--input-border);border-radius:8px;background:var(--input-bg);color:var(--input-fg);font:inherit}}
button{{margin-top:.65rem;width:100%;padding:.5rem .85rem;border:1px solid var(--btn-border);border-radius:8px;background:var(--btn-bg);color:#fff;cursor:pointer;font:inherit}}
button:hover{{filter:brightness(.95)}}
.lang-footer{{text-align:center;margin-top:1rem;font-size:.8rem;color:var(--muted)}}
.lang-footer a{{color:inherit}}
  </style>
</head>
<body>
  <article class="login-card">
    <div class="login-brand">
      <h1>WakeFromFar</h1>
      <p>{t("title_admin_login")}</p>
    </div>
    {error_html}
    <form method="post" action="/admin/ui/login" autocomplete="off">
      <input type="hidden" name="next" value="{_esc(safe_next)}" />
      <input type="hidden" name="lang" value="{_esc(lang)}" />
      <label for="login-username">{t("label_username")}</label>
      <input id="login-username" required name="username" autocomplete="username" />
      <label for="login-password">{t("label_password")}</label>
      <input id="login-password" required type="password" name="password" autocomplete="current-password" />
      <button type="submit">{t("action_login")}</button>
    </form>
    <div class="lang-footer">
      <a href="{_esc(_lang_switch_url(request, 'en'))}">{t("lang_en")}</a> |
      <a href="{_esc(_lang_switch_url(request, 'de'))}">{t("lang_de")}</a>
    </div>
  </article>
</body>
</html>"""
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
    device_name_map = {str(h["id"]): str(h["name"]) for h in devices}
    message, error = _msg(request)
    selected_run_id = request.query_params.get("run_id")
    bulk_form = ""
    if selected_run_id:
        bulk_form = f"""
    <form method="post" action="/admin/ui/discovery/runs/{_esc(selected_run_id)}/import-bulk" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:.8rem;">
      <label>{t("label_import_mode")}
        <select name="mode">
          <option value="auto_merge_by_mac">{t("option_auto_merge_by_mac")}</option>
          <option value="create_new">{t("option_create_new")}</option>
        </select>
      </label>
      <input name="name_prefix" placeholder="discovered" />
      <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" name="apply_power_settings" value="1" checked />power settings</label>
      <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" name="skip_without_mac" value="1" checked />skip without mac</label>
      <button type="submit">{t("action_bulk_import")}</button>
    </form>
        """

    body = f"""
    <div class="stat-cards">
      <article class="stat-card"><strong class="stat-number">{len(users)}</strong><span class="stat-label">{t("card_users")}</span></article>
      <article class="stat-card"><strong class="stat-number">{len(devices)}</strong><span class="stat-label">{t("card_devices")}</span></article>
      <article class="stat-card"><strong class="stat-number">{len(assignments)}</strong><span class="stat-label">{t("card_assignments")}</span></article>
      <article class="stat-card"><strong class="stat-number">{len(list_invite_tokens(limit=500))}</strong><span class="stat-label">{t("card_invites")}</span></article>
    </div>
    <h2>{t("heading_recent_wake_logs")}</h2>
    <figure><table>
      <thead><tr><th>{t("col_id")}</th><th>{t("col_device")}</th><th>{t("col_actor")}</th><th>{t("col_result")}</th><th>{t("col_time")}</th></tr></thead>
      <tbody>{"".join(f"<tr><td>{row['id']}</td><td>{_device_cell(row['host_id'], device_name_map)}</td><td>{_esc(row['actor_username'])}</td><td>{_badge(str(row['result']))}</td><td>{_esc(row['created_at'])}</td></tr>" for row in wake_logs)}</tbody>
    </table></figure>
    <h2>{t("heading_recent_power_checks")}</h2>
    <figure><table>
      <thead><tr><th>{t("col_id")}</th><th>{t("col_device")}</th><th>{t("col_method")}</th><th>{t("col_result")}</th><th>{t("col_time")}</th></tr></thead>
      <tbody>{"".join(f"<tr><td>{row['id']}</td><td>{_device_cell(row['device_id'], device_name_map)}</td><td>{_badge(str(row['method']))}</td><td>{_badge(str(row['result']))}</td><td>{_esc(row['created_at'])}</td></tr>" for row in power_logs)}</tbody>
    </table></figure>
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
          <td>{row['id']}</td><td>{_esc(row['username'])}</td><td>{_badge(str(row['role']))}</td><td>{_esc(row['created_at'])}</td>
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
            <form method="post" action="/admin/ui/users/{row['id']}/delete" data-confirm="{_esc(t('confirm_delete_user', username=str(row['username'])))}">
              <button type="submit" class="secondary">{t("action_delete")}</button>
            </form>
          </td>
        </tr>
        """
        for row in rows
    )
    body = f"""
    <h2>{t("heading_create_user")}</h2>
    <form method="post" action="/admin/ui/users/create" autocomplete="off" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:1.5rem;">
      <input required name="username" placeholder="{t("placeholder_username")}" />
      <input required name="password" type="password" placeholder="{t("placeholder_password_min12")}" />
      <select name="role"><option value="user">user</option><option value="admin">admin</option></select>
      <button type="submit">{t("action_create")}</button>
    </form>
    <h2>{t("heading_users")}</h2>
    <figure><table>
      <thead><tr><th>{t("col_id")}</th><th>{t("col_username")}</th><th>{t("col_role")}</th><th>{t("col_created")}</th><th>{t("col_update")}</th><th>{t("col_delete")}</th></tr></thead>
      <tbody>{table_rows}</tbody>
    </table></figure>
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
    if len(password) < 6:
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
        if len(password) < 6:
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
              <input name="source_network_cidr" value="{_esc(row['source_network_cidr'])}" placeholder="{t("placeholder_subnet_cidr")}" />
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
            <form method="post" action="/admin/ui/devices/{_esc(row['id'])}/test-power-check"><button type="submit" class="secondary">{t("action_test_power_check")}</button></form>
            <form method="post" action="/admin/ui/devices/{_esc(row['id'])}/delete" data-confirm="{_esc(t('confirm_delete_device', device=str(row['name'])))}"><button type="submit" class="secondary">{t("action_delete")}</button></form>
          </td>
        </tr>
        """
        for row in rows
    )
    body = f"""
    <h2>{t("heading_create_device")}</h2>
    <form method="post" action="/admin/ui/devices/create" autocomplete="off" style="display:grid;grid-template-columns:repeat(4,minmax(160px,1fr));gap:8px;margin-bottom:1.5rem;">
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
    <h2>{t("heading_devices")}</h2>
    <figure><table>
      <thead><tr><th>{t("col_id")}</th><th>{t("col_name")}</th><th>{t("col_display")}</th><th>{t("col_mac")}</th><th>{t("col_method")}</th><th>{t("col_target")}</th><th>{t("col_port")}</th><th>{t("col_state")}</th><th>{t("col_checked_at")}</th><th>{t("col_diagnostics")}</th><th>{t("col_update")}</th><th>{t("col_actions")}</th></tr></thead>
      <tbody>{table_rows}</tbody>
    </table></figure>
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
          <td><form method="post" action="/admin/ui/assignments/{row['user_id']}/{_esc(row['device_id'])}/delete" data-confirm="{_esc(t('confirm_remove_assignment'))}"><button type="submit" class="secondary">{t("action_remove")}</button></form></td>
        </tr>
        """
        for row in assignments
    )
    body = f"""
    <h2>{t("heading_create_assignment")}</h2>
    <form method="post" action="/admin/ui/assignments/create" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:1.5rem;">
      <select name="user_id">{user_opts}</select>
      <select name="device_id">{device_opts}</select>
      <button type="submit">{t("action_assign")}</button>
    </form>
    <h2>{t("heading_assignments")}</h2>
    <figure><table>
      <thead><tr><th>{t("col_user_id")}</th><th>{t("col_username")}</th><th>{t("col_device_id")}</th><th>{t("col_device")}</th><th>{t("col_created")}</th><th>{t("col_action")}</th></tr></thead>
      <tbody>{rows}</tbody>
    </table></figure>
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
          <td><form method="post" action="/admin/ui/invites/{_esc(row['id'])}/revoke" data-confirm="{_esc(t('confirm_revoke_invite'))}"><button type="submit" class="secondary">{t("action_revoke")}</button></form></td>
        </tr>
        """
        for row in invites
    )
    created_section = ""
    if created_token and created_link:
        qr_url = f"https://quickchart.io/qr?size=240&text={quote_plus(created_link)}"
        created_section = f"""
        <article>
          <h3>{t("heading_new_invite")}</h3>
          <p><strong>{t("label_token")}:</strong> <code>{_esc(created_token)}</code></p>
          <p><strong>{t("label_link")}:</strong> <code>{_esc(created_link)}</code></p>
          <img src="{_esc(qr_url)}" alt="{t("alt_invite_qr_code")}" style="margin-top:.5rem" />
        </article>
        """
    users = list_users()
    user_opts = "".join(f'<option value="{_esc(row["username"])}">{_esc(row["username"])}</option>' for row in users)
    body = f"""
    {created_section}
    <h2>{t("heading_create_invite")}</h2>
    <form method="post" action="/admin/ui/invites/create" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:1.5rem;">
      <select name="username">{user_opts}</select>
      <input name="backend_url_hint" placeholder="{t("placeholder_backend_url_hint_optional")}" />
      <input name="expires_in_hours" value="72" placeholder="{t("placeholder_hours")}" />
      <button type="submit">{t("action_create_invite")}</button>
    </form>
    <h2>{t("heading_invites")}</h2>
    <figure><table>
      <thead><tr><th>{t("col_id")}</th><th>{t("col_username")}</th><th>{t("col_backend_hint")}</th><th>{t("col_expires_at")}</th><th>{t("col_claimed_at")}</th><th>{t("col_created_by")}</th><th>{t("col_action")}</th></tr></thead>
      <tbody>{rows}</tbody>
    </table></figure>
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
    device_name_map = {str(h["id"]): str(h["name"]) for h in list_hosts()}
    message, error = _msg(request)
    body_rows = "".join(
        f"<tr><td>{row['id']}</td><td>{_device_cell(row['host_id'], device_name_map)}</td><td>{_esc(row['actor_username'])}</td><td>{_badge(str(row['result']))}</td><td>{_esc(row['precheck_state'])}</td><td>{_esc(row['error_detail'])}</td><td>{_esc(row['created_at'])}</td></tr>"
        for row in rows
    )
    body = f"""
    <h2>{t("heading_wake_logs")}</h2>
    <form method="get" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:1rem;">
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
    <figure><table>
      <thead><tr><th>{t("col_id")}</th><th>{t("col_host_id")}</th><th>{t("col_actor")}</th><th>{t("col_result")}</th><th>{t("col_precheck")}</th><th>{t("col_error")}</th><th>{t("col_created")}</th></tr></thead>
      <tbody>{body_rows}</tbody>
    </table></figure>
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
        f"<tr><td>{row['id']}</td><td>{_device_cell(row['device_id'], device_name_map)}</td><td>{_badge(str(row['method']))}</td><td>{_badge(str(row['result']))}</td><td>{_esc(row['detail'])}</td><td>{_esc(row['latency_ms'])}</td><td>{_esc(row['created_at'])}</td></tr>"
        for row in rows
    )
    body = f"""
    <h2>{t("heading_power_check_logs")}</h2>
    <form method="get" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:1rem;">
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
    <figure><table>
      <thead><tr><th>{t("col_id")}</th><th>{t("col_device_id")}</th><th>{t("col_method")}</th><th>{t("col_result")}</th><th>{t("col_detail")}</th><th>{t("col_latency_ms")}</th><th>{t("col_created")}</th></tr></thead>
      <tbody>{body_rows}</tbody>
    </table></figure>
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
    <figure><table>
      <thead><tr><th>{t("col_interface")}</th><th>{t("col_ipv4")}</th><th>{t("col_netmask")}</th><th>{t("col_network")}</th><th>{t("col_broadcast")}</th><th>{t("col_up")}</th><th>{t("col_loopback")}</th></tr></thead>
      <tbody>{''.join(network_rows)}</tbody>
    </table></figure>
    <h2>{t("heading_device_diagnostics_hints")}</h2>
    <figure><table>
      <thead><tr><th>{t("col_device_id")}</th><th>{t("col_name")}</th><th>{t("col_hints")}</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table></figure>
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
            f"<td><a href=\"{_with_lang(f'/admin/ui/discovery?run_id={_esc(row['id'])}', _lang(request))}\">{_esc(row['id'])}</a></td>"
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
                '<input type="hidden" name="mode" value="auto_merge_by_mac" />'
                '<input type="hidden" name="apply_power_settings" value="1" />'
                f'<button type="submit" class="secondary">{t("action_merge_suggested")}</button>'
                "</form>"
            )
        candidate_rows.append(
            f"""
            <tr>
              <td>{_esc(row['id'])}</td>
              <td>{_esc(row['hostname'])}</td>
              <td>{_esc(row['mac'])}</td>
              <td>{_esc(row['ip'])}</td>
              <td>{_badge(str(row['wol_confidence']))}</td>
              <td>{_esc(row['source_network_cidr'])}</td>
              <td>{_esc(row['imported_host_id'])}</td>
              <td>{suggested_cell}</td>
              <td>
                {suggested_action}
                <form method="post" action="/admin/ui/discovery/candidates/{_esc(row['id'])}/validate-wake" style="display:inline;">
                  <button type="submit" class="secondary">{t("action_validate_wake")}</button>
                </form>
                <form method="post" action="/admin/ui/discovery/candidates/{_esc(row['id'])}/import" style="display:inline-flex;gap:6px;align-items:center;">
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
        f"<tr><td>{row['id']}</td><td>{_esc(row['event_type'])}</td><td>{_esc(row['candidate_id'])}</td><td>{_esc(row['detail'])}</td><td>{_esc(row['created_at'])}</td></tr>"
        for row in events
    )
    binding_text = ", ".join(
        f"{_esc(row.get('network_cidr'))} via {_esc(row.get('source_ip'))}"
        for row in bindings
    ) or "-"
    bulk_form = ""
    if selected_run_id:
        bulk_form = f"""
    <form method="post" action="/admin/ui/discovery/runs/{_esc(selected_run_id)}/import-bulk" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:.8rem;">
      <label>{t("label_import_mode")}
        <select name="mode">
          <option value="auto_merge_by_mac">{t("option_auto_merge_by_mac")}</option>
          <option value="create_new">{t("option_create_new")}</option>
        </select>
      </label>
      <input name="name_prefix" placeholder="discovered" />
      <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" name="apply_power_settings" value="1" checked />power settings</label>
      <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" name="skip_without_mac" value="1" checked />skip without mac</label>
      <button type="submit">{t("action_bulk_import")}</button>
    </form>
        """

    body = f"""
    <h2>{t("heading_discovery_scan")}</h2>
    <p>{t("text_active_sender_bindings")}: <strong>{binding_text}</strong></p>
    <form method="post" action="/admin/ui/discovery/run" style="display:grid;grid-template-columns:repeat(4,minmax(170px,1fr));gap:8px;margin-bottom:1.5rem;">
      <input name="network_cidrs" placeholder="{t("placeholder_network_cidrs")}" />
      <input name="power_ports" placeholder="{t("placeholder_power_ports")}" />
      <input name="power_timeout_ms" value="200" />
      <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" name="host_probe_enabled" value="1" /> host probe</label>
      <input name="host_probe_timeout_ms" value="200" />
      <input name="max_hosts_per_network" value="{settings.discovery_default_host_cap}" />
      <button type="submit">{t("action_run_discovery")}</button>
    </form>
    <h2>{t("heading_discovery_runs")}</h2>
    <figure><table>
      <thead><tr><th>{t("col_run_id")}</th><th>{t("col_status")}</th><th>{t("col_summary")}</th><th>{t("col_created")}</th></tr></thead>
      <tbody>{''.join(run_rows)}</tbody>
    </table></figure>
    <h2>{t("heading_discovery_candidates")}</h2>
    {bulk_form}
    <p style="margin-bottom:.5rem;font-size:.875rem;">
      {"" if not docker_count else (
        f'<a href="{_with_lang(f"/admin/ui/discovery?run_id={_esc(selected_run_id)}", _lang(request))}">'
        f"Show real devices only</a>" if show_docker_flag else
        f'<a href="{_with_lang(f"/admin/ui/discovery?run_id={_esc(selected_run_id)}&show_docker=1", _lang(request))}">'
        f"Show all ({docker_count} Docker containers hidden)</a>"
      )}
    </p>
    <figure><table>
      <thead><tr><th>{t("col_id")}</th><th>{t("col_name")}</th><th>{t("col_mac")}</th><th>{t("col_ipv4")}</th><th>{t("col_wol_confidence")}</th><th>{t("col_source_network")}</th><th>{t("col_imported_host")}</th><th>{t("col_suggested_host")}</th><th>{t("col_actions")}</th></tr></thead>
      <tbody>{''.join(candidate_rows)}</tbody>
    </table></figure>
    <h2>Events</h2>
    <figure><table>
      <thead><tr><th>{t("col_id")}</th><th>{t("col_action")}</th><th>{t("col_device_id")}</th><th>{t("col_detail")}</th><th>{t("col_created")}</th></tr></thead>
      <tbody>{event_rows}</tbody>
    </table></figure>
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
        f"<tr><td>{row['id']}</td><td>{_esc(row['actor_username'])}</td><td>{_esc(row['action'])}</td><td>{_esc(row['target_type'])}</td><td>{_esc(row['target_id'])}</td><td>{_esc(row['detail'])}</td><td>{_esc(row['created_at'])}</td></tr>"
        for row in rows
    )
    body = f"""
    <h2>{t("heading_admin_audit_logs")}</h2>
    <figure><table>
      <thead><tr><th>{t("col_id")}</th><th>{t("col_actor")}</th><th>{t("col_action")}</th><th>{t("col_target_type")}</th><th>{t("col_target_id")}</th><th>{t("col_detail")}</th><th>{t("col_created")}</th></tr></thead>
      <tbody>{body_rows}</tbody>
    </table></figure>
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
    <figure><table>
      <thead><tr><th>{t("col_counter")}</th><th>{t("col_value")}</th></tr></thead>
      <tbody>{rows}</tbody>
    </table></figure>
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
    <figure><table>
      <thead><tr><th>{t("col_username")}</th><th>{t("col_claimed_at")}</th><th>{t("col_first_successful_wake")}</th><th>{t("col_seconds")}</th><th>{t("col_within_2m")}</th></tr></thead>
      <tbody>{''.join(details_rows)}</tbody>
    </table></figure>
    """
    message, error = _msg(request)
    return _layout(request, t("title_pilot_metrics"), body, admin["username"], message=message, error=error)
