from __future__ import annotations

import re
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.db import enable_user_mfa, get_user_by_username
from app.db import record_scheduled_wake_run
from app.config import get_settings
from app.power import PowerCheckResult
from app.security import create_state_token, decrypt_secret_value, encrypt_secret_value, generate_totp_code, generate_totp_secret

from .conftest import (
    ADMIN_UI_ORIGIN,
    admin_ui_headers,
    admin_ui_login,
    admin_ui_post,
    auth_headers,
    extract_admin_ui_csrf_token,
    login,
)

DAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
BACKEND_DIR = Path(__file__).resolve().parents[1]


def _future_schedule_form(device_id: str, *, label: str = "Morning Boot") -> dict[str, str]:
    now = datetime.now(UTC) + timedelta(minutes=5)
    return {
        "device_id": device_id,
        "label": label,
        "enabled": "1",
        "timezone": "UTC",
        "days_of_week": DAY_NAMES[now.weekday()],
        "local_time": now.strftime("%H:%M"),
    }


def _extract_hidden_input(response_text: str, field_name: str) -> str:
    match = re.search(rf'name="{re.escape(field_name)}"\s+value="([^"]+)"', response_text)
    assert match is not None, response_text
    return match.group(1)


def _enable_admin_mfa_for_tests(username: str = "admin") -> str:
    user = get_user_by_username(username)
    assert user is not None
    secret = generate_totp_secret()
    enabled = enable_user_mfa(int(user["id"]), encrypt_secret_value(secret))
    assert enabled is True
    return secret


def test_admin_ui_requires_login(client):
    response = client.get("/admin/ui", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/admin/ui/login")


def test_admin_ui_login_is_blocked_from_non_admin_network(client_factory):
    env = {
        "IP_ALLOWLIST_CIDRS": "192.168.0.0/16",
        "ADMIN_IP_ALLOWLIST_CIDRS": "127.0.0.1/32",
    }
    with client_factory(client_host="192.168.10.25", env_overrides=env) as client:
        response = client.get("/admin/ui/login")

    assert response.status_code == 403
    assert response.json()["detail"] == "Admin access is not allowed from this network"


def test_admin_ui_authenticated_page_is_blocked_from_non_admin_network(client_factory):
    with client_factory() as allowed_client:
        login_response = admin_ui_login(allowed_client, next_path="/admin/ui/users")
        session_cookie = allowed_client.cookies.get("admin_session")

    assert login_response.status_code == 303
    assert session_cookie

    env = {
        "IP_ALLOWLIST_CIDRS": "192.168.0.0/16",
        "ADMIN_IP_ALLOWLIST_CIDRS": "127.0.0.1/32",
    }
    with client_factory(client_host="192.168.10.25", env_overrides=env) as client:
        client.cookies.set("admin_session", session_cookie, path="/admin/ui")
        response = client.get("/admin/ui/users", follow_redirects=False)

    assert response.status_code == 403
    assert response.json()["detail"] == "Admin access is not allowed from this network"


def test_admin_ui_access_from_allowed_admin_network_still_works(client_factory):
    env = {
        "IP_ALLOWLIST_CIDRS": "192.168.0.0/16",
        "ADMIN_IP_ALLOWLIST_CIDRS": "192.168.0.0/16",
    }
    with client_factory(client_host="192.168.10.25", env_overrides=env) as client:
        login_page = client.get("/admin/ui/login")
        login_response = admin_ui_login(client, next_path="/admin/ui/users")
        users_page = client.get("/admin/ui/users")

    assert login_page.status_code == 200
    assert login_response.status_code == 303
    assert users_page.status_code == 200
    assert "Create User" in users_page.text


def test_admin_ui_disabled_returns_404_and_root_stays_safe(client_factory):
    env = {
        "ADMIN_UI_ENABLED": "false",
        "ADMIN_IP_ALLOWLIST_CIDRS": "127.0.0.1/32",
    }
    with client_factory(env_overrides=env) as client:
        login_page = client.get("/admin/ui/login")
        dashboard = client.get("/admin/ui")
        logout = client.get("/admin/ui/logout")
        create_user = client.post(
            "/admin/ui/users/create",
            data={"username": "uiuser", "password": "uiuserpassword12", "role": "user"},
        )
        root_response = client.get("/", follow_redirects=False)
        favicon = client.get("/favicon.ico", follow_redirects=False)
        admin_token = login(client, "admin", "adminpass123456")
        admin_api = client.get("/admin/users", headers=auth_headers(admin_token))

    assert login_page.status_code == 404
    assert dashboard.status_code == 404
    assert logout.status_code == 404
    assert create_user.status_code == 404
    assert root_response.status_code == 200
    assert "/admin/ui/login" not in root_response.text
    assert favicon.status_code == 404
    assert admin_api.status_code == 200, admin_api.text


def test_admin_ui_exposes_favicon(client):
    login_page = client.get("/admin/ui/login")
    assert login_page.status_code == 200
    assert 'rel="icon"' in login_page.text
    assert 'href="/admin/ui/favicon.png"' in login_page.text

    favicon = client.get("/admin/ui/favicon.png")
    assert favicon.status_code == 200
    assert favicon.headers.get("content-type", "").startswith("image/png")
    assert len(favicon.content) > 0


def test_root_favicon_redirects_to_admin_favicon(client):
    response = client.get("/favicon.ico", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "/admin/ui/favicon.png"


def test_admin_ui_login_page_renders_csrf_token(client):
    response = client.get("/admin/ui/login")

    assert response.status_code == 200
    assert extract_admin_ui_csrf_token(response.text)
    set_cookie = response.headers.get("set-cookie", "").lower()
    assert "admin_ui_csrf=" in set_cookie
    assert "httponly" in set_cookie
    assert "samesite=strict" in set_cookie
    assert "path=/admin/ui" in set_cookie


def test_admin_ui_login_post_requires_valid_csrf_token(client):
    login_page = client.get("/admin/ui/login")
    assert login_page.status_code == 200
    valid_csrf_token = extract_admin_ui_csrf_token(login_page.text)

    missing_token = client.post(
        "/admin/ui/login",
        data={"username": "admin", "password": "adminpass123456", "next": "/admin/ui/users"},
        headers=admin_ui_headers(),
        follow_redirects=False,
    )
    assert missing_token.status_code == 403
    assert missing_token.text == "Invalid CSRF token"

    invalid_token = client.post(
        "/admin/ui/login",
        data={
            "username": "admin",
            "password": "adminpass123456",
            "next": "/admin/ui/users",
            "csrf_token": "not-a-valid-token",
        },
        headers=admin_ui_headers(),
        follow_redirects=False,
    )
    assert invalid_token.status_code == 403
    assert invalid_token.text == "Invalid CSRF token"

    valid_token = client.post(
        "/admin/ui/login",
        data={
            "username": "admin",
            "password": "adminpass123456",
            "next": "/admin/ui/users",
            "csrf_token": valid_csrf_token,
        },
        headers=admin_ui_headers(),
        follow_redirects=False,
    )
    assert valid_token.status_code == 303
    assert valid_token.headers["location"] == "/admin/ui/users"


def test_admin_ui_authenticated_post_requires_valid_csrf_token(client):
    login_res = admin_ui_login(client, next_path="/admin/ui/users")
    assert login_res.status_code == 303

    users_page = client.get("/admin/ui/users")
    assert users_page.status_code == 200
    valid_csrf_token = extract_admin_ui_csrf_token(users_page.text)

    missing_token = client.post(
        "/admin/ui/users/create",
        data={"username": "csrf-missing", "password": "csrfmissing123", "role": "user"},
        headers=admin_ui_headers(),
        follow_redirects=False,
    )
    assert missing_token.status_code == 403
    assert missing_token.text == "Invalid CSRF token"

    invalid_token = client.post(
        "/admin/ui/users/create",
        data={
            "username": "csrf-invalid",
            "password": "csrfinvalid123",
            "role": "user",
            "csrf_token": f"{valid_csrf_token}x",
        },
        headers=admin_ui_headers(),
        follow_redirects=False,
    )
    assert invalid_token.status_code == 403
    assert invalid_token.text == "Invalid CSRF token"

    valid_token = client.post(
        "/admin/ui/users/create",
        data={
            "username": "csrf-valid",
            "password": "csrfvalid123",
            "role": "user",
            "csrf_token": valid_csrf_token,
        },
        headers=admin_ui_headers(),
        follow_redirects=False,
    )
    assert valid_token.status_code == 303
    assert valid_token.headers["location"].startswith("/admin/ui/users?")


def test_admin_ui_post_origin_and_referer_are_enforced(client):
    login_res = admin_ui_login(client, next_path="/admin/ui/users")
    assert login_res.status_code == 303

    same_origin = admin_ui_post(
        client,
        "/admin/ui/users/create",
        form_page_path="/admin/ui/users",
        data={"username": "origin-good", "password": "origingood123", "role": "user"},
        follow_redirects=False,
    )
    assert same_origin.status_code == 303

    users_page = client.get("/admin/ui/users")
    assert users_page.status_code == 200
    csrf_token = extract_admin_ui_csrf_token(users_page.text)

    wrong_origin = client.post(
        "/admin/ui/users/create",
        data={
            "username": "origin-bad",
            "password": "originbad123",
            "role": "user",
            "csrf_token": csrf_token,
        },
        headers=admin_ui_headers(origin="https://evil.example"),
        follow_redirects=False,
    )
    assert wrong_origin.status_code == 403
    assert wrong_origin.text == "Admin UI POST origin is not allowed"

    same_referer = client.post(
        "/admin/ui/users/create",
        data={
            "username": "referer-good",
            "password": "referergood123",
            "role": "user",
            "csrf_token": csrf_token,
        },
        headers=admin_ui_headers(origin=None, referer=f"{ADMIN_UI_ORIGIN}/admin/ui/users"),
        follow_redirects=False,
    )
    assert same_referer.status_code == 303

    null_origin_same_referer = client.post(
        "/admin/ui/users/create",
        data={
            "username": "origin-null-referer-good",
            "password": "nullreferergood123",
            "role": "user",
            "csrf_token": csrf_token,
        },
        headers=admin_ui_headers(origin="null", referer=f"{ADMIN_UI_ORIGIN}/admin/ui/users"),
        follow_redirects=False,
    )
    assert null_origin_same_referer.status_code == 303

    null_origin_no_referer = client.post(
        "/admin/ui/users/create",
        data={
            "username": "origin-null-no-referer-good",
            "password": "nullnoreferergood123",
            "role": "user",
            "csrf_token": csrf_token,
        },
        headers=admin_ui_headers(origin="null", referer=None),
        follow_redirects=False,
    )
    assert null_origin_no_referer.status_code == 403
    assert null_origin_no_referer.text == "Admin UI POST origin is not allowed"

    bad_referer = client.post(
        "/admin/ui/users/create",
        data={
            "username": "referer-bad",
            "password": "refererbad123",
            "role": "user",
            "csrf_token": csrf_token,
        },
        headers=admin_ui_headers(origin=None, referer="https://evil.example/admin/ui/users"),
        follow_redirects=False,
    )
    assert bad_referer.status_code == 403
    assert bad_referer.text == "Admin UI POST origin is not allowed"

    null_origin_bad_referer = client.post(
        "/admin/ui/users/create",
        data={
            "username": "origin-null-referer-bad",
            "password": "nullrefererbad123",
            "role": "user",
            "csrf_token": csrf_token,
        },
        headers=admin_ui_headers(origin="null", referer="https://evil.example/admin/ui/users"),
        follow_redirects=False,
    )
    assert null_origin_bad_referer.status_code == 403
    assert null_origin_bad_referer.text == "Admin UI POST origin is not allowed"


def test_admin_ui_login_allows_null_origin_without_referer(client):
    login_page = client.get("/admin/ui/login")
    assert login_page.status_code == 200
    csrf_token = extract_admin_ui_csrf_token(login_page.text)

    login_res = client.post(
        "/admin/ui/login",
        data={
            "username": "admin",
            "password": "adminpass123456",
            "next": "/admin/ui/users",
            "csrf_token": csrf_token,
        },
        headers=admin_ui_headers(origin="null", referer=None),
        follow_redirects=False,
    )
    assert login_res.status_code == 303
    assert login_res.headers["location"].startswith("/admin/ui")


def test_admin_ui_guard_failures_emit_security_counters(client):
    login_page = client.get("/admin/ui/login")
    csrf_token = extract_admin_ui_csrf_token(login_page.text)

    missing_csrf = client.post(
        "/admin/ui/login",
        data={"username": "admin", "password": "adminpass123456", "next": "/admin/ui/users"},
        headers=admin_ui_headers(),
        follow_redirects=False,
    )
    assert missing_csrf.status_code == 403

    wrong_origin = client.post(
        "/admin/ui/login",
        data={
            "username": "admin",
            "password": "adminpass123456",
            "next": "/admin/ui/users",
            "csrf_token": csrf_token,
        },
        headers=admin_ui_headers(origin="https://evil.example"),
        follow_redirects=False,
    )
    assert wrong_origin.status_code == 403

    admin_h = auth_headers(login(client, "admin", "adminpass123456"))
    metrics = client.get("/admin/metrics", headers=admin_h)
    assert metrics.status_code == 200, metrics.text
    counters = metrics.json()["counters"]
    assert counters["security.admin_ui.csrf_failed"] == 1
    assert counters["security.admin_ui.origin_failed"] == 1


def test_admin_ui_schedule_toggle_and_discovery_run_require_post_guards(client, monkeypatch):
    login_res = admin_ui_login(client, next_path="/admin/ui/scheduled-wakes")
    assert login_res.status_code == 303

    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)
    create_device_res = client.post(
        "/admin/devices",
        headers=admin_h,
        json={
            "name": "guard-box",
            "display_name": "Guard Box",
            "mac": "AA:BB:CC:DD:EE:14",
            "group_name": "Lab",
            "broadcast": "192.168.1.255",
            "source_ip": "192.168.1.14",
            "udp_port": 9,
            "check_method": "tcp",
            "check_target": "192.168.1.114",
            "check_port": 9,
        },
    )
    assert create_device_res.status_code == 201, create_device_res.text
    device_id = create_device_res.json()["id"]

    create_job_res = client.post(
        "/admin/scheduled-wakes",
        headers=admin_h,
        json={
            "device_id": device_id,
            "label": "Guard Wake",
            "enabled": True,
            "timezone": "UTC",
            "days_of_week": [DAY_NAMES[(datetime.now(UTC) + timedelta(minutes=5)).weekday()]],
            "local_time": (datetime.now(UTC) + timedelta(minutes=5)).strftime("%H:%M"),
        },
    )
    assert create_job_res.status_code == 201, create_job_res.text
    job_id = create_job_res.json()["id"]

    missing_toggle_token = client.post(
        f"/admin/ui/scheduled-wakes/{job_id}/toggle",
        data={"return_to": f"/admin/ui/scheduled-wakes?device_id={device_id}"},
        headers=admin_ui_headers(),
        follow_redirects=False,
    )
    assert missing_toggle_token.status_code == 403
    assert missing_toggle_token.text == "Invalid CSRF token"

    valid_toggle = admin_ui_post(
        client,
        f"/admin/ui/scheduled-wakes/{job_id}/toggle",
        form_page_path=f"/admin/ui/scheduled-wakes?device_id={device_id}",
        data={"return_to": f"/admin/ui/scheduled-wakes?device_id={device_id}"},
        follow_redirects=False,
    )
    assert valid_toggle.status_code == 303

    jobs_res = client.get("/admin/scheduled-wakes", headers=admin_h)
    assert jobs_res.status_code == 200, jobs_res.text
    toggled_job = next(row for row in jobs_res.json() if row["id"] == job_id)
    assert toggled_job["enabled"] is False

    monkeypatch.setattr(
        "app.admin_ui.discover_sender_bindings",
        lambda: [
            {
                "network_cidr": "192.168.1.0/24",
                "source_ip": "192.168.1.14",
                "interface": "eth0",
                "broadcast_ip": "192.168.1.255",
            }
        ],
    )
    monkeypatch.setattr("app.admin_ui._execute_discovery_run_ui", lambda *_args, **_kwargs: None)

    missing_discovery_token = client.post(
        "/admin/ui/discovery/run",
        data={"network_cidrs": "192.168.1.0/24"},
        headers=admin_ui_headers(),
        follow_redirects=False,
    )
    assert missing_discovery_token.status_code == 403
    assert missing_discovery_token.text == "Invalid CSRF token"

    valid_discovery = admin_ui_post(
        client,
        "/admin/ui/discovery/run",
        form_page_path="/admin/ui/discovery",
        data={"network_cidrs": "192.168.1.0/24"},
        follow_redirects=False,
    )
    assert valid_discovery.status_code == 303
    assert valid_discovery.headers["location"].startswith("/admin/ui/discovery?run_id=")


def test_admin_ui_login_and_crud_paths(client):
    login_res = admin_ui_login(client, next_path="/admin/ui/users")
    assert login_res.status_code == 303
    assert login_res.headers["location"] == "/admin/ui/users"
    set_cookie = login_res.headers.get("set-cookie", "")
    assert "admin_session" in set_cookie
    assert "Path=/admin/ui" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "samesite=strict" in set_cookie.lower()

    users_page = client.get("/admin/ui/users")
    assert users_page.status_code == 200
    assert "Create User" in users_page.text

    create_user = admin_ui_post(
        client,
        "/admin/ui/users/create",
        form_page_path="/admin/ui/users",
        data={"username": "uiuser", "password": "uiuserpassword12", "role": "user"},
        follow_redirects=False,
    )
    assert create_user.status_code == 303
    assert "/admin/ui/users" in create_user.headers["location"]

    users_page_after = client.get("/admin/ui/users")
    assert users_page_after.status_code == 200
    assert "uiuser" in users_page_after.text


def test_admin_ui_session_is_revoked_after_password_change(client):
    login_res = admin_ui_login(client, next_path="/admin/ui/users")
    assert login_res.status_code == 303

    users_page = client.get("/admin/ui/users")
    assert users_page.status_code == 200

    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)
    users = client.get("/admin/users", headers=admin_h)
    assert users.status_code == 200, users.text
    admin_id = next(row["id"] for row in users.json() if row["username"] == "admin")

    update = client.patch(
        f"/admin/users/{admin_id}",
        headers=admin_h,
        json={"password": "adminpassword7890"},
    )
    assert update.status_code == 200, update.text

    stale_session_res = client.get("/admin/ui/users", follow_redirects=False)
    assert stale_session_res.status_code == 303
    assert stale_session_res.headers["location"].startswith("/admin/ui/login")


def test_admin_ui_manual_provisioning_and_test_power_check(client, monkeypatch):
    # login via UI
    login_res = admin_ui_login(client, next_path="/admin/ui/devices")
    assert login_res.status_code == 303

    create_device = admin_ui_post(
        client,
        "/admin/ui/devices/create",
        form_page_path="/admin/ui/devices",
        data={
            "name": "UI-NAS",
            "display_name": "UI NAS",
            "mac": "AA:BB:CC:DD:EE:FF",
            "check_method": "tcp",
            "check_target": "192.168.1.50",
            "check_port": "22",
            "udp_port": "9",
            "group_name": "",
            "broadcast": "192.168.1.255",
            "subnet_cidr": "",
            "interface": "",
        },
        follow_redirects=False,
    )
    assert create_device.status_code == 303

    devices_page = client.get("/admin/ui/devices")
    assert devices_page.status_code == 200
    assert "UI-NAS" in devices_page.text

    # power-check test action on device page
    # parse device id from page by finding the first /test-power-check action
    match = re.search(r"/admin/ui/devices/([^/\"]+)/test-power-check", devices_page.text)
    assert match is not None
    device_id = match.group(1)

    update_device = admin_ui_post(
        client,
        f"/admin/ui/devices/{device_id}/update",
        form_page_path="/admin/ui/devices",
        data={
            "name": "UI-NAS",
            "display_name": "UI NAS",
            "mac": "AA:BB:CC:DD:EE:FF",
            "interface": "eth1",
            "source_ip": "192.168.1.10",
            "check_method": "tcp",
            "check_target": "192.168.1.50",
            "check_port": "22",
        },
        follow_redirects=False,
    )
    assert update_device.status_code == 303

    admin_token = login(client, "admin", "adminpass123456")
    devices_api = client.get("/admin/devices", headers={"authorization": f"Bearer {admin_token}"})
    assert devices_api.status_code == 200
    updated = [row for row in devices_api.json() if row["id"] == device_id]
    assert updated
    assert updated[0]["interface"] == "eth1"
    assert updated[0]["source_ip"] == "192.168.1.10"

    monkeypatch.setattr(
        "app.admin_ui.run_power_check",
        lambda *_args, **_kwargs: PowerCheckResult(method="tcp", result="on", detail="connected", latency_ms=7),
    )

    test_check = admin_ui_post(
        client,
        f"/admin/ui/devices/{device_id}/test-power-check",
        form_page_path="/admin/ui/devices",
        follow_redirects=False,
    )
    assert test_check.status_code == 303

    power_logs = client.get("/admin/ui/power-check-logs")
    assert power_logs.status_code == 200
    assert device_id in power_logs.text

    # invite flow is disabled and redirects to users page.
    create_user = admin_ui_post(
        client,
        "/admin/ui/users/create",
        form_page_path="/admin/ui/users",
        data={"username": "invitee", "password": "inviteepassword1", "role": "user"},
        follow_redirects=False,
    )
    assert create_user.status_code == 303

    invite_res = admin_ui_post(
        client,
        "/admin/ui/invites/create",
        form_page_path="/admin/ui/users",
        data={"username": "invitee"},
        follow_redirects=False,
    )
    assert invite_res.status_code == 303
    assert invite_res.headers["location"].startswith("/admin/ui/users?")


def test_admin_ui_scheduled_wake_flow(client):
    login_res = admin_ui_login(client, next_path="/admin/ui/scheduled-wakes")
    assert login_res.status_code == 303
    assert login_res.headers["location"] == "/admin/ui/scheduled-wakes"

    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)
    create_device_res = client.post(
        "/admin/devices",
        headers=admin_h,
        json={
            "name": "schedule-box",
            "display_name": "Schedule Box",
            "mac": "AA:BB:CC:DD:EE:12",
            "group_name": "Lab",
            "broadcast": "192.168.1.255",
            "source_ip": "192.168.1.12",
            "udp_port": 9,
            "check_method": "tcp",
            "check_target": "192.168.1.112",
            "check_port": 9,
        },
    )
    assert create_device_res.status_code == 201, create_device_res.text
    device_id = create_device_res.json()["id"]

    devices_page = client.get("/admin/ui/devices")
    assert devices_page.status_code == 200
    assert "Manage Schedules" in devices_page.text
    assert f"/admin/ui/scheduled-wakes?lang=en&amp;device_id={device_id}" in devices_page.text

    schedules_page = client.get(f"/admin/ui/scheduled-wakes?device_id={device_id}")
    assert schedules_page.status_code == 200
    assert "Scheduled Wakes" in schedules_page.text
    assert "Recent Scheduled Wake Runs" in schedules_page.text

    create_schedule = admin_ui_post(
        client,
        "/admin/ui/scheduled-wakes/create",
        form_page_path=f"/admin/ui/scheduled-wakes/new?device_id={device_id}",
        data={
            **_future_schedule_form(device_id, label="Morning Boot"),
            "return_to": f"/admin/ui/scheduled-wakes?device_id={device_id}",
        },
        follow_redirects=False,
    )
    assert create_schedule.status_code == 303
    assert create_schedule.headers["location"].startswith("/admin/ui/scheduled-wakes?")

    jobs_res = client.get("/admin/scheduled-wakes", headers=admin_h)
    assert jobs_res.status_code == 200, jobs_res.text
    job = next(row for row in jobs_res.json() if row["device_id"] == device_id and row["label"] == "Morning Boot")
    job_id = job["id"]

    created_page = client.get(create_schedule.headers["location"])
    assert created_page.status_code == 200
    assert "Morning Boot" in created_page.text
    assert f"/admin/ui/scheduled-wakes/{job_id}/edit" in created_page.text

    edit_page = client.get(f"/admin/ui/scheduled-wakes/{job_id}/edit")
    assert edit_page.status_code == 200
    assert "Edit Scheduled Wake" in edit_page.text

    update_schedule = admin_ui_post(
        client,
        f"/admin/ui/scheduled-wakes/{job_id}/update",
        form_page_path=f"/admin/ui/scheduled-wakes/{job_id}/edit",
        data={
            **_future_schedule_form(device_id, label="Office Wake"),
            "return_to": f"/admin/ui/scheduled-wakes?device_id={device_id}",
        },
        follow_redirects=False,
    )
    assert update_schedule.status_code == 303

    updated_jobs_res = client.get("/admin/scheduled-wakes", headers=admin_h)
    assert updated_jobs_res.status_code == 200, updated_jobs_res.text
    updated_job = next(row for row in updated_jobs_res.json() if row["id"] == job_id)
    assert updated_job["label"] == "Office Wake"

    toggle_schedule = admin_ui_post(
        client,
        f"/admin/ui/scheduled-wakes/{job_id}/toggle",
        form_page_path=f"/admin/ui/scheduled-wakes?device_id={device_id}",
        data={"return_to": f"/admin/ui/scheduled-wakes?device_id={device_id}"},
        follow_redirects=False,
    )
    assert toggle_schedule.status_code == 303

    toggled_jobs_res = client.get("/admin/scheduled-wakes", headers=admin_h)
    assert toggled_jobs_res.status_code == 200, toggled_jobs_res.text
    toggled_job = next(row for row in toggled_jobs_res.json() if row["id"] == job_id)
    assert toggled_job["enabled"] is False
    assert toggled_job["next_run_at"] is None

    delete_schedule = admin_ui_post(
        client,
        f"/admin/ui/scheduled-wakes/{job_id}/delete",
        form_page_path=f"/admin/ui/scheduled-wakes?device_id={device_id}",
        data={"return_to": f"/admin/ui/scheduled-wakes?device_id={device_id}"},
        follow_redirects=False,
    )
    assert delete_schedule.status_code == 303

    jobs_after_delete = client.get("/admin/scheduled-wakes", headers=admin_h)
    assert jobs_after_delete.status_code == 200, jobs_after_delete.text
    assert all(row["id"] != job_id for row in jobs_after_delete.json())

    audit_res = client.get("/admin/audit-logs", headers=admin_h)
    assert audit_res.status_code == 200, audit_res.text
    actions = [row["action"] for row in audit_res.json()]
    assert "ui_create_scheduled_wake" in actions
    assert "ui_update_scheduled_wake" in actions
    assert "ui_delete_scheduled_wake" in actions


def test_admin_ui_scheduled_wake_history_and_validation_errors(client):
    login_res = admin_ui_login(client, next_path="/admin/ui/scheduled-wakes")
    assert login_res.status_code == 303

    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)
    create_device_res = client.post(
        "/admin/devices",
        headers=admin_h,
        json={
            "name": "history-box",
            "display_name": "History Box",
            "mac": "AA:BB:CC:DD:EE:13",
            "group_name": "Lab",
            "broadcast": "192.168.1.255",
            "source_ip": "192.168.1.13",
            "udp_port": 9,
            "check_method": "tcp",
            "check_target": "192.168.1.113",
            "check_port": 9,
        },
    )
    assert create_device_res.status_code == 201, create_device_res.text
    device_id = create_device_res.json()["id"]

    create_job_res = client.post(
        "/admin/scheduled-wakes",
        headers=admin_h,
        json={
            "device_id": device_id,
            "label": "History Wake",
            "enabled": True,
            "timezone": "UTC",
            "days_of_week": [DAY_NAMES[(datetime.now(UTC) + timedelta(minutes=5)).weekday()]],
            "local_time": (datetime.now(UTC) + timedelta(minutes=5)).strftime("%H:%M"),
        },
    )
    assert create_job_res.status_code == 201, create_job_res.text
    job_id = create_job_res.json()["id"]

    started_at = datetime.now(UTC)
    record_scheduled_wake_run(
        job_id=job_id,
        device_id=device_id,
        started_at=started_at.isoformat(),
        finished_at=(started_at + timedelta(seconds=1)).isoformat(),
        result="sent",
        detail="magic_packet_sent",
        wake_log_id=77,
    )

    history_page = client.get(f"/admin/ui/scheduled-wakes?device_id={device_id}")
    assert history_page.status_code == 200
    assert "History Wake" in history_page.text
    assert "magic_packet_sent" in history_page.text
    assert "sent" in history_page.text

    invalid_timezone = admin_ui_post(
        client,
        "/admin/ui/scheduled-wakes/create",
        form_page_path=f"/admin/ui/scheduled-wakes/new?device_id={device_id}",
        data={
            **_future_schedule_form(device_id),
            "timezone": "Mars/Olympus",
            "return_to": f"/admin/ui/scheduled-wakes?device_id={device_id}",
        },
        follow_redirects=False,
    )
    assert invalid_timezone.status_code == 303
    invalid_timezone_page = client.get(invalid_timezone.headers["location"])
    assert invalid_timezone_page.status_code == 200
    assert "Invalid timezone" in invalid_timezone_page.text

    invalid_time = admin_ui_post(
        client,
        "/admin/ui/scheduled-wakes/create",
        form_page_path=f"/admin/ui/scheduled-wakes/new?device_id={device_id}",
        data={
            **_future_schedule_form(device_id),
            "local_time": "25:99",
            "return_to": f"/admin/ui/scheduled-wakes?device_id={device_id}",
        },
        follow_redirects=False,
    )
    assert invalid_time.status_code == 303
    invalid_time_page = client.get(invalid_time.headers["location"])
    assert invalid_time_page.status_code == 200
    assert "local_time must use HH:MM" in invalid_time_page.text

    missing_days = admin_ui_post(
        client,
        "/admin/ui/scheduled-wakes/create",
        form_page_path=f"/admin/ui/scheduled-wakes/new?device_id={device_id}",
        data={
            "device_id": device_id,
            "label": "No days",
            "enabled": "1",
            "timezone": "UTC",
            "local_time": "07:30",
            "return_to": f"/admin/ui/scheduled-wakes?device_id={device_id}",
        },
        follow_redirects=False,
    )
    assert missing_days.status_code == 303
    missing_days_page = client.get(missing_days.headers["location"])
    assert missing_days_page.status_code == 200
    assert "Select at least one day" in missing_days_page.text

    unknown_device = admin_ui_post(
        client,
        "/admin/ui/scheduled-wakes/create",
        form_page_path="/admin/ui/scheduled-wakes/new",
        data={
            **_future_schedule_form("missing-device"),
            "return_to": "/admin/ui/scheduled-wakes",
        },
        follow_redirects=False,
    )
    assert unknown_device.status_code == 303
    unknown_device_page = client.get(unknown_device.headers["location"])
    assert unknown_device_page.status_code == 200
    assert "Device not found" in unknown_device_page.text


def test_admin_ui_device_membership_flow(client):
    login_res = admin_ui_login(client, next_path="/admin/ui/device-memberships")
    assert login_res.status_code == 303
    assert login_res.headers["location"] == "/admin/ui/device-memberships"

    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    create_user_res = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": "member-ui", "password": "memberuipassword12", "role": "user"},
    )
    assert create_user_res.status_code == 201, create_user_res.text
    user_id = create_user_res.json()["id"]

    create_device_res = client.post(
        "/admin/devices",
        headers=admin_h,
        json={
            "name": "nas-box",
            "display_name": "Living Room NAS",
            "mac": "AA:BB:CC:DD:EE:10",
            "group_name": "Core",
            "broadcast": "192.168.1.255",
            "source_ip": "192.168.1.2",
            "udp_port": 9,
            "check_method": "tcp",
            "check_target": "192.168.1.10",
            "check_port": 445,
        },
    )
    assert create_device_res.status_code == 201, create_device_res.text
    device_id = create_device_res.json()["id"]

    memberships_page = client.get("/admin/ui/device-memberships")
    assert memberships_page.status_code == 200
    assert "Device Access" in memberships_page.text
    assert "Grant Device Access" in memberships_page.text
    assert "/admin/ui/device-memberships/create" in memberships_page.text
    assert "/admin/ui/assignments" not in memberships_page.text

    legacy_page = client.get("/admin/ui/assignments")
    assert legacy_page.status_code == 404

    create_membership = admin_ui_post(
        client,
        "/admin/ui/device-memberships/create",
        form_page_path="/admin/ui/device-memberships",
        data={
            "user_id": str(user_id),
            "device_id": device_id,
            "can_view_status": "1",
            "can_request_shutdown": "1",
            "can_manage_schedule": "1",
            "is_favorite": "1",
            "sort_order": "7",
        },
        follow_redirects=False,
    )
    assert create_membership.status_code == 303
    assert create_membership.headers["location"].startswith("/admin/ui/device-memberships?")

    memberships_res = client.get("/admin/device-memberships", headers=admin_h)
    assert memberships_res.status_code == 200, memberships_res.text
    membership = next(
        row for row in memberships_res.json() if row["user_id"] == user_id and row["device_id"] == device_id
    )
    assert membership["can_view_status"] is True
    assert membership["can_wake"] is False
    assert membership["can_request_shutdown"] is True
    assert membership["can_manage_schedule"] is True
    assert membership["is_favorite"] is True
    assert membership["sort_order"] == 7

    memberships_page_after_create = client.get("/admin/ui/device-memberships")
    assert memberships_page_after_create.status_code == 200
    assert "member-ui" in memberships_page_after_create.text
    assert "Living Room NAS (nas-box)" in memberships_page_after_create.text
    assert "Remove access for &#x27;member-ui&#x27; to &#x27;Living Room NAS (nas-box)&#x27;?" in memberships_page_after_create.text

    update_membership = admin_ui_post(
        client,
        f"/admin/ui/device-memberships/{membership['id']}/update",
        form_page_path="/admin/ui/device-memberships",
        data={
            "can_wake": "1",
            "can_manage_schedule": "1",
            "sort_order": "2",
        },
        follow_redirects=False,
    )
    assert update_membership.status_code == 303

    updated_res = client.get("/admin/device-memberships", headers=admin_h)
    assert updated_res.status_code == 200, updated_res.text
    updated_membership = next(row for row in updated_res.json() if row["id"] == membership["id"])
    assert updated_membership["can_view_status"] is False
    assert updated_membership["can_wake"] is True
    assert updated_membership["can_request_shutdown"] is False
    assert updated_membership["can_manage_schedule"] is True
    assert updated_membership["is_favorite"] is False
    assert updated_membership["sort_order"] == 2

    delete_membership = admin_ui_post(
        client,
        f"/admin/ui/device-memberships/{membership['id']}/delete",
        form_page_path="/admin/ui/device-memberships",
        follow_redirects=False,
    )
    assert delete_membership.status_code == 303

    memberships_after_delete = client.get("/admin/device-memberships", headers=admin_h)
    assert memberships_after_delete.status_code == 200, memberships_after_delete.text
    assert all(row["id"] != membership["id"] for row in memberships_after_delete.json())

    audit_res = client.get("/admin/audit-logs", headers=admin_h)
    assert audit_res.status_code == 200, audit_res.text
    actions = [row["action"] for row in audit_res.json()]
    assert "ui_create_device_membership" in actions
    assert "ui_update_device_membership" in actions
    assert "ui_delete_device_membership" in actions


def test_admin_ui_device_membership_errors_are_visible(client):
    login_res = admin_ui_login(client, next_path="/admin/ui/device-memberships")
    assert login_res.status_code == 303

    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    create_user_res = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": "member-ui-errors", "password": "memberuierrors12", "role": "user"},
    )
    assert create_user_res.status_code == 201, create_user_res.text
    user_id = create_user_res.json()["id"]

    create_device_res = client.post(
        "/admin/devices",
        headers=admin_h,
        json={
            "name": "desktop-box",
            "display_name": "Office Desktop",
            "mac": "AA:BB:CC:DD:EE:11",
            "group_name": "Work",
            "broadcast": "192.168.1.255",
            "source_ip": "192.168.1.3",
            "udp_port": 9,
            "check_method": "tcp",
            "check_target": "192.168.1.11",
            "check_port": 22,
        },
    )
    assert create_device_res.status_code == 201, create_device_res.text
    device_id = create_device_res.json()["id"]

    bad_sort_order = admin_ui_post(
        client,
        "/admin/ui/device-memberships/create",
        form_page_path="/admin/ui/device-memberships",
        data={"user_id": str(user_id), "device_id": device_id, "sort_order": "not-a-number"},
        follow_redirects=False,
    )
    assert bad_sort_order.status_code == 303
    assert bad_sort_order.headers["location"].startswith("/admin/ui/device-memberships?")

    bad_sort_page = client.get(bad_sort_order.headers["location"])
    assert bad_sort_page.status_code == 200
    assert "sort_order must be integer" in bad_sort_page.text

    delete_missing = admin_ui_post(
        client,
        "/admin/ui/device-memberships/not-a-real-id/delete",
        form_page_path="/admin/ui/device-memberships",
        follow_redirects=False,
    )
    assert delete_missing.status_code == 303
    assert delete_missing.headers["location"].startswith("/admin/ui/device-memberships?")

    delete_missing_page = client.get(delete_missing.headers["location"])
    assert delete_missing_page.status_code == 200
    assert "Membership not found" in delete_missing_page.text


def test_admin_ui_german_language_switch(client):
    login_page = client.get("/admin/ui/login?lang=de")
    assert login_page.status_code == 200
    assert "Admin-Login" in login_page.text
    assert "admin_ui_lang=de" in login_page.headers.get("set-cookie", "")

    login_res = admin_ui_login(client, next_path="/admin/ui/users", lang="de", login_page_path="/admin/ui/login?lang=de")
    assert login_res.status_code == 303
    assert login_res.headers["location"] == "/admin/ui/users"

    users_page = client.get("/admin/ui/users")
    assert users_page.status_code == 200
    assert "Benutzer erstellen" in users_page.text


def test_admin_ui_login_next_path_is_sanitized(client):
    login_res = admin_ui_login(client, next_path="https://evil.example/phish")
    assert login_res.status_code == 303
    assert login_res.headers["location"] == "/admin/ui"


def test_admin_ui_login_rate_limit_enforced(client):
    settings = get_settings()
    old_limit = settings.login_rate_limit_per_minute
    settings.login_rate_limit_per_minute = 1
    try:
        first = admin_ui_login(client, password="wrong-password")
        assert first.status_code == 303

        second = admin_ui_login(client, password="wrong-password")
        assert second.status_code == 303
        assert second.headers["location"].startswith("/admin/ui/login?")

        blocked = client.get(second.headers["location"])
        assert blocked.status_code == 200
        assert "Too many login attempts" in blocked.text
    finally:
        settings.login_rate_limit_per_minute = old_limit


def test_admin_ui_sets_security_headers(client):
    response = client.get("/admin/ui/login")
    assert response.status_code == 200
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
    assert response.headers.get("referrer-policy") == "same-origin"
    assert "frame-ancestors 'none'" in response.headers.get("content-security-policy", "")


def test_admin_ui_login_cookie_secure_with_trusted_forwarded_proto(client):
    settings = get_settings()
    old_trust_proxy_headers = settings.trust_proxy_headers
    try:
        settings.trust_proxy_headers = True
        response = admin_ui_login(
            client,
            next_path="/admin/ui/users",
            headers={"x-forwarded-proto": "https"},
            origin="https://testserver",
        )
        assert response.status_code == 303
        assert "secure" in response.headers.get("set-cookie", "").lower()
    finally:
        settings.trust_proxy_headers = old_trust_proxy_headers


def test_admin_ui_login_cookie_does_not_trust_proto_header_by_default(client):
    response = admin_ui_login(client, next_path="/admin/ui/users", headers={"x-forwarded-proto": "https"})
    assert response.status_code == 303
    assert "secure" not in response.headers.get("set-cookie", "").lower()


def test_admin_ui_mfa_setup_page_shows_enrollment_data(client):
    login_res = admin_ui_login(client, next_path="/admin/ui/mfa")
    assert login_res.status_code == 303

    page = client.get("/admin/ui/mfa")
    assert page.status_code == 200
    assert "Set Up Authenticator App" in page.text
    assert "otpauth://totp/" in page.text

    encrypted_secret = _extract_hidden_input(page.text, "encrypted_secret")
    secret = decrypt_secret_value(encrypted_secret)
    assert secret
    assert "WakeFromFar" in page.text


def test_admin_ui_mfa_setup_requires_valid_totp(client):
    login_res = admin_ui_login(client, next_path="/admin/ui/mfa")
    assert login_res.status_code == 303

    page = client.get("/admin/ui/mfa")
    assert page.status_code == 200
    csrf_token = extract_admin_ui_csrf_token(page.text)
    encrypted_secret = _extract_hidden_input(page.text, "encrypted_secret")
    secret = decrypt_secret_value(encrypted_secret)

    invalid = client.post(
        "/admin/ui/mfa/setup",
        data={"encrypted_secret": encrypted_secret, "code": "000000", "csrf_token": csrf_token},
        headers=admin_ui_headers(),
        follow_redirects=False,
    )
    assert invalid.status_code == 303
    assert invalid.headers["location"].startswith("/admin/ui/mfa/setup?")
    user = get_user_by_username("admin")
    assert user is not None
    assert bool(user["mfa_enabled"]) is False

    valid = client.post(
        "/admin/ui/mfa/setup",
        data={"encrypted_secret": encrypted_secret, "code": generate_totp_code(secret), "csrf_token": csrf_token},
        headers=admin_ui_headers(),
        follow_redirects=False,
    )
    assert valid.status_code == 303
    assert valid.headers["location"].startswith("/admin/ui/mfa?")

    refreshed_user = get_user_by_username("admin")
    assert refreshed_user is not None
    assert bool(refreshed_user["mfa_enabled"]) is True
    assert refreshed_user["mfa_totp_secret_encrypted"]

    admin_h = auth_headers(login(client, "admin", "adminpass123456"))
    metrics = client.get("/admin/metrics", headers=admin_h)
    assert metrics.status_code == 200, metrics.text
    counters = metrics.json()["counters"]
    assert counters["security.admin_ui.mfa.verify_failed"] >= 1
    assert counters["security.admin_ui.mfa.setup_completed"] == 1


def test_admin_ui_mfa_verify_route_keeps_csrf_and_origin_protection(client):
    _enable_admin_mfa_for_tests()
    login_res = admin_ui_login(client, next_path="/admin/ui/users")
    assert login_res.status_code == 303
    assert login_res.headers["location"].startswith("/admin/ui/mfa/verify")

    verify_page = client.get("/admin/ui/mfa/verify")
    assert verify_page.status_code == 200
    csrf_token = extract_admin_ui_csrf_token(verify_page.text)

    missing_csrf = client.post(
        "/admin/ui/mfa/verify",
        data={"code": "123456"},
        headers=admin_ui_headers(),
        follow_redirects=False,
    )
    assert missing_csrf.status_code == 403
    assert missing_csrf.text == "Invalid CSRF token"

    wrong_origin = client.post(
        "/admin/ui/mfa/verify",
        data={"code": "123456", "csrf_token": csrf_token},
        headers=admin_ui_headers(origin="https://evil.example"),
        follow_redirects=False,
    )
    assert wrong_origin.status_code == 403
    assert wrong_origin.text == "Admin UI POST origin is not allowed"


def test_admin_ui_login_with_mfa_enabled_requires_pending_verify_state(client):
    secret = _enable_admin_mfa_for_tests()

    login_res = admin_ui_login(client, next_path="/admin/ui/users")
    assert login_res.status_code == 303
    assert login_res.headers["location"].startswith("/admin/ui/mfa/verify")
    assert client.cookies.get("admin_session") is None
    assert client.cookies.get("admin_pending_session")

    blocked = client.get("/admin/ui/users", follow_redirects=False)
    assert blocked.status_code == 303
    assert blocked.headers["location"].startswith("/admin/ui/mfa/verify")

    invalid = admin_ui_post(
        client,
        "/admin/ui/mfa/verify",
        form_page_path="/admin/ui/mfa/verify",
        data={"code": "000000"},
        follow_redirects=False,
    )
    assert invalid.status_code == 303
    assert invalid.headers["location"].startswith("/admin/ui/mfa/verify?")

    valid = admin_ui_post(
        client,
        "/admin/ui/mfa/verify",
        form_page_path="/admin/ui/mfa/verify",
        data={"code": generate_totp_code(secret)},
        follow_redirects=False,
    )
    assert valid.status_code == 303
    assert valid.headers["location"] == "/admin/ui/users"
    assert client.cookies.get("admin_session")
    assert client.cookies.get("admin_pending_session") is None

    users_page = client.get("/admin/ui/users")
    assert users_page.status_code == 200
    assert "Create User" in users_page.text

    admin_h = auth_headers(login(client, "admin", "adminpass123456"))
    metrics = client.get("/admin/metrics", headers=admin_h)
    assert metrics.status_code == 200, metrics.text
    counters = metrics.json()["counters"]
    assert counters["security.admin_ui.mfa.verify_started"] == 1
    assert counters["security.admin_ui.mfa.verify_failed"] >= 1
    assert counters["security.admin_ui.mfa.verify_success"] == 1


def test_admin_ui_expired_pending_mfa_state_is_rejected_safely(client):
    _enable_admin_mfa_for_tests()
    user = get_user_by_username("admin")
    assert user is not None

    expired_token = create_state_token(
        subject="admin",
        state_type="admin_ui_pending",
        expires_seconds=-1,
        extra_claims={"ver": int(user["token_version"] or 0), "purpose": "verify", "next": "/admin/ui/users"},
    )
    client.cookies.set("admin_pending_session", expired_token, path="/admin/ui")

    response = client.get("/admin/ui/mfa/verify", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/admin/ui/login?")

    admin_h = auth_headers(login(client, "admin", "adminpass123456"))
    metrics = client.get("/admin/metrics", headers=admin_h)
    assert metrics.status_code == 200, metrics.text
    assert metrics.json()["counters"]["security.admin_ui.mfa.pending_expired"] >= 1


def test_admin_ui_mfa_required_false_still_allows_password_only_login_for_non_enrolled_admin(client_factory):
    with client_factory(env_overrides={"ADMIN_MFA_REQUIRED": "false"}) as client:
        response = admin_ui_login(client, next_path="/admin/ui/users")
        assert response.status_code == 303
        assert response.headers["location"] == "/admin/ui/users"
        assert client.cookies.get("admin_session")


def test_admin_ui_mfa_required_true_forces_non_enrolled_admin_into_setup(client_factory):
    with client_factory(env_overrides={"ADMIN_MFA_REQUIRED": "true"}) as client:
        login_res = admin_ui_login(client, next_path="/admin/ui/users")
        assert login_res.status_code == 303
        assert login_res.headers["location"].startswith("/admin/ui/mfa/setup")
        assert client.cookies.get("admin_session") is None
        assert client.cookies.get("admin_pending_session")

        setup_page = client.get("/admin/ui/mfa/setup")
        assert setup_page.status_code == 200
        encrypted_secret = _extract_hidden_input(setup_page.text, "encrypted_secret")
        secret = decrypt_secret_value(encrypted_secret)

        blocked = client.get("/admin/ui/users", follow_redirects=False)
        assert blocked.status_code == 303
        assert blocked.headers["location"].startswith("/admin/ui/mfa/setup")

        completed = admin_ui_post(
            client,
            "/admin/ui/mfa/setup",
            form_page_path="/admin/ui/mfa/setup",
            data={"encrypted_secret": encrypted_secret, "code": generate_totp_code(secret)},
            follow_redirects=False,
        )
        assert completed.status_code == 303
        assert completed.headers["location"].startswith("/admin/ui/users?")
        assert client.cookies.get("admin_session")


def test_admin_ui_mfa_required_true_still_requires_verify_for_enrolled_admin(client_factory):
    with client_factory(env_overrides={"ADMIN_MFA_REQUIRED": "true"}) as client:
        secret = _enable_admin_mfa_for_tests()
        login_res = admin_ui_login(client, next_path="/admin/ui/users")
        assert login_res.status_code == 303
        assert login_res.headers["location"].startswith("/admin/ui/mfa/verify")

        verified = admin_ui_post(
            client,
            "/admin/ui/mfa/verify",
            form_page_path="/admin/ui/mfa/verify",
            data={"code": generate_totp_code(secret)},
            follow_redirects=False,
        )
        assert verified.status_code == 303
        assert verified.headers["location"] == "/admin/ui/users"


def test_admin_ui_mfa_verify_rate_limit_is_enforced(client):
    secret = _enable_admin_mfa_for_tests()
    settings = get_settings()
    old_limit = settings.admin_mfa_verify_rate_limit_per_minute
    settings.admin_mfa_verify_rate_limit_per_minute = 1
    try:
        login_res = admin_ui_login(client, next_path="/admin/ui/users")
        assert login_res.status_code == 303

        first = admin_ui_post(
            client,
            "/admin/ui/mfa/verify",
            form_page_path="/admin/ui/mfa/verify",
            data={"code": "000000"},
            follow_redirects=False,
        )
        assert first.status_code == 303

        second = admin_ui_post(
            client,
            "/admin/ui/mfa/verify",
            form_page_path="/admin/ui/mfa/verify",
            data={"code": generate_totp_code(secret)},
            follow_redirects=False,
        )
        assert second.status_code == 303
        assert second.headers["location"].startswith("/admin/ui/mfa/verify?")

        blocked = client.get(second.headers["location"])
        assert blocked.status_code == 200
        assert "Too many MFA verification attempts" in blocked.text
    finally:
        settings.admin_mfa_verify_rate_limit_per_minute = old_limit


def test_admin_api_login_remains_password_only_when_browser_mfa_is_enabled(client):
    _enable_admin_mfa_for_tests()

    browser_login = admin_ui_login(client, next_path="/admin/ui/users")
    assert browser_login.status_code == 303
    assert browser_login.headers["location"].startswith("/admin/ui/mfa/verify")

    api_login = client.post("/auth/login", json={"username": "admin", "password": "adminpass123456"})
    assert api_login.status_code == 200, api_login.text
    assert api_login.json()["token"]


def test_admin_cli_disable_mfa_resets_admin_browser_flow(client_factory):
    with client_factory(env_overrides={"ADMIN_MFA_REQUIRED": "true"}) as client:
        _enable_admin_mfa_for_tests()

        result = subprocess.run(
            [sys.executable, "-m", "app.cli", "admin-disable-mfa", "--username", "admin"],
            cwd=BACKEND_DIR,
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "Disabled MFA for admin 'admin'" in result.stdout

        user = get_user_by_username("admin")
        assert user is not None
        assert bool(user["mfa_enabled"]) is False
        assert user["mfa_totp_secret_encrypted"] is None

        login_res = admin_ui_login(client, next_path="/admin/ui/users")
        assert login_res.status_code == 303
        assert login_res.headers["location"].startswith("/admin/ui/mfa/setup")
