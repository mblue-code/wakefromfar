from __future__ import annotations

import re

from app.config import get_settings
from app.power import PowerCheckResult

from .conftest import login


def test_admin_ui_requires_login(client):
    response = client.get("/admin/ui", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/admin/ui/login")


def test_admin_ui_login_and_crud_paths(client):
    login_res = client.post(
        "/admin/ui/login",
        data={"username": "admin", "password": "adminpass123456", "next": "/admin/ui/users"},
        follow_redirects=False,
    )
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

    create_user = client.post(
        "/admin/ui/users/create",
        data={"username": "uiuser", "password": "uiuserpassword12", "role": "user"},
        follow_redirects=False,
    )
    assert create_user.status_code == 303
    assert "/admin/ui/users" in create_user.headers["location"]

    users_page_after = client.get("/admin/ui/users")
    assert users_page_after.status_code == 200
    assert "uiuser" in users_page_after.text


def test_admin_ui_invite_and_test_power_check(client, monkeypatch):
    # login via UI
    login_res = client.post(
        "/admin/ui/login",
        data={"username": "admin", "password": "adminpass123456", "next": "/admin/ui/devices"},
        follow_redirects=False,
    )
    assert login_res.status_code == 303

    create_device = client.post(
        "/admin/ui/devices/create",
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

    update_device = client.post(
        f"/admin/ui/devices/{device_id}/update",
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

    test_check = client.post(f"/admin/ui/devices/{device_id}/test-power-check", follow_redirects=False)
    assert test_check.status_code == 303

    power_logs = client.get("/admin/ui/power-check-logs")
    assert power_logs.status_code == 200
    assert device_id in power_logs.text

    # create invite from UI and ensure QR/link are rendered
    create_user = client.post(
        "/admin/ui/users/create",
        data={"username": "invitee", "password": "inviteepassword1", "role": "user"},
        follow_redirects=False,
    )
    assert create_user.status_code == 303

    invite_res = client.post(
        "/admin/ui/invites/create",
        data={"username": "invitee", "backend_url_hint": "http://relay.local:8080", "expires_in_hours": "12"},
    )
    assert invite_res.status_code == 200
    assert "wakefromfar://claim?token=" in invite_res.text
    assert "quickchart.io/qr" in invite_res.text


def test_admin_ui_german_language_switch(client):
    login_page = client.get("/admin/ui/login?lang=de")
    assert login_page.status_code == 200
    assert "Admin-Login" in login_page.text
    assert "admin_ui_lang=de" in login_page.headers.get("set-cookie", "")

    login_res = client.post(
        "/admin/ui/login",
        data={"username": "admin", "password": "adminpass123456", "next": "/admin/ui/users"},
        follow_redirects=False,
    )
    assert login_res.status_code == 303
    assert login_res.headers["location"] == "/admin/ui/users"

    users_page = client.get("/admin/ui/users")
    assert users_page.status_code == 200
    assert "Benutzer erstellen" in users_page.text


def test_admin_ui_login_next_path_is_sanitized(client):
    login_res = client.post(
        "/admin/ui/login",
        data={"username": "admin", "password": "adminpass123456", "next": "https://evil.example/phish"},
        follow_redirects=False,
    )
    assert login_res.status_code == 303
    assert login_res.headers["location"] == "/admin/ui"


def test_admin_ui_login_rate_limit_enforced(client):
    settings = get_settings()
    old_limit = settings.login_rate_limit_per_minute
    settings.login_rate_limit_per_minute = 1
    try:
        first = client.post(
            "/admin/ui/login",
            data={"username": "admin", "password": "wrong-password", "next": "/admin/ui"},
            follow_redirects=False,
        )
        assert first.status_code == 303

        second = client.post(
            "/admin/ui/login",
            data={"username": "admin", "password": "wrong-password", "next": "/admin/ui"},
            follow_redirects=False,
        )
        assert second.status_code == 303
        assert second.headers["location"].startswith("/admin/ui/login?")

        blocked = client.get(second.headers["location"])
        assert blocked.status_code == 200
        assert "Too many login attempts" in blocked.text
    finally:
        settings.login_rate_limit_per_minute = old_limit
