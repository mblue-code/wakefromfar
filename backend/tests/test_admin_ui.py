from __future__ import annotations

import re

from app.power import PowerCheckResult


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
    assert "admin_session" in login_res.headers.get("set-cookie", "")

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
