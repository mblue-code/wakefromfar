from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from app.db import record_scheduled_wake_run
from app.config import get_settings
from app.power import PowerCheckResult

from .conftest import auth_headers, login

DAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


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


def test_admin_ui_requires_login(client):
    response = client.get("/admin/ui", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/admin/ui/login")


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


def test_admin_ui_session_is_revoked_after_password_change(client):
    login_res = client.post(
        "/admin/ui/login",
        data={"username": "admin", "password": "adminpass123456", "next": "/admin/ui/users"},
        follow_redirects=False,
    )
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

    # invite flow is disabled and redirects to users page.
    create_user = client.post(
        "/admin/ui/users/create",
        data={"username": "invitee", "password": "inviteepassword1", "role": "user"},
        follow_redirects=False,
    )
    assert create_user.status_code == 303

    invite_res = client.post(
        "/admin/ui/invites/create",
        data={"username": "invitee"},
        follow_redirects=False,
    )
    assert invite_res.status_code == 303
    assert invite_res.headers["location"].startswith("/admin/ui/users?")


def test_admin_ui_scheduled_wake_flow(client):
    login_res = client.post(
        "/admin/ui/login",
        data={"username": "admin", "password": "adminpass123456", "next": "/admin/ui/scheduled-wakes"},
        follow_redirects=False,
    )
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

    create_schedule = client.post(
        "/admin/ui/scheduled-wakes/create",
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

    update_schedule = client.post(
        f"/admin/ui/scheduled-wakes/{job_id}/update",
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

    toggle_schedule = client.post(
        f"/admin/ui/scheduled-wakes/{job_id}/toggle",
        data={"return_to": f"/admin/ui/scheduled-wakes?device_id={device_id}"},
        follow_redirects=False,
    )
    assert toggle_schedule.status_code == 303

    toggled_jobs_res = client.get("/admin/scheduled-wakes", headers=admin_h)
    assert toggled_jobs_res.status_code == 200, toggled_jobs_res.text
    toggled_job = next(row for row in toggled_jobs_res.json() if row["id"] == job_id)
    assert toggled_job["enabled"] is False
    assert toggled_job["next_run_at"] is None

    delete_schedule = client.post(
        f"/admin/ui/scheduled-wakes/{job_id}/delete",
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
    login_res = client.post(
        "/admin/ui/login",
        data={"username": "admin", "password": "adminpass123456", "next": "/admin/ui/scheduled-wakes"},
        follow_redirects=False,
    )
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

    invalid_timezone = client.post(
        "/admin/ui/scheduled-wakes/create",
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

    invalid_time = client.post(
        "/admin/ui/scheduled-wakes/create",
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

    missing_days = client.post(
        "/admin/ui/scheduled-wakes/create",
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

    unknown_device = client.post(
        "/admin/ui/scheduled-wakes/create",
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
    login_res = client.post(
        "/admin/ui/login",
        data={"username": "admin", "password": "adminpass123456", "next": "/admin/ui/device-memberships"},
        follow_redirects=False,
    )
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

    create_membership = client.post(
        "/admin/ui/device-memberships/create",
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

    update_membership = client.post(
        f"/admin/ui/device-memberships/{membership['id']}/update",
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

    delete_membership = client.post(
        f"/admin/ui/device-memberships/{membership['id']}/delete",
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
    login_res = client.post(
        "/admin/ui/login",
        data={"username": "admin", "password": "adminpass123456", "next": "/admin/ui/device-memberships"},
        follow_redirects=False,
    )
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

    bad_sort_order = client.post(
        "/admin/ui/device-memberships/create",
        data={"user_id": str(user_id), "device_id": device_id, "sort_order": "not-a-number"},
        follow_redirects=False,
    )
    assert bad_sort_order.status_code == 303
    assert bad_sort_order.headers["location"].startswith("/admin/ui/device-memberships?")

    bad_sort_page = client.get(bad_sort_order.headers["location"])
    assert bad_sort_page.status_code == 200
    assert "sort_order must be integer" in bad_sort_page.text

    delete_missing = client.post("/admin/ui/device-memberships/not-a-real-id/delete", follow_redirects=False)
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


def test_admin_ui_sets_security_headers(client):
    response = client.get("/admin/ui/login")
    assert response.status_code == 200
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
    assert response.headers.get("referrer-policy") == "no-referrer"
    assert "frame-ancestors 'none'" in response.headers.get("content-security-policy", "")


def test_admin_ui_login_cookie_secure_with_trusted_forwarded_proto(client):
    settings = get_settings()
    old_trust_proxy_headers = settings.trust_proxy_headers
    try:
        settings.trust_proxy_headers = True
        response = client.post(
            "/admin/ui/login",
            data={"username": "admin", "password": "adminpass123456", "next": "/admin/ui/users"},
            headers={"x-forwarded-proto": "https"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "secure" in response.headers.get("set-cookie", "").lower()
    finally:
        settings.trust_proxy_headers = old_trust_proxy_headers


def test_admin_ui_login_cookie_does_not_trust_proto_header_by_default(client):
    response = client.post(
        "/admin/ui/login",
        data={"username": "admin", "password": "adminpass123456", "next": "/admin/ui/users"},
        headers={"x-forwarded-proto": "https"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "secure" not in response.headers.get("set-cookie", "").lower()
