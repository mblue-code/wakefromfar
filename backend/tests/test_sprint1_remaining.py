from __future__ import annotations

from app.power import PowerCheckResult

from .conftest import auth_headers, create_device_membership, login


def test_manual_user_provisioning_flow(client):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    create_user_res = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": "eve", "password": "initialpassword12", "role": "user"},
    )
    assert create_user_res.status_code == 201, create_user_res.text

    # Manual credentials are immediately valid for normal login.
    eve_token = login(client, "eve", "initialpassword12")
    assert eve_token

    onboarding_res = client.post(
        "/onboarding/claim",
        json={"token": "unused", "password": "anothernewpass12"},
    )
    assert onboarding_res.status_code == 410


def test_invite_endpoints_are_disabled(client):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)
    create_invite_res = client.post(
        "/admin/invites",
        headers=admin_h,
        json={"username": "admin", "backend_url_hint": "http://relay.internal", "expires_in_hours": 4},
    )
    assert create_invite_res.status_code == 410

    list_invites_res = client.get("/admin/invites", headers=admin_h)
    assert list_invites_res.status_code == 410

    revoke_invite_res = client.post("/admin/invites/legacy-id/revoke", headers=admin_h)
    assert revoke_invite_res.status_code == 410


def test_admin_user_and_device_patch_delete(client):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    # Last-admin protection.
    admins = client.get("/admin/users", headers=admin_h).json()
    bootstrap_admin = next(row for row in admins if row["username"] == "admin")
    demote_last_admin_res = client.patch(
        f"/admin/users/{bootstrap_admin['id']}",
        headers=admin_h,
        json={"role": "user"},
    )
    assert demote_last_admin_res.status_code == 400

    create_user_res = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": "charlie", "password": "charliepassword1", "role": "user"},
    )
    assert create_user_res.status_code == 201, create_user_res.text
    charlie_id = create_user_res.json()["id"]

    patch_user_res = client.patch(
        f"/admin/users/{charlie_id}",
        headers=admin_h,
        json={"role": "admin", "password": "charliepassword2"},
    )
    assert patch_user_res.status_code == 200, patch_user_res.text
    assert patch_user_res.json()["role"] == "admin"

    # Updated password works.
    charlie_token = login(client, "charlie", "charliepassword2")
    assert charlie_token

    create_device_res = client.post(
        "/admin/devices",
        headers=admin_h,
        json={
            "name": "Workstation",
            "mac": "AA:AA:AA:AA:AA:01",
            "broadcast": "10.10.0.255",
            "udp_port": 9,
            "check_method": "tcp",
            "check_target": "10.10.0.20",
            "check_port": 22,
        },
    )
    assert create_device_res.status_code == 201, create_device_res.text
    device_id = create_device_res.json()["id"]

    patch_device_res = client.patch(
        f"/admin/devices/{device_id}",
        headers=admin_h,
        json={
            "name": "Workstation-Updated",
            "display_name": "Main Workstation",
            "mac": "AA:AA:AA:AA:AA:02",
            "check_target": "10.10.0.21",
            "check_port": 3389,
        },
    )
    assert patch_device_res.status_code == 200, patch_device_res.text
    assert patch_device_res.json()["name"] == "Workstation-Updated"
    assert patch_device_res.json()["display_name"] == "Main Workstation"
    assert patch_device_res.json()["mac"] == "aaaaaaaaaa02"
    assert patch_device_res.json()["check_port"] == 3389

    delete_device_res = client.delete(f"/admin/devices/{device_id}", headers=admin_h)
    assert delete_device_res.status_code == 200, delete_device_res.text
    assert delete_device_res.json() == {"ok": True}

    delete_user_res = client.delete(f"/admin/users/{charlie_id}", headers=admin_h)
    assert delete_user_res.status_code == 200, delete_user_res.text
    assert delete_user_res.json() == {"ok": True}


def test_password_change_revokes_existing_tokens(client):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    create_user_res = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": "revoked-user", "password": "initialpassword12", "role": "user"},
    )
    assert create_user_res.status_code == 201, create_user_res.text
    user_id = create_user_res.json()["id"]

    old_token = login(client, "revoked-user", "initialpassword12")
    old_headers = auth_headers(old_token)
    before_change = client.get("/me/devices", headers=old_headers)
    assert before_change.status_code == 200, before_change.text

    rotate_password_res = client.patch(
        f"/admin/users/{user_id}",
        headers=admin_h,
        json={"password": "newpassword456"},
    )
    assert rotate_password_res.status_code == 200, rotate_password_res.text

    old_token_after_change = client.get("/me/devices", headers=old_headers)
    assert old_token_after_change.status_code == 401, old_token_after_change.text

    new_token = login(client, "revoked-user", "newpassword456")
    after_change = client.get("/me/devices", headers=auth_headers(new_token))
    assert after_change.status_code == 200, after_change.text


def test_me_devices_triggers_background_power_check_for_stale_entries(client, monkeypatch):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    create_user_res = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": "dana", "password": "danapassword123", "role": "user"},
    )
    assert create_user_res.status_code == 201, create_user_res.text
    dana_id = create_user_res.json()["id"]

    create_device_res = client.post(
        "/admin/devices",
        headers=admin_h,
        json={
            "name": "NAS",
            "mac": "00:11:22:33:44:55",
            "broadcast": "192.168.10.255",
            "udp_port": 9,
            "check_method": "tcp",
            "check_target": "192.168.10.20",
            "check_port": 22,
        },
    )
    assert create_device_res.status_code == 201, create_device_res.text
    device_id = create_device_res.json()["id"]

    create_device_membership(client, admin_h, user_id=dana_id, device_id=device_id)

    calls: list[tuple] = []

    def fake_power_check(*_args, **_kwargs):
        calls.append(("called",))
        return PowerCheckResult(method="tcp", result="off", detail="timeout", latency_ms=9)

    monkeypatch.setattr("app.main.run_power_check", fake_power_check)

    dana_token = login(client, "dana", "danapassword123")
    dana_h = auth_headers(dana_token)
    me_devices_res = client.get("/me/devices", headers=dana_h)
    assert me_devices_res.status_code == 200, me_devices_res.text
    assert len(me_devices_res.json()) == 1
    assert me_devices_res.json()[0]["is_stale"] is True

    # Background task executes during request lifecycle in TestClient.
    assert len(calls) == 1

    power_logs_res = client.get("/admin/power-check-logs", headers=admin_h)
    assert power_logs_res.status_code == 200, power_logs_res.text
    assert any(row["device_id"] == device_id for row in power_logs_res.json())
