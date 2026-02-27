from __future__ import annotations

from app.power import PowerCheckResult

from .conftest import auth_headers, login


def test_new_endpoints_smoke(client, monkeypatch):
    health_res = client.get("/health")
    assert health_res.status_code == 200
    assert health_res.json() == {"ok": "true"}

    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    user_res = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": "bob", "password": "bobpassword1234", "role": "user"},
    )
    assert user_res.status_code == 201, user_res.text
    user_id = user_res.json()["id"]

    users_res = client.get("/admin/users", headers=admin_h)
    assert users_res.status_code == 200, users_res.text
    assert any(row["username"] == "bob" for row in users_res.json())

    device_res = client.post(
        "/admin/devices",
        headers=admin_h,
        json={
            "name": "Lab-PC",
            "mac": "10:20:30:40:50:60",
            "broadcast": "10.0.0.255",
            "source_ip": "10.0.0.2",
            "udp_port": 9,
            "check_method": "tcp",
            "check_target": "10.0.0.10",
            "check_port": 3389,
        },
    )
    assert device_res.status_code == 201, device_res.text
    device_id = device_res.json()["id"]

    devices_res = client.get("/admin/devices", headers=admin_h)
    assert devices_res.status_code == 200, devices_res.text
    assert any(row["id"] == device_id and row["source_ip"] == "10.0.0.2" for row in devices_res.json())

    assign_res = client.post(
        "/admin/assignments",
        headers=admin_h,
        json={"user_id": user_id, "device_id": device_id},
    )
    assert assign_res.status_code == 201, assign_res.text

    assignments_res = client.get("/admin/assignments", headers=admin_h)
    assert assignments_res.status_code == 200, assignments_res.text
    assert any(row["user_id"] == user_id and row["device_id"] == device_id for row in assignments_res.json())

    invite_res = client.post(
        "/admin/invites",
        headers=admin_h,
        json={"username": "bob", "backend_url_hint": "http://relay.local", "expires_in_hours": 12},
    )
    assert invite_res.status_code == 201, invite_res.text
    invite_id = invite_res.json()["id"]
    assert invite_res.json()["token"]

    invites_res = client.get("/admin/invites", headers=admin_h)
    assert invites_res.status_code == 200, invites_res.text
    assert any(row["id"] == invite_id for row in invites_res.json())

    revoke_res = client.post(f"/admin/invites/{invite_id}/revoke", headers=admin_h)
    assert revoke_res.status_code == 200, revoke_res.text

    user_token = login(client, "bob", "bobpassword1234")
    user_h = auth_headers(user_token)

    me_devices_res = client.get("/me/devices", headers=user_h)
    assert me_devices_res.status_code == 200, me_devices_res.text
    assert len(me_devices_res.json()) == 1
    assert me_devices_res.json()[0]["id"] == device_id

    monkeypatch.setattr(
        "app.main.run_power_check",
        lambda *_args, **_kwargs: PowerCheckResult(method="tcp", result="off", detail="timeout", latency_ms=110),
    )
    monkeypatch.setattr("app.main.send_magic_packet", lambda *_args, **_kwargs: None)

    power_res = client.post(f"/me/devices/{device_id}/power-check", headers=user_h)
    assert power_res.status_code == 200, power_res.text
    assert power_res.json()["result"] == "off"

    wake_res = client.post(f"/me/devices/{device_id}/wake", headers=user_h)
    assert wake_res.status_code == 200, wake_res.text
    assert wake_res.json()["result"] == "sent"

    wake_logs_res = client.get("/admin/wake-logs", headers=admin_h)
    assert wake_logs_res.status_code == 200, wake_logs_res.text
    assert any(row["host_id"] == device_id for row in wake_logs_res.json())

    power_logs_res = client.get("/admin/power-check-logs", headers=admin_h)
    assert power_logs_res.status_code == 200, power_logs_res.text
    assert any(row["device_id"] == device_id for row in power_logs_res.json())
