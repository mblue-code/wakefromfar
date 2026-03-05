from __future__ import annotations

from app.config import get_settings
from app.power import PowerCheckResult

from .conftest import auth_headers, login


def _setup_user_and_device(client, username: str = "harduser"):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    user_res = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": username, "password": "hardpassword123", "role": "user"},
    )
    assert user_res.status_code == 201, user_res.text
    user_id = user_res.json()["id"]

    device_res = client.post(
        "/admin/devices",
        headers=admin_h,
        json={
            "name": "Hard-Device",
            "mac": "AA:00:00:00:00:01",
            "broadcast": "192.168.1.255",
            "udp_port": 9,
            "check_method": "tcp",
            "check_target": "192.168.1.20",
            "check_port": 22,
        },
    )
    assert device_res.status_code == 201, device_res.text
    device_id = device_res.json()["id"]

    assign_res = client.post(
        "/admin/assignments",
        headers=admin_h,
        json={"user_id": user_id, "device_id": device_id},
    )
    assert assign_res.status_code == 201, assign_res.text
    return admin_h, user_id, device_id


def test_wake_rate_limit_enforced(client, monkeypatch):
    _, _, device_id = _setup_user_and_device(client, username="wake-limit")
    user_token = login(client, "wake-limit", "hardpassword123")
    user_h = auth_headers(user_token)

    settings = get_settings()
    old_limit = settings.wake_rate_limit_per_minute
    settings.wake_rate_limit_per_minute = 1

    monkeypatch.setattr(
        "app.main.run_power_check",
        lambda *_args, **_kwargs: PowerCheckResult(method="tcp", result="off", detail="timeout", latency_ms=4),
    )
    monkeypatch.setattr("app.main.send_magic_packet", lambda *_args, **_kwargs: None)

    first = client.post(f"/me/devices/{device_id}/wake", headers=user_h)
    assert first.status_code == 200, first.text

    second = client.post(f"/me/devices/{device_id}/wake", headers=user_h)
    assert second.status_code == 429
    assert second.json()["detail"] == "Too many wake attempts"

    settings.wake_rate_limit_per_minute = old_limit


def test_onboarding_endpoint_is_disabled(client):
    response = client.post("/onboarding/claim", json={"token": "not-a-real-token", "password": "newpassword1234"})
    assert response.status_code == 410


def test_audit_logs_metrics_and_diagnostics(client):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    create_user = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": "audited-user", "password": "auditedpassword", "role": "user"},
    )
    assert create_user.status_code == 201, create_user.text

    create_device = client.post(
        "/admin/devices",
        headers=admin_h,
        json={
            "name": "Misconfigured",
            "mac": "AA:00:00:00:00:02",
            "broadcast": "192.168.2.255",
            "udp_port": 9,
            "check_method": "tcp",
            "check_target": None,
            "check_port": None,
        },
    )
    assert create_device.status_code == 201, create_device.text

    audit = client.get("/admin/audit-logs", headers=admin_h)
    assert audit.status_code == 200, audit.text
    assert any(row["action"] == "create_user" for row in audit.json())
    assert any(row["action"] == "create_device" for row in audit.json())

    metrics = client.get("/admin/metrics", headers=admin_h)
    assert metrics.status_code == 200, metrics.text
    counters = metrics.json()["counters"]
    assert counters.get("admin_action.create_user", 0) >= 1
    assert counters.get("admin_action.create_device", 0) >= 1

    diagnostics = client.get("/admin/diagnostics/devices", headers=admin_h)
    assert diagnostics.status_code == 200, diagnostics.text
    misconfigured = [row for row in diagnostics.json() if row["name"] == "Misconfigured"]
    assert misconfigured
    assert any("missing" in hint.lower() for hint in misconfigured[0]["hints"])

    network_diagnostics = client.get("/admin/diagnostics/network", headers=admin_h)
    assert network_diagnostics.status_code == 200, network_diagnostics.text
    net_payload = network_diagnostics.json()
    assert "interfaces" in net_payload
    assert isinstance(net_payload["interfaces"], list)
    assert "has_multiple_active_networks" in net_payload


def test_pilot_metrics_endpoint_is_disabled(client):
    admin_h, _, _ = _setup_user_and_device(client, username="pilot-user")
    metrics = client.get("/admin/pilot-metrics", headers=admin_h)
    assert metrics.status_code == 410, metrics.text


def test_admin_password_policy_is_stricter_than_user_policy(client):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    create_user = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": "policy-user", "password": "123456", "role": "user"},
    )
    assert create_user.status_code == 201, create_user.text
    user_id = create_user.json()["id"]

    create_admin_with_short_password = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": "policy-admin", "password": "123456", "role": "admin"},
    )
    assert create_admin_with_short_password.status_code == 400

    promote_without_password_rotation = client.patch(
        f"/admin/users/{user_id}",
        headers=admin_h,
        json={"role": "admin"},
    )
    assert promote_without_password_rotation.status_code == 400

    promote_with_admin_password = client.patch(
        f"/admin/users/{user_id}",
        headers=admin_h,
        json={"role": "admin", "password": "123456789012"},
    )
    assert promote_with_admin_password.status_code == 200, promote_with_admin_password.text
