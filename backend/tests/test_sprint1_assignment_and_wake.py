from __future__ import annotations

from app.power import PowerCheckResult

from .conftest import auth_headers, login


def _setup_user_and_device(client):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    user_res = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": "alice", "password": "alicepassword123", "role": "user"},
    )
    assert user_res.status_code == 201, user_res.text
    user_id = user_res.json()["id"]

    device_res = client.post(
        "/admin/devices",
        headers=admin_h,
        json={
            "name": "NAS",
            "display_name": "Home NAS",
            "mac": "AA:BB:CC:DD:EE:FF",
            "broadcast": "192.168.1.255",
            "udp_port": 9,
            "check_method": "tcp",
            "check_target": "192.168.1.10",
            "check_port": 22,
        },
    )
    assert device_res.status_code == 201, device_res.text
    device_id = device_res.json()["id"]

    user_token = login(client, "alice", "alicepassword123")
    return admin_h, user_id, device_id, user_token


def test_unassigned_user_cannot_wake_device(client):
    _, _, device_id, user_token = _setup_user_and_device(client)
    user_h = auth_headers(user_token)

    wake_res = client.post(f"/me/devices/{device_id}/wake", headers=user_h)
    assert wake_res.status_code == 404
    assert wake_res.json()["detail"] == "Host not found"


def test_wake_returns_already_on_and_does_not_send_magic_packet(client, monkeypatch):
    admin_h, user_id, device_id, user_token = _setup_user_and_device(client)
    user_h = auth_headers(user_token)

    assign_res = client.post(
        "/admin/assignments",
        headers=admin_h,
        json={"user_id": user_id, "device_id": device_id},
    )
    assert assign_res.status_code == 201, assign_res.text

    def fake_power_check(method: str, target: str | None, port: int | None, timeout_seconds: float = 1.5):
        assert method == "tcp"
        assert target == "192.168.1.10"
        assert port == 22
        return PowerCheckResult(method="tcp", result="on", detail="connected", latency_ms=3)

    def fail_if_send_called(*_args, **_kwargs):
        raise AssertionError("send_magic_packet must not run for already_on")

    monkeypatch.setattr("app.main.run_power_check", fake_power_check)
    monkeypatch.setattr("app.main.send_magic_packet", fail_if_send_called)

    wake_res = client.post(f"/me/devices/{device_id}/wake", headers=user_h)
    assert wake_res.status_code == 200, wake_res.text
    payload = wake_res.json()
    assert payload["result"] == "already_on"
    assert payload["precheck_state"] == "on"
    assert payload["sent_to"] is None


def test_wake_returns_sent_when_precheck_off_and_send_succeeds(client, monkeypatch):
    admin_h, user_id, device_id, user_token = _setup_user_and_device(client)
    user_h = auth_headers(user_token)

    assign_res = client.post(
        "/admin/assignments",
        headers=admin_h,
        json={"user_id": user_id, "device_id": device_id},
    )
    assert assign_res.status_code == 201, assign_res.text

    monkeypatch.setattr(
        "app.main.run_power_check",
        lambda *_args, **_kwargs: PowerCheckResult(
            method="tcp",
            result="off",
            detail="timeout",
            latency_ms=250,
        ),
    )

    sent_calls: list[tuple] = []

    def fake_send_magic_packet(mac: str, target_ip: str, udp_port: int = 9, interface: str | None = None):
        sent_calls.append((mac, target_ip, udp_port, interface))

    monkeypatch.setattr("app.main.send_magic_packet", fake_send_magic_packet)

    wake_res = client.post(f"/me/devices/{device_id}/wake", headers=user_h)
    assert wake_res.status_code == 200, wake_res.text
    payload = wake_res.json()
    assert payload["result"] == "sent"
    assert payload["precheck_state"] == "off"
    assert payload["sent_to"] == "192.168.1.255:9"
    assert len(sent_calls) == 1


def test_wake_returns_failed_when_send_raises(client, monkeypatch):
    admin_h, user_id, device_id, user_token = _setup_user_and_device(client)
    user_h = auth_headers(user_token)

    assign_res = client.post(
        "/admin/assignments",
        headers=admin_h,
        json={"user_id": user_id, "device_id": device_id},
    )
    assert assign_res.status_code == 201, assign_res.text

    monkeypatch.setattr(
        "app.main.run_power_check",
        lambda *_args, **_kwargs: PowerCheckResult(
            method="tcp",
            result="unknown",
            detail="dns_resolution_failed",
            latency_ms=None,
        ),
    )

    def failing_send_magic_packet(*_args, **_kwargs):
        raise OSError("simulated send failure")

    monkeypatch.setattr("app.main.send_magic_packet", failing_send_magic_packet)

    wake_res = client.post(f"/me/devices/{device_id}/wake", headers=user_h)
    assert wake_res.status_code == 200, wake_res.text
    payload = wake_res.json()
    assert payload["result"] == "failed"
    assert payload["precheck_state"] == "unknown"
    assert payload["error_detail"] == "simulated send failure"
