from __future__ import annotations

from app.power import PowerCheckResult

from .conftest import auth_headers, create_device_membership, login


def _setup_user_and_device(client, username: str = "mobile-admin-user"):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    user_res = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": username, "password": "mobileuserpassword123", "role": "user"},
    )
    assert user_res.status_code == 201, user_res.text
    user_id = user_res.json()["id"]

    device_res = client.post(
        "/admin/devices",
        headers=admin_h,
        json={
            "name": "Plex Server",
            "display_name": "Plex",
            "mac": "AA:BB:CC:11:22:33",
            "broadcast": "192.168.1.255",
            "source_ip": "192.168.1.2",
            "udp_port": 9,
            "check_method": "tcp",
            "check_target": "192.168.1.10",
            "check_port": 22,
        },
    )
    assert device_res.status_code == 201, device_res.text
    device_id = device_res.json()["id"]

    create_device_membership(client, admin_h, user_id=user_id, device_id=device_id)

    user_token = login(client, username, "mobileuserpassword123")
    user_h = auth_headers(user_token)
    return admin_h, user_h, device_id


def test_admin_mobile_events_requires_admin_role(client):
    _, user_h, _ = _setup_user_and_device(client, username="mobile-non-admin")

    res = client.get("/admin/mobile/events", headers=user_h)
    assert res.status_code == 403
    assert res.json()["detail"] == "Admin role required"


def test_admin_mobile_events_paginates_and_filters_wake_events(client, monkeypatch):
    admin_h, user_h, device_id = _setup_user_and_device(client, username="mobile-events")

    monkeypatch.setattr(
        "app.main.run_power_check",
        lambda *_args, **_kwargs: PowerCheckResult(method="tcp", result="off", detail="timeout", latency_ms=8),
    )
    monkeypatch.setattr("app.main.send_magic_packet", lambda *_args, **_kwargs: None)

    for _ in range(3):
        wake_res = client.post(f"/me/devices/{device_id}/wake", headers=user_h)
        assert wake_res.status_code == 200, wake_res.text
        assert wake_res.json()["result"] == "sent"

    first_page = client.get("/admin/mobile/events?type=wake&limit=2", headers=admin_h)
    assert first_page.status_code == 200, first_page.text
    first_items = first_page.json()
    assert len(first_items) == 2
    assert all(item["event_type"] == "wake_sent" for item in first_items)
    assert all(item["actor_username"] == "mobile-events" for item in first_items)
    assert all(item["server_id"] == device_id for item in first_items)

    cursor = first_items[-1]["id"]
    second_page = client.get(f"/admin/mobile/events?type=wake&limit=2&cursor={cursor}", headers=admin_h)
    assert second_page.status_code == 200, second_page.text
    second_items = second_page.json()
    assert len(second_items) >= 1
    assert all(item["id"] < cursor for item in second_items)
    assert all(item["event_type"] == "wake_sent" for item in second_items)

    all_ids = [item["id"] for item in first_items + second_items]
    assert len(set(all_ids)) == len(all_ids)
    assert len(all_ids) >= 3


def test_admin_mobile_events_rejects_unknown_type_filter(client):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    res = client.get("/admin/mobile/events?type=invalid", headers=admin_h)
    assert res.status_code == 400
    assert "Unsupported activity filter" in res.json()["detail"]


def test_admin_mobile_events_poll_metrics_emitted(client, monkeypatch):
    admin_h, user_h, device_id = _setup_user_and_device(client, username="mobile-metrics")

    monkeypatch.setattr(
        "app.main.run_power_check",
        lambda *_args, **_kwargs: PowerCheckResult(method="tcp", result="off", detail="timeout", latency_ms=4),
    )
    monkeypatch.setattr("app.main.send_magic_packet", lambda *_args, **_kwargs: None)

    wake_res = client.post(f"/me/devices/{device_id}/wake", headers=user_h)
    assert wake_res.status_code == 200, wake_res.text

    feed_res = client.get("/admin/mobile/events?type=wake&limit=10", headers=admin_h)
    assert feed_res.status_code == 200, feed_res.text

    metrics_res = client.get("/admin/metrics", headers=admin_h)
    assert metrics_res.status_code == 200, metrics_res.text
    counters = metrics_res.json()["counters"]
    assert counters.get("activity_feed.poll_requests", 0) >= 1
    assert counters.get("activity_feed.poll_errors", 0) == 0


def test_admin_mobile_events_poll_errors_metric_emitted(client, monkeypatch):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    def _raise_list_error(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("app.main.list_activity_events", _raise_list_error)

    feed_res = client.get("/admin/mobile/events?type=wake&limit=10", headers=admin_h)
    assert feed_res.status_code == 500
    assert feed_res.json()["detail"] == "Could not load activity events"

    metrics_res = client.get("/admin/metrics", headers=admin_h)
    assert metrics_res.status_code == 200, metrics_res.text
    counters = metrics_res.json()["counters"]
    assert counters.get("activity_feed.poll_requests", 0) >= 1
    assert counters.get("activity_feed.poll_errors", 0) >= 1
