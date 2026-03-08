from __future__ import annotations

from app.config import get_settings

from .conftest import auth_headers, create_device_membership, login


def _setup_user_and_devices(client, username: str = "poke-user"):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    user_res = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": username, "password": "pokeuserpassword123", "role": "user"},
    )
    assert user_res.status_code == 201, user_res.text
    user_id = user_res.json()["id"]

    assigned_device_res = client.post(
        "/admin/devices",
        headers=admin_h,
        json={
            "name": "Plex Server",
            "display_name": "Plex",
            "mac": "AA:BB:CC:11:22:44",
            "broadcast": "192.168.1.255",
            "source_ip": "192.168.1.2",
            "udp_port": 9,
            "check_method": "tcp",
            "check_target": "192.168.1.10",
            "check_port": 22,
        },
    )
    assert assigned_device_res.status_code == 201, assigned_device_res.text
    assigned_device_id = assigned_device_res.json()["id"]

    unassigned_device_res = client.post(
        "/admin/devices",
        headers=admin_h,
        json={
            "name": "NAS Server",
            "display_name": "NAS",
            "mac": "AA:BB:CC:11:22:55",
            "broadcast": "192.168.1.255",
            "source_ip": "192.168.1.3",
            "udp_port": 9,
            "check_method": "tcp",
            "check_target": "192.168.1.11",
            "check_port": 22,
        },
    )
    assert unassigned_device_res.status_code == 201, unassigned_device_res.text
    unassigned_device_id = unassigned_device_res.json()["id"]

    create_device_membership(client, admin_h, user_id=user_id, device_id=assigned_device_id)

    user_token = login(client, username, "pokeuserpassword123")
    user_h = auth_headers(user_token)

    return admin_h, user_h, assigned_device_id, unassigned_device_id


def test_user_can_create_shutdown_poke_on_assigned_device(client):
    admin_h, user_h, assigned_device_id, unassigned_device_id = _setup_user_and_devices(client, username="poke-create")

    create_res = client.post(
        f"/me/devices/{assigned_device_id}/shutdown-poke",
        headers=user_h,
        json={"message": "done watching"},
    )
    assert create_res.status_code == 201, create_res.text
    created = create_res.json()
    assert created["status"] == "open"
    assert created["server_id"] == assigned_device_id
    assert created["message"] == "done watching"
    poke_id = created["id"]

    open_list_res = client.get("/admin/shutdown-pokes?status=open&limit=50", headers=admin_h)
    assert open_list_res.status_code == 200, open_list_res.text
    assert any(item["id"] == poke_id for item in open_list_res.json())

    poke_events_res = client.get("/admin/mobile/events?type=poke&limit=20", headers=admin_h)
    assert poke_events_res.status_code == 200, poke_events_res.text
    poke_events = poke_events_res.json()
    assert any(event["event_type"] == "shutdown_poke_requested" and event["target_id"] == poke_id for event in poke_events)

    unauthorized_device_res = client.post(
        f"/me/devices/{unassigned_device_id}/shutdown-poke",
        headers=user_h,
        json={"message": "this should fail"},
    )
    assert unauthorized_device_res.status_code == 404

    admin_unassigned_res = client.post(
        f"/me/devices/{unassigned_device_id}/shutdown-poke",
        headers=admin_h,
        json={"message": "admin can poke any device"},
    )
    assert admin_unassigned_res.status_code == 201, admin_unassigned_res.text


def test_admin_can_transition_shutdown_poke_seen_and_resolved(client):
    admin_h, user_h, assigned_device_id, _ = _setup_user_and_devices(client, username="poke-transition")

    create_res = client.post(
        f"/me/devices/{assigned_device_id}/shutdown-poke",
        headers=user_h,
        json={"message": "please shut it down"},
    )
    assert create_res.status_code == 201, create_res.text
    poke_id = create_res.json()["id"]

    seen_res = client.post(f"/admin/shutdown-pokes/{poke_id}/seen", headers=admin_h)
    assert seen_res.status_code == 200, seen_res.text
    assert seen_res.json()["status"] == "seen"
    assert seen_res.json()["seen_at"] is not None

    seen_res_repeat = client.post(f"/admin/shutdown-pokes/{poke_id}/seen", headers=admin_h)
    assert seen_res_repeat.status_code == 200, seen_res_repeat.text
    assert seen_res_repeat.json()["status"] == "seen"

    resolve_res = client.post(f"/admin/shutdown-pokes/{poke_id}/resolve", headers=admin_h)
    assert resolve_res.status_code == 200, resolve_res.text
    assert resolve_res.json()["status"] == "resolved"
    assert resolve_res.json()["resolved_at"] is not None
    assert resolve_res.json()["resolved_by_user_id"] is not None

    resolve_res_repeat = client.post(f"/admin/shutdown-pokes/{poke_id}/resolve", headers=admin_h)
    assert resolve_res_repeat.status_code == 200, resolve_res_repeat.text
    assert resolve_res_repeat.json()["status"] == "resolved"

    open_res = client.get("/admin/shutdown-pokes?status=open", headers=admin_h)
    assert open_res.status_code == 200, open_res.text
    assert all(item["id"] != poke_id for item in open_res.json())

    resolved_res = client.get("/admin/shutdown-pokes?status=resolved", headers=admin_h)
    assert resolved_res.status_code == 200, resolved_res.text
    assert any(item["id"] == poke_id for item in resolved_res.json())

    poke_events_res = client.get("/admin/mobile/events?type=poke&limit=50", headers=admin_h)
    assert poke_events_res.status_code == 200, poke_events_res.text
    poke_events = [event for event in poke_events_res.json() if event["target_id"] == poke_id]
    assert sum(1 for event in poke_events if event["event_type"] == "shutdown_poke_requested") == 1
    assert sum(1 for event in poke_events if event["event_type"] == "shutdown_poke_seen") == 1
    assert sum(1 for event in poke_events if event["event_type"] == "shutdown_poke_resolved") == 1

    audit_res = client.get("/admin/audit-logs", headers=admin_h)
    assert audit_res.status_code == 200, audit_res.text
    audit_actions = [item["action"] for item in audit_res.json()]
    assert "seen_shutdown_poke" in audit_actions
    assert "resolve_shutdown_poke" in audit_actions

    metrics_res = client.get("/admin/metrics", headers=admin_h)
    assert metrics_res.status_code == 200, metrics_res.text
    counters = metrics_res.json()["counters"]
    assert counters.get("activity_events.created", 0) >= 3
    assert counters.get("shutdown_pokes.open", 0) >= 1
    assert counters.get("shutdown_pokes.resolved", 0) >= 1


def test_shutdown_poke_admin_endpoints_require_admin_role(client):
    admin_h, user_h, assigned_device_id, _ = _setup_user_and_devices(client, username="poke-authz")

    create_res = client.post(
        f"/me/devices/{assigned_device_id}/shutdown-poke",
        headers=user_h,
        json={"message": "finishing up"},
    )
    assert create_res.status_code == 201, create_res.text
    poke_id = create_res.json()["id"]

    list_res = client.get("/admin/shutdown-pokes?status=open", headers=user_h)
    assert list_res.status_code == 403
    assert list_res.json()["detail"] == "Admin role required"

    seen_res = client.post(f"/admin/shutdown-pokes/{poke_id}/seen", headers=user_h)
    assert seen_res.status_code == 403

    resolve_res = client.post(f"/admin/shutdown-pokes/{poke_id}/resolve", headers=user_h)
    assert resolve_res.status_code == 403

    admin_create_res = client.post(
        f"/me/devices/{assigned_device_id}/shutdown-poke",
        headers=admin_h,
        json={"message": "admin can also request"},
    )
    assert admin_create_res.status_code == 201, admin_create_res.text


def test_shutdown_poke_request_rate_limit_enforced(client):
    _, user_h, assigned_device_id, _ = _setup_user_and_devices(client, username="poke-limit-user")
    settings = get_settings()
    old_limit = settings.shutdown_poke_request_rate_limit_per_minute
    settings.shutdown_poke_request_rate_limit_per_minute = 1

    first = client.post(
        f"/me/devices/{assigned_device_id}/shutdown-poke",
        headers=user_h,
        json={"message": "first"},
    )
    assert first.status_code == 201, first.text

    second = client.post(
        f"/me/devices/{assigned_device_id}/shutdown-poke",
        headers=user_h,
        json={"message": "second"},
    )
    assert second.status_code == 429
    assert second.json()["detail"] == "Too many shutdown requests"

    settings.shutdown_poke_request_rate_limit_per_minute = old_limit


def test_shutdown_poke_seen_and_resolve_rate_limit_enforced(client):
    admin_h, user_h, assigned_device_id, _ = _setup_user_and_devices(client, username="poke-limit-admin")
    settings = get_settings()
    old_seen_limit = settings.shutdown_poke_seen_rate_limit_per_minute
    old_resolve_limit = settings.shutdown_poke_resolve_rate_limit_per_minute
    settings.shutdown_poke_seen_rate_limit_per_minute = 1
    settings.shutdown_poke_resolve_rate_limit_per_minute = 1

    first_poke = client.post(
        f"/me/devices/{assigned_device_id}/shutdown-poke",
        headers=user_h,
        json={"message": "one"},
    )
    assert first_poke.status_code == 201, first_poke.text
    first_poke_id = first_poke.json()["id"]

    second_poke = client.post(
        f"/me/devices/{assigned_device_id}/shutdown-poke",
        headers=user_h,
        json={"message": "two"},
    )
    assert second_poke.status_code == 201, second_poke.text
    second_poke_id = second_poke.json()["id"]

    first_seen = client.post(f"/admin/shutdown-pokes/{first_poke_id}/seen", headers=admin_h)
    assert first_seen.status_code == 200, first_seen.text

    second_seen = client.post(f"/admin/shutdown-pokes/{second_poke_id}/seen", headers=admin_h)
    assert second_seen.status_code == 429
    assert second_seen.json()["detail"] == "Too many shutdown seen updates"

    first_resolve = client.post(f"/admin/shutdown-pokes/{first_poke_id}/resolve", headers=admin_h)
    assert first_resolve.status_code == 200, first_resolve.text

    second_resolve = client.post(f"/admin/shutdown-pokes/{second_poke_id}/resolve", headers=admin_h)
    assert second_resolve.status_code == 429
    assert second_resolve.json()["detail"] == "Too many shutdown resolve updates"

    settings.shutdown_poke_seen_rate_limit_per_minute = old_seen_limit
    settings.shutdown_poke_resolve_rate_limit_per_minute = old_resolve_limit
