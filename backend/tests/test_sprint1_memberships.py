from __future__ import annotations

from app.power import PowerCheckResult

from .conftest import auth_headers, create_device_membership, login


def _setup_user_and_devices(client, username: str = "member-user"):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    user_res = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": username, "password": "memberpassword123", "role": "user"},
    )
    assert user_res.status_code == 201, user_res.text
    user_id = user_res.json()["id"]

    first_device_res = client.post(
        "/admin/devices",
        headers=admin_h,
        json={
            "name": "alpha-box",
            "display_name": "Alpha Box",
            "mac": "AA:BB:CC:DD:EE:01",
            "broadcast": "192.168.1.255",
            "source_ip": "192.168.1.2",
            "udp_port": 9,
            "check_method": "tcp",
            "check_target": "192.168.1.10",
            "check_port": 22,
        },
    )
    assert first_device_res.status_code == 201, first_device_res.text

    second_device_res = client.post(
        "/admin/devices",
        headers=admin_h,
        json={
            "name": "beta-box",
            "display_name": "Beta Box",
            "mac": "AA:BB:CC:DD:EE:02",
            "broadcast": "192.168.1.255",
            "source_ip": "192.168.1.3",
            "udp_port": 9,
            "check_method": "tcp",
            "check_target": "192.168.1.11",
            "check_port": 22,
        },
    )
    assert second_device_res.status_code == 201, second_device_res.text

    user_token = login(client, username, "memberpassword123")
    return admin_h, auth_headers(user_token), user_id, first_device_res.json()["id"], second_device_res.json()["id"]


def test_device_membership_crud_and_duplicate_protection(client):
    admin_h, _, user_id, device_id, _ = _setup_user_and_devices(client, username="membership-crud")

    create_res = client.post(
        "/admin/device-memberships",
        headers=admin_h,
        json={
            "user_id": user_id,
            "device_id": device_id,
            "can_view_status": True,
            "can_wake": False,
            "can_request_shutdown": True,
            "can_manage_schedule": False,
            "is_favorite": True,
            "sort_order": 7,
        },
    )
    assert create_res.status_code == 201, create_res.text
    membership = create_res.json()
    assert membership["user_id"] == user_id
    assert membership["device_id"] == device_id
    assert membership["can_wake"] is False
    assert membership["is_favorite"] is True
    assert membership["sort_order"] == 7

    duplicate_res = client.post(
        "/admin/device-memberships",
        headers=admin_h,
        json={"user_id": user_id, "device_id": device_id},
    )
    assert duplicate_res.status_code == 409, duplicate_res.text
    assert duplicate_res.json()["detail"] == "Device membership already exists"

    list_res = client.get("/admin/device-memberships", headers=admin_h)
    assert list_res.status_code == 200, list_res.text
    assert any(row["id"] == membership["id"] for row in list_res.json())

    update_res = client.patch(
        f"/admin/device-memberships/{membership['id']}",
        headers=admin_h,
        json={"can_wake": True, "can_manage_schedule": True, "is_favorite": False, "sort_order": 2},
    )
    assert update_res.status_code == 200, update_res.text
    updated = update_res.json()
    assert updated["can_wake"] is True
    assert updated["can_manage_schedule"] is True
    assert updated["is_favorite"] is False
    assert updated["sort_order"] == 2

    delete_res = client.delete(f"/admin/device-memberships/{membership['id']}", headers=admin_h)
    assert delete_res.status_code == 200, delete_res.text
    assert delete_res.json() == {"ok": True}

    list_after_delete = client.get("/admin/device-memberships", headers=admin_h)
    assert list_after_delete.status_code == 200, list_after_delete.text
    assert all(row["id"] != membership["id"] for row in list_after_delete.json())


def test_me_devices_uses_membership_visibility_and_returns_permission_fields(client):
    admin_h, user_h, user_id, visible_device_id, hidden_device_id = _setup_user_and_devices(client, username="visibility-user")

    create_device_membership(
        client,
        admin_h,
        user_id=user_id,
        device_id=visible_device_id,
        can_view_status=False,
        can_wake=True,
        can_request_shutdown=False,
        can_manage_schedule=False,
        is_favorite=True,
        sort_order=3,
    )

    me_devices_res = client.get("/me/devices", headers=user_h)
    assert me_devices_res.status_code == 200, me_devices_res.text
    payload = me_devices_res.json()
    assert [row["id"] for row in payload] == [visible_device_id]
    assert hidden_device_id not in {row["id"] for row in payload}
    assert payload[0]["is_favorite"] is True
    assert payload[0]["sort_order"] == 3
    assert payload[0]["permissions"] == {
        "can_view_status": False,
        "can_wake": True,
        "can_request_shutdown": False,
        "can_manage_schedule": False,
    }


def test_membership_permissions_are_enforced_for_user_device_actions(client, monkeypatch):
    admin_h, user_h, user_id, device_id, _ = _setup_user_and_devices(client, username="permission-user")

    create_device_membership(
        client,
        admin_h,
        user_id=user_id,
        device_id=device_id,
        can_view_status=False,
        can_wake=False,
        can_request_shutdown=False,
    )

    monkeypatch.setattr(
        "app.main.run_power_check",
        lambda *_args, **_kwargs: PowerCheckResult(method="tcp", result="off", detail="timeout", latency_ms=10),
    )
    monkeypatch.setattr("app.main.send_magic_packet", lambda *_args, **_kwargs: None)

    power_res = client.post(f"/me/devices/{device_id}/power-check", headers=user_h)
    assert power_res.status_code == 403, power_res.text
    assert power_res.json()["detail"] == "Power-check not permitted for this device"

    wake_res = client.post(f"/me/devices/{device_id}/wake", headers=user_h)
    assert wake_res.status_code == 403, wake_res.text
    assert wake_res.json()["detail"] == "Wake not permitted for this device"

    poke_res = client.post(
        f"/me/devices/{device_id}/shutdown-poke",
        headers=user_h,
        json={"message": "no access"},
    )
    assert poke_res.status_code == 403, poke_res.text
    assert poke_res.json()["detail"] == "Shutdown request not permitted for this device"


def test_me_device_preferences_patch_updates_only_membership_preferences(client):
    admin_h, user_h, user_id, device_id, _ = _setup_user_and_devices(client, username="preferences-user")

    membership = create_device_membership(
        client,
        admin_h,
        user_id=user_id,
        device_id=device_id,
        can_view_status=False,
        can_wake=False,
        can_request_shutdown=True,
        can_manage_schedule=False,
        is_favorite=False,
        sort_order=1,
    )

    update_res = client.patch(
        f"/me/devices/{device_id}/preferences",
        headers=user_h,
        json={"is_favorite": True, "sort_order": 9},
    )
    assert update_res.status_code == 200, update_res.text
    updated_device = update_res.json()
    assert updated_device["id"] == device_id
    assert updated_device["is_favorite"] is True
    assert updated_device["sort_order"] == 9
    assert updated_device["permissions"] == {
        "can_view_status": False,
        "can_wake": False,
        "can_request_shutdown": True,
        "can_manage_schedule": False,
    }

    list_res = client.get("/admin/device-memberships", headers=admin_h)
    assert list_res.status_code == 200, list_res.text
    stored = next(row for row in list_res.json() if row["id"] == membership["id"])
    assert stored["can_view_status"] is False
    assert stored["can_wake"] is False
    assert stored["can_request_shutdown"] is True
    assert stored["can_manage_schedule"] is False
    assert stored["is_favorite"] is True
    assert stored["sort_order"] == 9


def test_me_device_preferences_patch_rejects_negative_sort_order(client):
    admin_h, user_h, user_id, device_id, _ = _setup_user_and_devices(client, username="preferences-sort-order")

    create_device_membership(client, admin_h, user_id=user_id, device_id=device_id)

    res = client.patch(
        f"/me/devices/{device_id}/preferences",
        headers=user_h,
        json={"sort_order": -1},
    )
    assert res.status_code == 400, res.text
    assert res.json()["detail"] == "sort_order must be non-negative"


def test_me_device_preferences_patch_returns_404_for_unknown_user_device(client):
    _, user_h, _, _, _ = _setup_user_and_devices(client, username="preferences-404")

    res = client.patch(
        "/me/devices/not-visible/preferences",
        headers=user_h,
        json={"is_favorite": True},
    )
    assert res.status_code == 404, res.text
    assert res.json()["detail"] == "Device not found"


def test_me_devices_orders_favorites_before_grouped_non_favorites(client):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    user_res = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": "group-order-user", "password": "memberpassword123", "role": "user"},
    )
    assert user_res.status_code == 201, user_res.text
    user_id = user_res.json()["id"]

    devices: list[tuple[str, str, str | None]] = [
        ("zeta-box", "Zeta Box", None),
        ("beta-box", "Beta Box", "Work"),
        ("alpha-box", "Alpha Box", "Core"),
        ("omega-box", "Omega Box", "Lab"),
    ]
    device_ids: dict[str, str] = {}
    for index, (name, display_name, group_name) in enumerate(devices, start=1):
        device_res = client.post(
            "/admin/devices",
            headers=admin_h,
            json={
                "name": name,
                "display_name": display_name,
                "group_name": group_name,
                "mac": f"AA:BB:CC:DD:EE:{index:02d}",
                "broadcast": "192.168.1.255",
                "source_ip": "192.168.1.2",
                "udp_port": 9,
                "check_method": "tcp",
                "check_target": f"192.168.1.{10 + index}",
                "check_port": 22,
            },
        )
        assert device_res.status_code == 201, device_res.text
        device_ids[name] = device_res.json()["id"]

    create_device_membership(
        client,
        admin_h,
        user_id=user_id,
        device_id=device_ids["omega-box"],
        is_favorite=True,
        sort_order=20,
    )
    create_device_membership(
        client,
        admin_h,
        user_id=user_id,
        device_id=device_ids["alpha-box"],
        is_favorite=False,
        sort_order=7,
    )
    create_device_membership(
        client,
        admin_h,
        user_id=user_id,
        device_id=device_ids["beta-box"],
        is_favorite=False,
        sort_order=1,
    )
    create_device_membership(
        client,
        admin_h,
        user_id=user_id,
        device_id=device_ids["zeta-box"],
        is_favorite=False,
        sort_order=0,
    )

    user_token = login(client, "group-order-user", "memberpassword123")
    me_devices_res = client.get("/me/devices", headers=auth_headers(user_token))
    assert me_devices_res.status_code == 200, me_devices_res.text

    payload = me_devices_res.json()
    assert [row["name"] for row in payload] == ["omega-box", "alpha-box", "beta-box", "zeta-box"]


def test_admin_can_store_own_device_preferences_via_me_endpoint(client):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    device_res = client.post(
        "/admin/devices",
        headers=admin_h,
        json={
            "name": "admin-box",
            "display_name": "Admin Box",
            "group_name": "Office",
            "mac": "AA:BB:CC:DD:EE:44",
            "broadcast": "192.168.1.255",
            "source_ip": "192.168.1.2",
            "udp_port": 9,
            "check_method": "tcp",
            "check_target": "192.168.1.44",
            "check_port": 22,
        },
    )
    assert device_res.status_code == 201, device_res.text
    device_id = device_res.json()["id"]

    update_res = client.patch(
        f"/me/devices/{device_id}/preferences",
        headers=admin_h,
        json={"is_favorite": True, "sort_order": 4},
    )
    assert update_res.status_code == 200, update_res.text
    updated_device = update_res.json()
    assert updated_device["is_favorite"] is True
    assert updated_device["sort_order"] == 4
    assert updated_device["permissions"] == {
        "can_view_status": True,
        "can_wake": True,
        "can_request_shutdown": True,
        "can_manage_schedule": True,
    }

    me_devices_res = client.get("/me/devices", headers=admin_h)
    assert me_devices_res.status_code == 200, me_devices_res.text
    device_row = next(row for row in me_devices_res.json() if row["id"] == device_id)
    assert device_row["is_favorite"] is True
    assert device_row["sort_order"] == 4
    assert device_row["permissions"]["can_manage_schedule"] is True


def test_admin_can_access_any_device_without_membership(client, monkeypatch):
    admin_h, _, _, device_id, _ = _setup_user_and_devices(client, username="admin-bypass")

    monkeypatch.setattr(
        "app.main.run_power_check",
        lambda *_args, **_kwargs: PowerCheckResult(method="tcp", result="off", detail="timeout", latency_ms=15),
    )
    monkeypatch.setattr("app.main.send_magic_packet", lambda *_args, **_kwargs: None)

    admin_devices_res = client.get("/me/devices", headers=admin_h)
    assert admin_devices_res.status_code == 200, admin_devices_res.text
    admin_device = next(row for row in admin_devices_res.json() if row["id"] == device_id)
    assert admin_device["permissions"] == {
        "can_view_status": True,
        "can_wake": True,
        "can_request_shutdown": True,
        "can_manage_schedule": True,
    }
    assert admin_device["is_favorite"] is False
    assert admin_device["sort_order"] == 0

    power_res = client.post(f"/me/devices/{device_id}/power-check", headers=admin_h)
    assert power_res.status_code == 200, power_res.text

    wake_res = client.post(f"/me/devices/{device_id}/wake", headers=admin_h)
    assert wake_res.status_code == 200, wake_res.text

    poke_res = client.post(
        f"/me/devices/{device_id}/shutdown-poke",
        headers=admin_h,
        json={"message": "admin bypass"},
    )
    assert poke_res.status_code == 201, poke_res.text
