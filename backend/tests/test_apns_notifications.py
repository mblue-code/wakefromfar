from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.apns import APNSHTTPResult, APNSNotificationService
from app.config import get_settings
from app.db import (
    get_user_by_username,
    list_notification_devices,
    reserve_notification_device_visible_alert,
)

from .conftest import auth_headers, login


def _setup_user_and_device(client, username: str = "apns-user"):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    user_res = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": username, "password": "apns-user-password", "role": "user"},
    )
    assert user_res.status_code == 201, user_res.text

    device_res = client.post(
        "/admin/devices",
        headers=admin_h,
        json={
            "name": "APNS Device",
            "display_name": "APNS Device",
            "mac": "AA:BB:CC:11:22:99",
            "broadcast": "192.168.1.255",
            "source_ip": "192.168.1.20",
            "udp_port": 9,
            "check_method": "tcp",
            "check_target": "192.168.1.21",
            "check_port": 22,
        },
    )
    assert device_res.status_code == 201, device_res.text
    device_id = device_res.json()["id"]

    assign_res = client.post(
        "/admin/assignments",
        headers=admin_h,
        json={"user_id": user_res.json()["id"], "device_id": device_id},
    )
    assert assign_res.status_code == 201, assign_res.text

    user_token = login(client, username, "apns-user-password")
    user_h = auth_headers(user_token)
    return admin_h, user_h, device_id


class _FakeTokenFactory:
    def bearer_token(self) -> str:
        return "test-provider-token"


class _FakeTransport:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def send_notification(self, *, device_token: str, headers: dict[str, str], payload: dict[str, object]) -> APNSHTTPResult:
        self.calls.append(
            {
                "device_token": device_token,
                "headers": headers,
                "payload": payload,
            }
        )
        return APNSHTTPResult(status_code=200, apns_id="test-apns-id")


class _StaticResultTransport:
    def __init__(self, result: APNSHTTPResult) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    def send_notification(self, *, device_token: str, headers: dict[str, str], payload: dict[str, object]) -> APNSHTTPResult:
        self.calls.append(
            {
                "device_token": device_token,
                "headers": headers,
                "payload": payload,
            }
        )
        return self.result


def test_apns_token_invalidation_only_targets_unregistered_tokens():
    assert APNSHTTPResult(status_code=410, reason="Unregistered").should_invalidate_token is True
    assert APNSHTTPResult(status_code=410, reason=None).should_invalidate_token is True
    assert APNSHTTPResult(status_code=400, reason="BadTopic").should_invalidate_token is False
    assert APNSHTTPResult(status_code=400, reason="DeviceTokenNotForTopic").should_invalidate_token is False
    assert APNSHTTPResult(status_code=400, reason="BadDeviceToken").should_invalidate_token is False


def test_apns_registration_upserts_installation_and_supports_delete(client):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    register_res = client.post(
        "/me/notification-devices/apns",
        headers=admin_h,
        json={
            "installation_id": "install-1",
            "token": "a" * 64,
            "app_bundle_id": "com.wakefromfar.iosclient",
            "environment": "development",
        },
    )
    assert register_res.status_code == 200, register_res.text
    assert register_res.json()["is_active"] is True

    create_user = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": "token-user", "password": "tokenuserpass123", "role": "user"},
    )
    assert create_user.status_code == 201, create_user.text
    user_token = login(client, "token-user", "tokenuserpass123")
    user_h = auth_headers(user_token)

    second_register_res = client.post(
        "/me/notification-devices/apns",
        headers=user_h,
        json={
            "installation_id": "install-1",
            "token": "b" * 64,
            "app_bundle_id": "com.wakefromfar.iosclient",
            "environment": "development",
        },
    )
    assert second_register_res.status_code == 200, second_register_res.text

    rows = list_notification_devices()
    assert len(rows) == 1
    assert rows[0]["installation_id"] == "install-1"
    assert rows[0]["token"] == "b" * 64
    assert rows[0]["user_id"] == get_user_by_username("token-user")["id"]
    assert int(rows[0]["is_active"]) == 1

    delete_res = client.delete("/me/notification-devices/apns/install-1", headers=user_h)
    assert delete_res.status_code == 204, delete_res.text

    rows = list_notification_devices()
    assert len(rows) == 1
    assert int(rows[0]["is_active"]) == 0


def test_shutdown_poke_request_sends_minimal_apns_alert_to_active_admin_devices(client, monkeypatch):
    admin_h, user_h, device_id = _setup_user_and_device(client, username="apns-alert-user")
    transport = _FakeTransport()
    settings = get_settings()

    register_res = client.post(
        "/me/notification-devices/apns",
        headers=admin_h,
        json={
            "installation_id": "admin-install",
            "token": "c" * 64,
            "app_bundle_id": "com.wakefromfar.iosclient",
            "environment": "development",
        },
    )
    assert register_res.status_code == 200, register_res.text

    monkeypatch.setattr(settings, "apns_enabled", True)
    monkeypatch.setattr(settings, "apns_topic", "com.wakefromfar.iosclient")
    monkeypatch.setattr(settings, "apns_environment", "development")
    monkeypatch.setattr(
        "app.main._get_apns_notification_service",
        lambda: APNSNotificationService(
            settings,
            token_factory=_FakeTokenFactory(),
            transport=transport,
        ),
    )

    create_res = client.post(
        f"/me/devices/{device_id}/shutdown-poke",
        headers=user_h,
        json={"message": "please shut the media box down"},
    )
    assert create_res.status_code == 201, create_res.text

    assert len(transport.calls) == 1
    delivered = transport.calls[0]
    assert delivered["device_token"] == "c" * 64
    assert delivered["headers"]["apns-topic"] == "com.wakefromfar.iosclient"
    assert delivered["headers"]["apns-push-type"] == "alert"
    payload = delivered["payload"]
    assert payload["aps"]["alert"]["body"] == "A shutdown request needs review."
    assert payload["wf"]["route"] == "admin_activity"
    assert "media box" not in str(payload).lower()
    assert "please shut" not in str(payload).lower()

    admin_id = int(get_user_by_username("admin")["id"])
    rows = list_notification_devices(user_id=admin_id)
    assert len(rows) == 1
    assert rows[0]["last_alert_sent_at"] is not None
    assert int(rows[0]["suppressed_shutdown_count"]) == 0


def test_shutdown_poke_hourly_cap_aggregates_suppressed_alerts(client, monkeypatch):
    admin_h, user_h, device_id = _setup_user_and_device(client, username="apns-aggregate-user")
    transport = _FakeTransport()
    settings = get_settings()
    now_ref = {"value": datetime(2026, 3, 5, 9, 0, tzinfo=UTC)}

    register_res = client.post(
        "/me/notification-devices/apns",
        headers=admin_h,
        json={
            "installation_id": "aggregate-install",
            "token": "d" * 64,
            "app_bundle_id": "com.wakefromfar.iosclient",
            "environment": "development",
        },
    )
    assert register_res.status_code == 200, register_res.text

    monkeypatch.setattr(settings, "apns_enabled", True)
    monkeypatch.setattr(settings, "apns_topic", "com.wakefromfar.iosclient")
    monkeypatch.setattr(settings, "apns_environment", "development")
    monkeypatch.setattr(settings, "apns_admin_alert_min_visible_interval_seconds", 3600)
    monkeypatch.setattr(
        "app.main._get_apns_notification_service",
        lambda: APNSNotificationService(
            settings,
            token_factory=_FakeTokenFactory(),
            transport=transport,
            now=lambda: now_ref["value"],
        ),
    )

    first_res = client.post(
        f"/me/devices/{device_id}/shutdown-poke",
        headers=user_h,
        json={"message": "first request"},
    )
    assert first_res.status_code == 201, first_res.text
    assert len(transport.calls) == 1

    now_ref["value"] = now_ref["value"] + timedelta(minutes=10)
    second_res = client.post(
        f"/me/devices/{device_id}/shutdown-poke",
        headers=user_h,
        json={"message": "second request"},
    )
    assert second_res.status_code == 201, second_res.text
    assert len(transport.calls) == 1

    admin_id = int(get_user_by_username("admin")["id"])
    rows = list_notification_devices(user_id=admin_id)
    assert len(rows) == 1
    assert int(rows[0]["suppressed_shutdown_count"]) == 1

    now_ref["value"] = now_ref["value"] + timedelta(minutes=51)
    third_res = client.post(
        f"/me/devices/{device_id}/shutdown-poke",
        headers=user_h,
        json={"message": "third request"},
    )
    assert third_res.status_code == 201, third_res.text
    assert len(transport.calls) == 2
    assert transport.calls[-1]["payload"]["aps"]["alert"]["body"] == "2 shutdown requests need review."

    rows = list_notification_devices(user_id=admin_id)
    assert int(rows[0]["suppressed_shutdown_count"]) == 0


def test_deactivated_apns_device_is_not_targeted_for_shutdown_alerts(client, monkeypatch):
    admin_h, user_h, device_id = _setup_user_and_device(client, username="apns-deactivated-user")
    transport = _FakeTransport()
    settings = get_settings()

    register_res = client.post(
        "/me/notification-devices/apns",
        headers=admin_h,
        json={
            "installation_id": "inactive-install",
            "token": "e" * 64,
            "app_bundle_id": "com.wakefromfar.iosclient",
            "environment": "development",
        },
    )
    assert register_res.status_code == 200, register_res.text

    delete_res = client.delete("/me/notification-devices/apns/inactive-install", headers=admin_h)
    assert delete_res.status_code == 204, delete_res.text

    monkeypatch.setattr(settings, "apns_enabled", True)
    monkeypatch.setattr(settings, "apns_topic", "com.wakefromfar.iosclient")
    monkeypatch.setattr(settings, "apns_environment", "development")
    monkeypatch.setattr(
        "app.main._get_apns_notification_service",
        lambda: APNSNotificationService(
            settings,
            token_factory=_FakeTokenFactory(),
            transport=transport,
        ),
    )

    create_res = client.post(
        f"/me/devices/{device_id}/shutdown-poke",
        headers=user_h,
        json={"message": "should not notify inactive install"},
    )
    assert create_res.status_code == 201, create_res.text

    assert transport.calls == []


def test_bad_apns_request_does_not_invalidate_registered_device(client, monkeypatch):
    admin_h, user_h, device_id = _setup_user_and_device(client, username="apns-bad-request-user")
    transport = _StaticResultTransport(APNSHTTPResult(status_code=400, reason="BadTopic"))
    settings = get_settings()

    register_res = client.post(
        "/me/notification-devices/apns",
        headers=admin_h,
        json={
            "installation_id": "bad-request-install",
            "token": "g" * 64,
            "app_bundle_id": "com.wakefromfar.iosclient",
            "environment": "development",
        },
    )
    assert register_res.status_code == 200, register_res.text

    monkeypatch.setattr(settings, "apns_enabled", True)
    monkeypatch.setattr(settings, "apns_topic", "com.wakefromfar.iosclient")
    monkeypatch.setattr(settings, "apns_environment", "development")
    monkeypatch.setattr(
        "app.main._get_apns_notification_service",
        lambda: APNSNotificationService(
            settings,
            token_factory=_FakeTokenFactory(),
            transport=transport,
        ),
    )

    create_res = client.post(
        f"/me/devices/{device_id}/shutdown-poke",
        headers=user_h,
        json={"message": "should not invalidate on bad topic"},
    )
    assert create_res.status_code == 201, create_res.text

    admin_id = int(get_user_by_username("admin")["id"])
    rows = list_notification_devices(user_id=admin_id)
    assert len(rows) == 1
    assert int(rows[0]["is_active"]) == 1
    assert rows[0]["invalidation_reason"] is None


def test_visible_alert_reservation_is_atomic_for_the_same_device(client):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    register_res = client.post(
        "/me/notification-devices/apns",
        headers=admin_h,
        json={
            "installation_id": "atomic-install",
            "token": "f" * 64,
            "app_bundle_id": "com.wakefromfar.iosclient",
            "environment": "development",
        },
    )
    assert register_res.status_code == 200, register_res.text

    admin_id = int(get_user_by_username("admin")["id"])
    rows = list_notification_devices(user_id=admin_id)
    assert len(rows) == 1
    device_id = str(rows[0]["id"])
    reserved_at = datetime(2026, 3, 6, 10, 0, tzinfo=UTC).isoformat()

    first_reserved = reserve_notification_device_visible_alert(
        device_id,
        min_interval_seconds=3600,
        reserved_at=reserved_at,
    )
    second_reserved = reserve_notification_device_visible_alert(
        device_id,
        min_interval_seconds=3600,
        reserved_at=reserved_at,
    )

    assert first_reserved is True
    assert second_reserved is False
