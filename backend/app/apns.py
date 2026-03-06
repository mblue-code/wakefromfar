from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Callable

import httpx
import jwt

from .config import Settings
from .db import (
    increment_notification_device_suppressed_shutdown_count,
    invalidate_notification_device,
    list_active_admin_notification_devices,
    record_notification_device_alert_sent,
    release_notification_device_visible_alert_reservation,
    reserve_notification_device_visible_alert,
)


class APNSConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True)
class APNSDeliveryResult:
    sent_count: int = 0
    suppressed_count: int = 0
    invalidated_count: int = 0
    failed_count: int = 0


@dataclass(frozen=True)
class APNSHTTPResult:
    status_code: int
    reason: str | None = None
    apns_id: str | None = None

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def should_invalidate_token(self) -> bool:
        return self.status_code == 410 or (self.reason or "").strip() == "Unregistered"


class APNSProviderTokenFactory:
    def __init__(self, settings: Settings, now: Callable[[], datetime] | None = None) -> None:
        self._settings = settings
        self._now = now or (lambda: datetime.now(UTC))
        self._cached_token: str | None = None
        self._cached_until: datetime | None = None

    def bearer_token(self) -> str:
        if self._cached_token and self._cached_until and self._now() < self._cached_until:
            return self._cached_token

        private_key = self._settings.apns_private_key_text
        if not private_key:
            raise APNSConfigurationError("APNS private key is not configured")
        if not self._settings.apns_team_id or not self._settings.apns_key_id:
            raise APNSConfigurationError("APNS team ID and key ID must be configured")

        issued_at = int(self._now().timestamp())
        token = jwt.encode(
            {"iss": self._settings.apns_team_id, "iat": issued_at},
            private_key,
            algorithm="ES256",
            headers={"kid": self._settings.apns_key_id},
        )
        self._cached_token = token
        self._cached_until = self._now() + timedelta(minutes=50)
        return token


class APNSHTTPTransport:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def send_notification(
        self,
        *,
        device_token: str,
        headers: dict[str, str],
        payload: dict[str, object],
    ) -> APNSHTTPResult:
        base_url = (
            "https://api.sandbox.push.apple.com"
            if self._settings.apns_environment == "development"
            else "https://api.push.apple.com"
        )
        with httpx.Client(http2=True, timeout=10.0) as client:
            response = client.post(
                f"{base_url}/3/device/{device_token}",
                headers=headers,
                json=payload,
            )
        reason = None
        if response.text:
            try:
                reason = response.json().get("reason")
            except ValueError:
                reason = response.text.strip() or None
        return APNSHTTPResult(
            status_code=response.status_code,
            reason=reason,
            apns_id=response.headers.get("apns-id"),
        )


class APNSNotificationService:
    def __init__(
        self,
        settings: Settings,
        *,
        token_factory: APNSProviderTokenFactory | None = None,
        transport: APNSHTTPTransport | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._settings = settings
        self._now = now or (lambda: datetime.now(UTC))
        self._token_factory = token_factory or APNSProviderTokenFactory(settings, now=self._now)
        self._transport = transport or APNSHTTPTransport(settings)

    def send_admin_shutdown_request_alerts(self) -> APNSDeliveryResult:
        if not self._settings.apns_enabled:
            return APNSDeliveryResult()
        if not self._settings.apns_topic:
            raise APNSConfigurationError("APNS topic is not configured")

        bearer_token = self._token_factory.bearer_token()
        rows = list_active_admin_notification_devices(
            provider="apns",
            platform="ios",
            environment=self._settings.apns_environment,
        )
        sent_count = 0
        suppressed_count = 0
        invalidated_count = 0
        failed_count = 0
        min_interval = max(0, self._settings.apns_admin_alert_min_visible_interval_seconds)
        for row in rows:
            device_id = str(row["id"])
            previous_last_alert_sent_at = str(row["last_alert_sent_at"] or "") or None
            reserved_at = self._now().isoformat()
            if not reserve_notification_device_visible_alert(
                device_id,
                min_interval_seconds=min_interval,
                reserved_at=reserved_at,
            ):
                increment_notification_device_suppressed_shutdown_count(str(row["id"]))
                suppressed_count += 1
                continue

            aggregate_count = int(row["suppressed_shutdown_count"] or 0) + 1
            result = self._transport.send_notification(
                device_token=str(row["token"]),
                headers={
                    "authorization": f"bearer {bearer_token}",
                    "apns-topic": self._settings.apns_topic,
                    "apns-push-type": "alert",
                    "apns-priority": "10",
                },
                payload=self._shutdown_request_payload(aggregate_count),
            )
            if result.is_success:
                record_notification_device_alert_sent(device_id, sent_at=reserved_at)
                sent_count += 1
                continue
            if result.should_invalidate_token:
                invalidate_notification_device(device_id, reason=result.reason)
                invalidated_count += 1
                continue
            release_notification_device_visible_alert_reservation(
                device_id,
                reserved_at=reserved_at,
                previous_last_alert_sent_at=previous_last_alert_sent_at,
            )
            failed_count += 1

        return APNSDeliveryResult(
            sent_count=sent_count,
            suppressed_count=suppressed_count,
            invalidated_count=invalidated_count,
            failed_count=failed_count,
        )

    def _shutdown_request_payload(self, aggregate_count: int) -> dict[str, object]:
        body = (
            "A shutdown request needs review."
            if aggregate_count <= 1
            else f"{aggregate_count} shutdown requests need review."
        )
        return {
            "aps": {
                "alert": {
                    "title": "WakeFromFar",
                    "body": body,
                },
                "sound": "default",
            },
            "wf": {
                "route": "admin_activity",
                "kind": "shutdown_request",
                "aggregate_count": aggregate_count,
            },
        }
