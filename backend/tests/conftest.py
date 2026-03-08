from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("APP_SECRET", "test-secret-value-1234-abcdef-5678")
    monkeypatch.setenv("ADMIN_USER", "admin")
    monkeypatch.setenv("ADMIN_PASS", "adminpass123456")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("DB_FILENAME", "test.db")
    monkeypatch.setenv("ENFORCE_IP_ALLOWLIST", "false")
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "false")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32,::1/128")
    monkeypatch.setenv("RATE_LIMIT_BACKEND", "memory")

    from app.config import get_settings
    from app.main import app
    from app.rate_limit import reset_rate_limiter_for_tests
    from app.telemetry import reset_counters

    get_settings.cache_clear()
    reset_rate_limiter_for_tests()
    reset_counters()

    with TestClient(app, client=("127.0.0.1", 50000)) as test_client:
        yield test_client

    reset_rate_limiter_for_tests()
    get_settings.cache_clear()


def login(client: TestClient, username: str, password: str) -> str:
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["token"]


def auth_headers(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


def create_device_membership(
    client: TestClient,
    admin_headers: dict[str, str],
    *,
    user_id: int,
    device_id: str,
    can_view_status: bool = True,
    can_wake: bool = True,
    can_request_shutdown: bool = True,
    can_manage_schedule: bool = False,
    is_favorite: bool = False,
    sort_order: int = 0,
) -> dict:
    response = client.post(
        "/admin/device-memberships",
        headers=admin_headers,
        json={
            "user_id": user_id,
            "device_id": device_id,
            "can_view_status": can_view_status,
            "can_wake": can_wake,
            "can_request_shutdown": can_request_shutdown,
            "can_manage_schedule": can_manage_schedule,
            "is_favorite": is_favorite,
            "sort_order": sort_order,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()
