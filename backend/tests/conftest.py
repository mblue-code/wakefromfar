from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("APP_SECRET", "test-secret-value-1234")
    monkeypatch.setenv("ADMIN_USER", "admin")
    monkeypatch.setenv("ADMIN_PASS", "adminpass123456")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("DB_FILENAME", "test.db")
    monkeypatch.setenv("ENFORCE_IP_ALLOWLIST", "false")

    from app.config import get_settings
    from app.admin_ui import _LOGIN_ATTEMPTS
    from app.main import LOGIN_ATTEMPTS, ONBOARDING_ATTEMPTS, WAKE_ATTEMPTS, app
    from app.telemetry import reset_counters

    get_settings.cache_clear()
    LOGIN_ATTEMPTS.clear()
    _LOGIN_ATTEMPTS.clear()
    ONBOARDING_ATTEMPTS.clear()
    WAKE_ATTEMPTS.clear()
    reset_counters()

    with TestClient(app) as test_client:
        yield test_client

    get_settings.cache_clear()


def login(client: TestClient, username: str, password: str) -> str:
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["token"]


def auth_headers(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}
