from __future__ import annotations

import re
from contextlib import contextmanager
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient


def _default_env(tmp_path) -> dict[str, str]:
    return {
        "APP_SECRET": "test-secret-value-1234-abcdef-5678",
        "ADMIN_USER": "admin",
        "ADMIN_PASS": "adminpass123456",
        "DATA_DIR": str(tmp_path),
        "DB_FILENAME": "test.db",
        "ENFORCE_IP_ALLOWLIST": "true",
        "IP_ALLOWLIST_CIDRS": "127.0.0.1/32,::1/128",
        "ALLOW_UNSAFE_PUBLIC_EXPOSURE": "false",
        "TRUST_PROXY_HEADERS": "false",
        "TRUSTED_PROXY_CIDRS": "127.0.0.1/32,::1/128",
        "REQUIRE_TLS_FOR_AUTH": "true",
        "ALLOW_INSECURE_PRIVATE_HTTP": "true",
        "PRIVATE_HTTP_ALLOWED_CIDRS": (
            "127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,"
            "100.64.0.0/10,fd7a:115c:a1e0::/48"
        ),
        "ADMIN_UI_ENABLED": "true",
        "ADMIN_IP_ALLOWLIST_CIDRS": "127.0.0.1/32,::1/128",
        "APP_PROOF_MODE": "disabled",
        "APP_PROOF_ANDROID_PACKAGE_NAME": "com.wakefromfar.wolrelay",
        "APP_PROOF_ANDROID_ALLOWED_CERT_SHA256": "ABCD1234",
        "APP_PROOF_IOS_TEAM_ID": "TEAM123456",
        "APP_PROOF_IOS_BUNDLE_ID": "com.wakefromfar.wolrelay.ios",
        "RATE_LIMIT_BACKEND": "memory",
    }


@pytest.fixture()
def client_factory(tmp_path, monkeypatch: pytest.MonkeyPatch):
    @contextmanager
    def _make_client(
        *,
        client_host: str = "127.0.0.1",
        scheme: str = "http",
        env_overrides: dict[str, str | None] | None = None,
    ) -> Iterator[TestClient]:
        for key, value in _default_env(tmp_path).items():
            monkeypatch.setenv(key, value)
        for key, value in (env_overrides or {}).items():
            if value is None:
                monkeypatch.delenv(key, raising=False)
            else:
                monkeypatch.setenv(key, value)

        from app.config import get_settings
        from app.main import app
        from app.rate_limit import reset_rate_limiter_for_tests
        from app.telemetry import reset_counters

        get_settings.cache_clear()
        reset_rate_limiter_for_tests()
        reset_counters()

        with TestClient(app, base_url=f"{scheme}://testserver", client=(client_host, 50000)) as test_client:
            yield test_client

        reset_rate_limiter_for_tests()
        reset_counters()
        get_settings.cache_clear()

    return _make_client


@pytest.fixture()
def client(client_factory) -> Iterator[TestClient]:
    with client_factory() as test_client:
        yield test_client


def login(client: TestClient, username: str, password: str) -> str:
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["token"]


def auth_headers(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


ADMIN_UI_ORIGIN = "http://testserver"


def extract_admin_ui_csrf_token(response_text: str) -> str:
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', response_text)
    assert match is not None, response_text
    return match.group(1)


def admin_ui_headers(
    *,
    origin: str | None = ADMIN_UI_ORIGIN,
    referer: str | None = None,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    headers: dict[str, str] = {}
    if origin is not None:
        headers["origin"] = origin
    if referer is not None:
        headers["referer"] = referer
    if extra:
        headers.update(extra)
    return headers


def admin_ui_login(
    client: TestClient,
    *,
    username: str = "admin",
    password: str = "adminpass123456",
    next_path: str = "/admin/ui",
    lang: str = "en",
    login_page_path: str = "/admin/ui/login",
    origin: str | None = ADMIN_UI_ORIGIN,
    referer: str | None = None,
    headers: dict[str, str] | None = None,
    follow_redirects: bool = False,
):
    login_page = client.get(login_page_path)
    assert login_page.status_code == 200, login_page.text
    csrf_token = extract_admin_ui_csrf_token(login_page.text)
    return client.post(
        "/admin/ui/login",
        data={
            "username": username,
            "password": password,
            "next": next_path,
            "lang": lang,
            "csrf_token": csrf_token,
        },
        headers=admin_ui_headers(origin=origin, referer=referer, extra=headers),
        follow_redirects=follow_redirects,
    )


def admin_ui_post(
    client: TestClient,
    path: str,
    *,
    form_page_path: str,
    data: dict[str, str] | None = None,
    origin: str | None = ADMIN_UI_ORIGIN,
    referer: str | None = None,
    headers: dict[str, str] | None = None,
    follow_redirects: bool = False,
):
    form_page = client.get(form_page_path)
    assert form_page.status_code == 200, form_page.text
    csrf_token = extract_admin_ui_csrf_token(form_page.text)
    payload = dict(data or {})
    payload["csrf_token"] = csrf_token
    return client.post(
        path,
        data=payload,
        headers=admin_ui_headers(origin=origin, referer=referer, extra=headers),
        follow_redirects=follow_redirects,
    )


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
