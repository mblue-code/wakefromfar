from __future__ import annotations

from app.request_context import AUTHENTICATED_TLS_REQUIRED_DETAIL, LOGIN_TLS_REQUIRED_DETAIL
from app.telemetry import get_counters

from .conftest import admin_ui_login


def _unsafe_public_env(**overrides: str) -> dict[str, str]:
    env = {
        "ENFORCE_IP_ALLOWLIST": "false",
        "ALLOW_UNSAFE_PUBLIC_EXPOSURE": "true",
        "REQUIRE_TLS_FOR_AUTH": "true",
        "ALLOW_INSECURE_PRIVATE_HTTP": "true",
        "ADMIN_IP_ALLOWLIST_CIDRS": "127.0.0.1/32,::1/128,8.8.8.8/32,192.168.0.0/16,100.64.0.0/10",
    }
    env.update(overrides)
    return env


def _login_json(client, username: str = "admin", password: str = "adminpass123456", headers: dict[str, str] | None = None):
    return client.post(
        "/auth/login",
        json={"username": username, "password": password},
        headers=headers,
    )


def test_login_over_public_http_is_rejected(client_factory):
    with client_factory(client_host="8.8.8.8", env_overrides=_unsafe_public_env()) as client:
        response = _login_json(client)

    assert response.status_code == 403
    assert response.json()["detail"] == LOGIN_TLS_REQUIRED_DETAIL


def test_transport_policy_rejections_emit_security_counter(client_factory):
    with client_factory(client_host="8.8.8.8", env_overrides=_unsafe_public_env()) as client:
        response = _login_json(client)
        assert response.status_code == 403
        assert get_counters()["security.transport_auth.blocked"] >= 1


def test_login_over_private_http_is_allowed_when_private_http_exception_is_enabled(client_factory):
    with client_factory(client_host="192.168.10.25", env_overrides=_unsafe_public_env()) as client:
        response = _login_json(client)

    assert response.status_code == 200, response.text
    assert response.json()["token"]


def test_login_over_private_http_is_rejected_when_private_http_exception_is_disabled(client_factory):
    with client_factory(
        client_host="192.168.10.25",
        env_overrides=_unsafe_public_env(ALLOW_INSECURE_PRIVATE_HTTP="false"),
    ) as client:
        response = _login_json(client)

    assert response.status_code == 403
    assert response.json()["detail"] == LOGIN_TLS_REQUIRED_DETAIL


def test_login_over_public_http_is_allowed_when_tls_requirement_is_disabled(client_factory):
    with client_factory(
        client_host="8.8.8.8",
        env_overrides=_unsafe_public_env(REQUIRE_TLS_FOR_AUTH="false"),
    ) as client:
        response = _login_json(client)

    assert response.status_code == 200, response.text
    assert response.json()["token"]


def test_authenticated_me_devices_over_public_http_is_rejected(client_factory):
    with client_factory(client_host="8.8.8.8", scheme="https", env_overrides=_unsafe_public_env()) as secure_client:
        token = _login_json(secure_client).json()["token"]

    with client_factory(client_host="8.8.8.8", env_overrides=_unsafe_public_env()) as client:
        response = client.get("/me/devices", headers={"authorization": f"Bearer {token}"})

    assert response.status_code == 403
    assert response.json()["detail"] == AUTHENTICATED_TLS_REQUIRED_DETAIL


def test_authenticated_me_devices_over_private_http_are_allowed(client_factory):
    with client_factory(client_host="192.168.10.25", env_overrides=_unsafe_public_env()) as client:
        token = _login_json(client).json()["token"]
        response = client.get("/me/devices", headers={"authorization": f"Bearer {token}"})

    assert response.status_code == 200, response.text
    assert response.json() == []


def test_admin_api_over_public_http_is_rejected(client_factory):
    with client_factory(client_host="8.8.8.8", scheme="https", env_overrides=_unsafe_public_env()) as secure_client:
        token = _login_json(secure_client).json()["token"]

    with client_factory(client_host="8.8.8.8", env_overrides=_unsafe_public_env()) as client:
        response = client.get("/admin/users", headers={"authorization": f"Bearer {token}"})

    assert response.status_code == 403
    assert response.json()["detail"] == AUTHENTICATED_TLS_REQUIRED_DETAIL


def test_admin_ui_login_over_public_http_is_rejected(client_factory):
    with client_factory(client_host="8.8.8.8", env_overrides=_unsafe_public_env()) as client:
        response = admin_ui_login(client)

    assert response.status_code == 403
    assert response.text == LOGIN_TLS_REQUIRED_DETAIL


def test_admin_ui_authenticated_page_over_public_http_is_rejected(client_factory):
    with client_factory(client_host="8.8.8.8", scheme="https", env_overrides=_unsafe_public_env()) as secure_client:
        login_response = admin_ui_login(secure_client, next_path="/admin/ui/users", origin="https://testserver")
        session_cookie = secure_client.cookies.get("admin_session")

    assert login_response.status_code == 303
    assert session_cookie

    with client_factory(client_host="8.8.8.8", env_overrides=_unsafe_public_env()) as client:
        client.cookies.set("admin_session", session_cookie, path="/admin/ui")
        response = client.get("/admin/ui/users", follow_redirects=False)

    assert response.status_code == 403
    assert response.json()["detail"] == AUTHENTICATED_TLS_REQUIRED_DETAIL


def test_public_https_allows_login_and_authenticated_requests(client_factory):
    with client_factory(client_host="8.8.8.8", scheme="https", env_overrides=_unsafe_public_env()) as client:
        login_response = _login_json(client)
        token = login_response.json()["token"]
        me_response = client.get("/me/devices", headers={"authorization": f"Bearer {token}"})

    assert login_response.status_code == 200, login_response.text
    assert me_response.status_code == 200, me_response.text


def test_trusted_proxy_https_allows_login_and_authenticated_requests(client_factory):
    env = _unsafe_public_env(
        TRUST_PROXY_HEADERS="true",
        TRUSTED_PROXY_CIDRS="127.0.0.1/32,::1/128",
    )
    proxy_headers = {
        "x-forwarded-for": "8.8.8.8",
        "x-forwarded-proto": "https",
    }
    with client_factory(client_host="127.0.0.1", env_overrides=env) as client:
        login_response = _login_json(client, headers=proxy_headers)
        token = login_response.json()["token"]
        me_response = client.get("/me/devices", headers={"authorization": f"Bearer {token}", **proxy_headers})

    assert login_response.status_code == 200, login_response.text
    assert me_response.status_code == 200, me_response.text
