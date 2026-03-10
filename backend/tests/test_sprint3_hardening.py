from __future__ import annotations

import pytest

from app.config import Settings, get_settings
from app.main import _init_bootstrap
from app.power import PowerCheckResult

from .conftest import auth_headers, create_device_membership, login


def _setup_user_and_device(client, username: str = "harduser"):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    user_res = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": username, "password": "hardpassword123", "role": "user"},
    )
    assert user_res.status_code == 201, user_res.text
    user_id = user_res.json()["id"]

    device_res = client.post(
        "/admin/devices",
        headers=admin_h,
        json={
            "name": "Hard-Device",
            "mac": "AA:00:00:00:00:01",
            "broadcast": "192.168.1.255",
            "udp_port": 9,
            "check_method": "tcp",
            "check_target": "192.168.1.20",
            "check_port": 22,
        },
    )
    assert device_res.status_code == 201, device_res.text
    device_id = device_res.json()["id"]

    create_device_membership(client, admin_h, user_id=user_id, device_id=device_id)
    return admin_h, user_id, device_id


def test_wake_rate_limit_enforced(client, monkeypatch):
    _, _, device_id = _setup_user_and_device(client, username="wake-limit")
    user_token = login(client, "wake-limit", "hardpassword123")
    user_h = auth_headers(user_token)

    settings = get_settings()
    old_limit = settings.wake_rate_limit_per_minute
    settings.wake_rate_limit_per_minute = 1

    monkeypatch.setattr(
        "app.main.run_power_check",
        lambda *_args, **_kwargs: PowerCheckResult(method="tcp", result="off", detail="timeout", latency_ms=4),
    )
    monkeypatch.setattr("app.main.send_magic_packet", lambda *_args, **_kwargs: None)

    first = client.post(f"/me/devices/{device_id}/wake", headers=user_h)
    assert first.status_code == 200, first.text

    second = client.post(f"/me/devices/{device_id}/wake", headers=user_h)
    assert second.status_code == 429
    assert second.json()["detail"] == "Too many wake attempts"

    settings.wake_rate_limit_per_minute = old_limit


def test_onboarding_endpoint_is_disabled(client):
    response = client.post("/onboarding/claim", json={"token": "not-a-real-token", "password": "newpassword1234"})
    assert response.status_code == 410


def test_audit_logs_metrics_and_diagnostics(client):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    create_user = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": "audited-user", "password": "auditedpassword", "role": "user"},
    )
    assert create_user.status_code == 201, create_user.text

    create_device = client.post(
        "/admin/devices",
        headers=admin_h,
        json={
            "name": "Misconfigured",
            "mac": "AA:00:00:00:00:02",
            "broadcast": "192.168.2.255",
            "udp_port": 9,
            "check_method": "tcp",
            "check_target": None,
            "check_port": None,
        },
    )
    assert create_device.status_code == 201, create_device.text

    audit = client.get("/admin/audit-logs", headers=admin_h)
    assert audit.status_code == 200, audit.text
    assert any(row["action"] == "create_user" for row in audit.json())
    assert any(row["action"] == "create_device" for row in audit.json())

    metrics = client.get("/admin/metrics", headers=admin_h)
    assert metrics.status_code == 200, metrics.text
    counters = metrics.json()["counters"]
    assert counters.get("admin_action.create_user", 0) >= 1
    assert counters.get("admin_action.create_device", 0) >= 1

    diagnostics = client.get("/admin/diagnostics/devices", headers=admin_h)
    assert diagnostics.status_code == 200, diagnostics.text
    misconfigured = [row for row in diagnostics.json() if row["name"] == "Misconfigured"]
    assert misconfigured
    assert any("missing" in hint.lower() for hint in misconfigured[0]["hints"])

    network_diagnostics = client.get("/admin/diagnostics/network", headers=admin_h)
    assert network_diagnostics.status_code == 200, network_diagnostics.text
    net_payload = network_diagnostics.json()
    assert "interfaces" in net_payload
    assert isinstance(net_payload["interfaces"], list)
    assert "has_multiple_active_networks" in net_payload


def test_security_status_surfaces_risky_allowed_states(client_factory):
    env = {
        "ENFORCE_IP_ALLOWLIST": "false",
        "ALLOW_UNSAFE_PUBLIC_EXPOSURE": "true",
        "ALLOW_INSECURE_PRIVATE_HTTP": "true",
        "ADMIN_MFA_REQUIRED": "false",
        "APP_PROOF_MODE": "report_only",
        "APP_PROOF_REQUIRE_ON_ADMIN_BEARER_LOGIN": "false",
    }
    with client_factory(env_overrides=env) as client:
        admin_h = auth_headers(login(client, "admin", "adminpass123456"))
        response = client.get("/admin/security-status", headers=admin_h)

    assert response.status_code == 200, response.text
    payload = response.json()
    warning_codes = {item["code"] for item in payload["warnings"]}
    assert warning_codes >= {
        "unsafe_public_exposure",
        "private_http_exception_enabled",
        "admin_ui_enabled",
        "admin_mfa_not_required",
        "app_proof_report_only",
        "admin_bearer_login_app_proof_deferred",
    }
    deferral_codes = {item["code"] for item in payload["deferrals"]}
    assert deferral_codes >= {
        "all_request_proof_of_possession_deferred",
        "admin_bearer_app_proof_rollout_deferred",
        "mtls_deferred",
        "devicecheck_not_enforcement",
        "private_network_first",
    }


def test_pilot_metrics_endpoint_is_disabled(client):
    admin_h, _, _ = _setup_user_and_device(client, username="pilot-user")
    metrics = client.get("/admin/pilot-metrics", headers=admin_h)
    assert metrics.status_code == 410, metrics.text


def test_password_policy_enforces_role_specific_minimums(client):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)

    create_user_with_short_password = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": "policy-short-user", "password": "123456", "role": "user"},
    )
    assert create_user_with_short_password.status_code == 422

    create_user = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": "policy-user", "password": "1234567890", "role": "user"},
    )
    assert create_user.status_code == 201, create_user.text
    user_id = create_user.json()["id"]

    create_admin_with_short_password = client.post(
        "/admin/users",
        headers=admin_h,
        json={"username": "policy-admin", "password": "123456", "role": "admin"},
    )
    assert create_admin_with_short_password.status_code == 422

    promote_without_password_rotation = client.patch(
        f"/admin/users/{user_id}",
        headers=admin_h,
        json={"role": "admin"},
    )
    assert promote_without_password_rotation.status_code == 400

    promote_with_admin_password = client.patch(
        f"/admin/users/{user_id}",
        headers=admin_h,
        json={"role": "admin", "password": "123456789012"},
    )
    assert promote_with_admin_password.status_code == 200, promote_with_admin_password.text


def test_api_docs_are_disabled_by_default(client):
    docs = client.get("/docs")
    assert docs.status_code == 404

    openapi = client.get("/openapi.json")
    assert openapi.status_code == 404


def test_security_defaults_for_settings_ignore_env_file(monkeypatch):
    monkeypatch.delenv("RATE_LIMIT_BACKEND", raising=False)
    monkeypatch.delenv("ENABLE_API_DOCS", raising=False)
    monkeypatch.delenv("ENFORCE_IP_ALLOWLIST", raising=False)
    monkeypatch.delenv("IP_ALLOWLIST_CIDRS", raising=False)
    monkeypatch.delenv("ALLOW_UNSAFE_PUBLIC_EXPOSURE", raising=False)
    monkeypatch.delenv("REQUIRE_TLS_FOR_AUTH", raising=False)
    monkeypatch.delenv("ALLOW_INSECURE_PRIVATE_HTTP", raising=False)
    monkeypatch.delenv("PRIVATE_HTTP_ALLOWED_CIDRS", raising=False)
    settings = Settings(_env_file=None)
    assert settings.enforce_ip_allowlist is True
    assert settings.allow_unsafe_public_exposure is False
    assert settings.require_tls_for_auth is True
    assert settings.allow_insecure_private_http is True
    assert settings.admin_ui_enabled is True
    assert settings.admin_mfa_required is False
    assert settings.admin_mfa_issuer == "WakeFromFar"
    assert settings.admin_mfa_pending_expires_seconds == 300
    assert settings.admin_mfa_verify_rate_limit_per_minute == 10
    assert settings.parsed_admin_allowed_cidrs == [
        "127.0.0.1/32",
        "::1/128",
        "100.64.0.0/10",
        "fd7a:115c:a1e0::/48",
    ]
    assert settings.rate_limit_backend == "memory"
    assert settings.enable_api_docs is False


def _bootstrap_settings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    *,
    enforce_ip_allowlist: str,
    ip_allowlist_cidrs: str | None = None,
    admin_ip_allowlist_cidrs: str | None = None,
    allow_unsafe_public_exposure: str = "false",
    allow_insecure_private_http: str = "true",
    private_http_allowed_cidrs: str | None = None,
) -> None:
    monkeypatch.setenv("APP_SECRET", "test-secret-value-1234-abcdef-5678")
    monkeypatch.setenv("ADMIN_USER", "admin")
    monkeypatch.setenv("ADMIN_PASS", "adminpass123456")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("DB_FILENAME", "bootstrap.db")
    monkeypatch.setenv("RATE_LIMIT_BACKEND", "memory")
    monkeypatch.setenv("ENFORCE_IP_ALLOWLIST", enforce_ip_allowlist)
    monkeypatch.setenv("ALLOW_UNSAFE_PUBLIC_EXPOSURE", allow_unsafe_public_exposure)
    monkeypatch.setenv("ALLOW_INSECURE_PRIVATE_HTTP", allow_insecure_private_http)
    if ip_allowlist_cidrs is None:
        monkeypatch.delenv("IP_ALLOWLIST_CIDRS", raising=False)
    else:
        monkeypatch.setenv("IP_ALLOWLIST_CIDRS", ip_allowlist_cidrs)
    if admin_ip_allowlist_cidrs is None:
        monkeypatch.delenv("ADMIN_IP_ALLOWLIST_CIDRS", raising=False)
    else:
        monkeypatch.setenv("ADMIN_IP_ALLOWLIST_CIDRS", admin_ip_allowlist_cidrs)
    if private_http_allowed_cidrs is None:
        monkeypatch.delenv("PRIVATE_HTTP_ALLOWED_CIDRS", raising=False)
    else:
        monkeypatch.setenv("PRIVATE_HTTP_ALLOWED_CIDRS", private_http_allowed_cidrs)

    monkeypatch.setattr("app.main.configure_rate_limiter", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("app.main.init_db", lambda: None)
    monkeypatch.setattr("app.main.upsert_admin", lambda *_args, **_kwargs: None)

    get_settings.cache_clear()
    try:
        _init_bootstrap()
    finally:
        get_settings.cache_clear()


def test_startup_fails_when_allowlist_is_disabled_without_explicit_override(monkeypatch, tmp_path):
    with pytest.raises(RuntimeError, match="ENFORCE_IP_ALLOWLIST=false"):
        _bootstrap_settings(
            monkeypatch,
            tmp_path,
            enforce_ip_allowlist="false",
            allow_unsafe_public_exposure="false",
        )


def test_startup_succeeds_when_allowlist_is_disabled_with_explicit_override(monkeypatch, tmp_path):
    _bootstrap_settings(
        monkeypatch,
        tmp_path,
        enforce_ip_allowlist="false",
        allow_unsafe_public_exposure="true",
    )


def test_startup_fails_when_allowlist_is_enabled_but_empty(monkeypatch, tmp_path):
    with pytest.raises(RuntimeError, match="IP_ALLOWLIST_CIDRS is empty"):
        _bootstrap_settings(
            monkeypatch,
            tmp_path,
            enforce_ip_allowlist="true",
            ip_allowlist_cidrs=" , ",
        )


def test_startup_fails_when_allowlist_contains_only_invalid_cidrs(monkeypatch, tmp_path):
    with pytest.raises(RuntimeError, match="IP_ALLOWLIST_CIDRS did not contain any valid CIDRs"):
        _bootstrap_settings(
            monkeypatch,
            tmp_path,
            enforce_ip_allowlist="true",
            ip_allowlist_cidrs="nope,still-nope",
        )


def test_startup_fails_when_allowlist_contains_malformed_cidr_even_if_one_is_valid(monkeypatch, tmp_path):
    with pytest.raises(RuntimeError, match="IP_ALLOWLIST_CIDRS contains invalid CIDR entries"):
        _bootstrap_settings(
            monkeypatch,
            tmp_path,
            enforce_ip_allowlist="true",
            ip_allowlist_cidrs="127.0.0.1/32,not-a-cidr",
        )


def test_startup_succeeds_when_allowlist_is_enabled_with_valid_cidr(monkeypatch, tmp_path):
    _bootstrap_settings(
        monkeypatch,
        tmp_path,
        enforce_ip_allowlist="true",
        ip_allowlist_cidrs="127.0.0.1/32",
    )


def test_startup_succeeds_with_default_admin_allowlist(monkeypatch, tmp_path):
    _bootstrap_settings(
        monkeypatch,
        tmp_path,
        enforce_ip_allowlist="true",
        ip_allowlist_cidrs="127.0.0.1/32",
    )


def test_startup_fails_when_admin_allowlist_is_empty(monkeypatch, tmp_path):
    with pytest.raises(RuntimeError, match="ADMIN_IP_ALLOWLIST_CIDRS is empty"):
        _bootstrap_settings(
            monkeypatch,
            tmp_path,
            enforce_ip_allowlist="true",
            ip_allowlist_cidrs="127.0.0.1/32",
            admin_ip_allowlist_cidrs=" , ",
        )


def test_startup_fails_when_admin_allowlist_contains_only_invalid_cidrs(monkeypatch, tmp_path):
    with pytest.raises(RuntimeError, match="ADMIN_IP_ALLOWLIST_CIDRS did not contain any valid CIDRs"):
        _bootstrap_settings(
            monkeypatch,
            tmp_path,
            enforce_ip_allowlist="true",
            ip_allowlist_cidrs="127.0.0.1/32",
            admin_ip_allowlist_cidrs="nope,still-nope",
        )


def test_startup_fails_when_admin_allowlist_contains_malformed_cidr_even_if_one_is_valid(monkeypatch, tmp_path):
    with pytest.raises(RuntimeError, match="ADMIN_IP_ALLOWLIST_CIDRS contains invalid CIDR entries"):
        _bootstrap_settings(
            monkeypatch,
            tmp_path,
            enforce_ip_allowlist="true",
            ip_allowlist_cidrs="127.0.0.1/32",
            admin_ip_allowlist_cidrs="127.0.0.1/32,not-a-cidr",
        )


def test_startup_succeeds_when_admin_allowlist_is_enabled_with_valid_cidr(monkeypatch, tmp_path):
    _bootstrap_settings(
        monkeypatch,
        tmp_path,
        enforce_ip_allowlist="true",
        ip_allowlist_cidrs="127.0.0.1/32",
        admin_ip_allowlist_cidrs="127.0.0.1/32",
    )


def test_startup_allows_invalid_admin_allowlist_with_explicit_unsafe_override(monkeypatch, tmp_path):
    _bootstrap_settings(
        monkeypatch,
        tmp_path,
        enforce_ip_allowlist="true",
        ip_allowlist_cidrs="127.0.0.1/32",
        admin_ip_allowlist_cidrs="not-a-cidr",
        allow_unsafe_public_exposure="true",
    )


def test_startup_fails_when_private_http_allowlist_contains_invalid_cidrs(monkeypatch, tmp_path):
    with pytest.raises(RuntimeError, match="PRIVATE_HTTP_ALLOWED_CIDRS contains invalid CIDR entries"):
        _bootstrap_settings(
            monkeypatch,
            tmp_path,
            enforce_ip_allowlist="true",
            ip_allowlist_cidrs="127.0.0.1/32",
            private_http_allowed_cidrs="192.168.0.0/16,not-a-cidr",
        )


def test_admin_api_request_from_allowed_admin_cidr_succeeds(client_factory):
    env = {
        "IP_ALLOWLIST_CIDRS": "192.168.0.0/16",
        "ADMIN_IP_ALLOWLIST_CIDRS": "192.168.0.0/16",
    }
    with client_factory(client_host="192.168.10.25", env_overrides=env) as client:
        admin_token = login(client, "admin", "adminpass123456")
        response = client.get("/admin/users", headers=auth_headers(admin_token))

    assert response.status_code == 200, response.text
    assert any(row["username"] == "admin" for row in response.json())


def test_admin_api_request_from_non_allowed_admin_cidr_is_rejected_even_with_valid_auth(client_factory):
    env = {
        "IP_ALLOWLIST_CIDRS": "192.168.0.0/16",
        "ADMIN_IP_ALLOWLIST_CIDRS": "127.0.0.1/32",
    }
    with client_factory(client_host="192.168.10.25", env_overrides=env) as client:
        admin_token = login(client, "admin", "adminpass123456")
        response = client.get("/admin/users", headers=auth_headers(admin_token))

    assert response.status_code == 403
    assert response.json()["detail"] == "Admin access is not allowed from this network"


def test_non_admin_me_request_is_not_affected_by_admin_allowlist(client_factory):
    env = {
        "IP_ALLOWLIST_CIDRS": "192.168.0.0/16",
        "ADMIN_IP_ALLOWLIST_CIDRS": "127.0.0.1/32",
    }
    with client_factory(client_host="192.168.10.25", env_overrides=env) as client:
        user_token = login(client, "admin", "adminpass123456")
        response = client.get("/me/devices", headers=auth_headers(user_token))

    assert response.status_code == 200, response.text
    assert response.json() == []


def test_admin_api_proxy_allows_forwarded_client_ip_in_admin_allowlist(client_factory):
    env = {
        "ENFORCE_IP_ALLOWLIST": "false",
        "ALLOW_UNSAFE_PUBLIC_EXPOSURE": "true",
        "TRUST_PROXY_HEADERS": "true",
        "TRUSTED_PROXY_CIDRS": "127.0.0.1/32",
        "ADMIN_IP_ALLOWLIST_CIDRS": "100.64.0.0/10",
    }
    proxy_headers = {
        "x-forwarded-for": "100.64.10.20",
        "x-forwarded-proto": "https",
    }
    with client_factory(client_host="127.0.0.1", env_overrides=env) as client:
        login_response = client.post("/auth/login", json={"username": "admin", "password": "adminpass123456"}, headers=proxy_headers)
        token = login_response.json()["token"]
        response = client.get("/admin/users", headers={**auth_headers(token), **proxy_headers})

    assert login_response.status_code == 200, login_response.text
    assert response.status_code == 200, response.text


def test_admin_api_untrusted_proxy_headers_do_not_bypass_admin_allowlist(client_factory):
    env = {
        "ENFORCE_IP_ALLOWLIST": "false",
        "ALLOW_UNSAFE_PUBLIC_EXPOSURE": "true",
        "TRUST_PROXY_HEADERS": "true",
        "TRUSTED_PROXY_CIDRS": "127.0.0.1/32",
        "ADMIN_IP_ALLOWLIST_CIDRS": "100.64.0.0/10",
    }
    proxy_headers = {
        "x-forwarded-for": "100.64.10.20",
        "x-forwarded-proto": "https",
    }
    with client_factory(client_host="10.0.0.10", env_overrides=env) as client:
        login_response = client.post("/auth/login", json={"username": "admin", "password": "adminpass123456"})
        token = login_response.json()["token"]
        response = client.get("/admin/users", headers={**auth_headers(token), **proxy_headers})

    assert login_response.status_code == 200, login_response.text
    assert response.status_code == 403
    assert response.json()["detail"] == "Admin access is not allowed from this network"
