from __future__ import annotations

import pytest
from starlette.requests import Request

from app.config import Settings
from app.request_context import get_request_ip, is_auth_transport_allowed, is_https_request, is_private_http_client_allowed, parse_cidrs


def _request(
    *,
    client_host: str | None,
    scheme: str = "http",
    x_forwarded_for: str | None = None,
    x_forwarded_proto: str | None = None,
) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if x_forwarded_for is not None:
        headers.append((b"x-forwarded-for", x_forwarded_for.encode("utf-8")))
    if x_forwarded_proto is not None:
        headers.append((b"x-forwarded-proto", x_forwarded_proto.encode("utf-8")))
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": scheme,
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": headers,
        "client": (client_host, 12345) if client_host is not None else None,
        "server": ("127.0.0.1", 8080),
        "root_path": "",
    }
    return Request(scope)


def test_proxy_headers_not_trusted_when_peer_is_not_ip() -> None:
    settings = Settings(_env_file=None)
    settings.trust_proxy_headers = True
    request = _request(client_host="testclient", x_forwarded_for="1.2.3.4", x_forwarded_proto="https")

    assert get_request_ip(request, settings) is None
    assert is_https_request(request, settings) is False


def test_direct_https_request_is_secure() -> None:
    settings = Settings(_env_file=None)
    request = _request(client_host="8.8.8.8", scheme="https")

    assert is_https_request(request, settings) is True
    assert is_auth_transport_allowed(request, settings) is True


def test_proxy_headers_trusted_for_configured_proxy_peer() -> None:
    settings = Settings(_env_file=None)
    settings.trust_proxy_headers = True
    settings.trusted_proxy_cidrs = "127.0.0.1/32"
    request = _request(client_host="127.0.0.1", x_forwarded_for="100.64.10.20", x_forwarded_proto="https")

    assert get_request_ip(request, settings) == "100.64.10.20"
    assert is_https_request(request, settings) is True


def test_proxy_headers_ignored_for_untrusted_proxy_peer() -> None:
    settings = Settings(_env_file=None)
    settings.trust_proxy_headers = True
    settings.trusted_proxy_cidrs = "127.0.0.1/32"
    request = _request(client_host="10.0.0.10", x_forwarded_for="100.64.10.20", x_forwarded_proto="https")

    assert get_request_ip(request, settings) == "10.0.0.10"
    assert is_https_request(request, settings) is False


def test_parse_cidrs_reports_invalid_entries() -> None:
    valid, invalid = parse_cidrs(["127.0.0.1/32", "not-a-cidr", "100.64.0.0/10"])

    assert valid == ["127.0.0.1/32", "100.64.0.0/10"]
    assert invalid == ["not-a-cidr"]


def test_private_http_allowed_cidrs_parse_from_settings() -> None:
    settings = Settings(_env_file=None)
    settings.private_http_allowed_cidrs = "127.0.0.1/32, 192.168.0.0/16 ,fd7a:115c:a1e0::/48"

    assert settings.private_http_allowed_cidrs_list == [
        "127.0.0.1/32",
        "192.168.0.0/16",
        "fd7a:115c:a1e0::/48",
    ]


def test_admin_allowed_cidrs_parse_from_settings() -> None:
    settings = Settings(_env_file=None)
    settings.admin_ip_allowlist_cidrs = "127.0.0.1/32, 100.64.0.0/10 ,fd7a:115c:a1e0::/48"

    assert settings.admin_allowed_cidrs_list == [
        "127.0.0.1/32",
        "100.64.0.0/10",
        "fd7a:115c:a1e0::/48",
    ]
    assert settings.parsed_admin_allowed_cidrs == [
        "127.0.0.1/32",
        "100.64.0.0/10",
        "fd7a:115c:a1e0::/48",
    ]


def test_parsed_admin_allowed_cidrs_reject_invalid_entries() -> None:
    settings = Settings(_env_file=None)
    settings.admin_ip_allowlist_cidrs = "127.0.0.1/32,not-a-cidr"

    with pytest.raises(ValueError, match="ADMIN_IP_ALLOWLIST_CIDRS contains invalid CIDR entries"):
        _ = settings.parsed_admin_allowed_cidrs


def test_private_http_client_is_recognized_when_ip_is_allowed() -> None:
    settings = Settings(_env_file=None)
    settings.private_http_allowed_cidrs = "192.168.0.0/16,100.64.0.0/10"
    request = _request(client_host="192.168.10.25")

    assert is_private_http_client_allowed(request, settings) is True
    assert is_auth_transport_allowed(request, settings) is True


def test_private_http_client_is_not_allowed_when_disabled() -> None:
    settings = Settings(_env_file=None)
    settings.allow_insecure_private_http = False
    settings.private_http_allowed_cidrs = "192.168.0.0/16"
    request = _request(client_host="192.168.10.25")

    assert is_private_http_client_allowed(request, settings) is False
    assert is_auth_transport_allowed(request, settings) is False
