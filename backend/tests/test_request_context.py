from __future__ import annotations

from starlette.requests import Request

from app.config import Settings
from app.request_context import get_request_ip, is_https_request


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
