from __future__ import annotations

import ipaddress

from fastapi import Request

from .config import Settings


def _parse_ip(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not value:
        return None
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def is_ip_in_networks(ip_text: str, cidrs: list[str]) -> bool:
    ip_obj = _parse_ip(ip_text)
    if not ip_obj:
        return False
    for cidr in cidrs:
        try:
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def _trusted_proxy_peer(request: Request, settings: Settings) -> bool:
    if not settings.trust_proxy_headers:
        return False
    peer_ip = request.client.host if request.client else None
    if not peer_ip:
        return False
    if _parse_ip(peer_ip) is None:
        return False
    return is_ip_in_networks(peer_ip, settings.trusted_proxy_cidrs_list)


def _extract_forwarded_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        first = forwarded_for.split(",")[0].strip()
        if _parse_ip(first):
            return first
    real_ip = request.headers.get("x-real-ip")
    if real_ip and _parse_ip(real_ip):
        return real_ip.strip()
    return None


def _extract_forwarded_proto(request: Request) -> str | None:
    forwarded_proto = request.headers.get("x-forwarded-proto")
    if forwarded_proto:
        first = forwarded_proto.split(",")[0].strip().lower()
        if first:
            return first

    forwarded = request.headers.get("forwarded", "")
    for part in forwarded.split(","):
        for segment in part.split(";"):
            key, sep, value = segment.strip().partition("=")
            if sep and key.strip().lower() == "proto":
                return value.strip().strip('"').lower()
    return None


def get_request_ip(request: Request, settings: Settings) -> str | None:
    peer_ip = request.client.host if request.client else None
    if _trusted_proxy_peer(request, settings):
        forwarded_ip = _extract_forwarded_ip(request)
        if forwarded_ip:
            return forwarded_ip
    if peer_ip and _parse_ip(peer_ip):
        return peer_ip
    return None


def is_https_request(request: Request, settings: Settings) -> bool:
    if request.url.scheme == "https":
        return True
    if not _trusted_proxy_peer(request, settings):
        return False
    return _extract_forwarded_proto(request) == "https"
