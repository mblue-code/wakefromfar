from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from .config import Settings
from .schemas import (
    InstallationPlatformSummaryOut,
    RecentSecurityCategoryOut,
    SecurityCounterOut,
    SecurityDeferralOut,
    SecurityStatusOut,
    SecurityWarningOut,
)


def _parse_iso(value: object | None) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def build_security_warnings(settings: Settings) -> list[SecurityWarningOut]:
    warnings: list[SecurityWarningOut] = []
    if settings.allow_unsafe_public_exposure:
        warnings.append(
            SecurityWarningOut(
                code="unsafe_public_exposure",
                severity="warning",
                message="ALLOW_UNSAFE_PUBLIC_EXPOSURE=true disables the fail-closed startup guard for broad network exposure.",
            )
        )
    if settings.allow_insecure_private_http:
        warnings.append(
            SecurityWarningOut(
                code="private_http_exception_enabled",
                severity="info",
                message="ALLOW_INSECURE_PRIVATE_HTTP=true still permits HTTP for configured private-network CIDRs. Verify those CIDRs before beta rollout.",
            )
        )
    if settings.admin_ui_enabled:
        warnings.append(
            SecurityWarningOut(
                code="admin_ui_enabled",
                severity="info",
                message="ADMIN_UI_ENABLED=true exposes the browser admin plane. Keep ADMIN_IP_ALLOWLIST_CIDRS tightly scoped.",
            )
        )
    if not settings.admin_mfa_required:
        warnings.append(
            SecurityWarningOut(
                code="admin_mfa_not_required",
                severity="warning",
                message="ADMIN_MFA_REQUIRED=false allows password-only browser admin login for non-enrolled admins.",
            )
        )
    if settings.app_proof_mode == "disabled":
        warnings.append(
            SecurityWarningOut(
                code="app_proof_disabled",
                severity="warning",
                message="APP_PROOF_MODE=disabled leaves bearer-token login without mobile app proof enforcement.",
            )
        )
    elif settings.app_proof_mode == "report_only":
        warnings.append(
            SecurityWarningOut(
                code="app_proof_report_only",
                severity="warning",
                message="APP_PROOF_MODE=report_only records missing app proof but still issues bearer sessions.",
            )
        )
    if not settings.app_proof_require_on_admin_bearer_login:
        warnings.append(
            SecurityWarningOut(
                code="admin_bearer_login_app_proof_deferred",
                severity="info",
                message="APP_PROOF_REQUIRE_ON_ADMIN_BEARER_LOGIN=false keeps admin bearer-token login outside default app-proof enforcement.",
            )
        )
    return warnings


def build_security_deferrals(settings: Settings) -> list[SecurityDeferralOut]:
    deferrals = [
        SecurityDeferralOut(
            code="all_request_proof_of_possession_deferred",
            message="All-request proof-of-possession is still deferred. Authenticated mobile requests remain bearer-token based after login.",
        ),
        SecurityDeferralOut(
            code="mtls_deferred",
            message="mTLS is still deferred and is not part of the default hardening stack.",
        ),
        SecurityDeferralOut(
            code="devicecheck_not_enforcement",
            message="DeviceCheck remains a report-only signal and is not an enforcement substitute for iOS app proof.",
        ),
        SecurityDeferralOut(
            code="private_network_first",
            message="WakeFromFar remains a private-network-first product. Public internet exposure is still unsupported.",
        ),
    ]
    if not settings.app_proof_require_on_admin_bearer_login:
        deferrals.insert(
            1,
            SecurityDeferralOut(
                code="admin_bearer_app_proof_rollout_deferred",
                message="Admin bearer-token login app proof is deferred by default behind APP_PROOF_REQUIRE_ON_ADMIN_BEARER_LOGIN=false.",
            ),
        )
    return deferrals


def build_app_installation_summary(rows: list[dict[str, Any] | Any]) -> dict[str, InstallationPlatformSummaryOut]:
    counts: dict[str, dict[str, int]] = {
        "android": defaultdict(int),
        "ios": defaultdict(int),
    }
    totals = {"android": 0, "ios": 0}
    for row in rows:
        platform = str(row["platform"])
        status = str(row["status"])
        if platform not in counts:
            continue
        totals[platform] += 1
        counts[platform][status] += 1
    return {
        platform: InstallationPlatformSummaryOut(total=totals[platform], by_status=dict(sorted(statuses.items())))
        for platform, statuses in counts.items()
    }


def _app_proof_failure_category(event: dict[str, Any]) -> str | None:
    name = str(event.get("event") or "")
    if not name.startswith("app_proof."):
        return None
    reason = str(event.get("reason") or "").strip()
    if name == "app_proof.verify_failed":
        return reason or "verify_failed"
    if name == "app_proof.enforce_login_blocked":
        return "missing_proof_enforce_login"
    if name == "app_proof.installation_session_mismatch":
        return reason or "session_mismatch"
    if name == "app_proof.installation_revoked":
        return "revoked_installation"
    if name == "app_proof.invalid_nonce":
        return reason or "invalid_nonce"
    if name == "app_proof.challenge_expired":
        return "expired_challenge"
    if name == "app_proof.replay_detected":
        return "replayed_challenge"
    if name == "app_proof.provider_timeout":
        return "provider_timeout"
    if name == "app_proof.provider_error":
        return "provider_error"
    if name == "app_proof.provider_quota":
        return "provider_quota"
    return None


def build_recent_app_proof_failures(events: list[dict[str, Any]]) -> list[RecentSecurityCategoryOut]:
    grouped: dict[str, dict[str, Any]] = {}
    for event in events:
        category = _app_proof_failure_category(event)
        if category is None:
            continue
        current = grouped.setdefault(category, {"count": 0, "last_seen_at": None})
        current["count"] += 1
        seen_at = _parse_iso(event.get("ts"))
        if seen_at and (current["last_seen_at"] is None or seen_at > current["last_seen_at"]):
            current["last_seen_at"] = seen_at
    ordered = sorted(
        grouped.items(),
        key=lambda item: (
            -(int(item[1]["count"])),
            -(item[1]["last_seen_at"].timestamp() if item[1]["last_seen_at"] else 0),
            item[0],
        ),
    )
    return [
        RecentSecurityCategoryOut(
            category=category,
            count=int(data["count"]),
            last_seen_at=data["last_seen_at"],
        )
        for category, data in ordered[:10]
    ]


def build_security_status(
    *,
    settings: Settings,
    counters: dict[str, int],
    installation_rows: list[dict[str, Any] | Any],
    recent_events: list[dict[str, Any]],
) -> SecurityStatusOut:
    counter_rows = [
        SecurityCounterOut(name=name, value=value)
        for name, value in sorted(counters.items())
        if name.startswith("security.") or name.startswith("app_proof.")
    ]
    return SecurityStatusOut(
        generated_at=datetime.now(UTC),
        private_network_first=True,
        hardening_mode="fail_closed_private_network_first" if settings.enforce_ip_allowlist else "unsafe_override",
        app_proof_mode=settings.app_proof_mode,
        admin_bearer_login_app_proof_deferred=not settings.app_proof_require_on_admin_bearer_login,
        admin_ui_enabled=settings.admin_ui_enabled,
        admin_mfa_required=settings.admin_mfa_required,
        require_tls_for_auth=settings.require_tls_for_auth,
        allow_insecure_private_http=settings.allow_insecure_private_http,
        allow_unsafe_public_exposure=settings.allow_unsafe_public_exposure,
        ip_allowlist_enabled=settings.enforce_ip_allowlist,
        allowlist_summary={
            "app_cidr_count": len(settings.allowed_cidrs),
            "admin_cidr_count": len(settings.admin_allowed_cidrs_list),
            "private_http_exception_cidr_count": len(settings.private_http_allowed_cidrs_list),
        },
        app_proof_installations=build_app_installation_summary(installation_rows),
        recent_app_proof_failures=build_recent_app_proof_failures(recent_events),
        security_counters=counter_rows,
        warnings=build_security_warnings(settings),
        deferrals=build_security_deferrals(settings),
    )
