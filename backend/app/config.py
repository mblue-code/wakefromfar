from __future__ import annotations

import ipaddress
import json
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _split_csv(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def _parse_cidrs(value: str) -> tuple[list[str], list[str]]:
    valid: list[str] = []
    invalid: list[str] = []
    for cidr in _split_csv(value):
        try:
            valid.append(str(ipaddress.ip_network(cidr, strict=False)))
        except ValueError:
            invalid.append(cidr)
    return valid, invalid


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_secret: str = Field(default="change-me", alias="APP_SECRET")
    token_expires_seconds: int = Field(default=28_800, alias="TOKEN_EXPIRES_SECONDS")

    data_dir: Path = Field(default=Path("/data"), alias="DATA_DIR")
    db_filename: str = Field(default="wol.db", alias="DB_FILENAME")

    admin_user: str | None = Field(default=None, alias="ADMIN_USER")
    admin_pass: str | None = Field(default=None, alias="ADMIN_PASS")

    enforce_ip_allowlist: bool = Field(default=True, alias="ENFORCE_IP_ALLOWLIST")
    ip_allowlist_cidrs: str = Field(
        default="100.64.0.0/10,fd7a:115c:a1e0::/48,127.0.0.1/32,::1/128",
        alias="IP_ALLOWLIST_CIDRS",
    )
    allow_unsafe_public_exposure: bool = Field(default=False, alias="ALLOW_UNSAFE_PUBLIC_EXPOSURE")
    trust_proxy_headers: bool = Field(default=False, alias="TRUST_PROXY_HEADERS")
    trusted_proxy_cidrs: str = Field(default="127.0.0.1/32,::1/128", alias="TRUSTED_PROXY_CIDRS")
    require_tls_for_auth: bool = Field(default=True, alias="REQUIRE_TLS_FOR_AUTH")
    allow_insecure_private_http: bool = Field(default=True, alias="ALLOW_INSECURE_PRIVATE_HTTP")
    private_http_allowed_cidrs: str = Field(
        default=(
            "127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,"
            "100.64.0.0/10,fd7a:115c:a1e0::/48"
        ),
        alias="PRIVATE_HTTP_ALLOWED_CIDRS",
    )
    admin_ui_enabled: bool = Field(default=True, alias="ADMIN_UI_ENABLED")
    admin_ip_allowlist_cidrs: str = Field(
        default="127.0.0.1/32,::1/128,100.64.0.0/10,fd7a:115c:a1e0::/48",
        alias="ADMIN_IP_ALLOWLIST_CIDRS",
    )
    admin_mfa_required: bool = Field(default=False, alias="ADMIN_MFA_REQUIRED")
    admin_mfa_issuer: str = Field(default="WakeFromFar", alias="ADMIN_MFA_ISSUER")
    admin_mfa_pending_expires_seconds: int = Field(default=300, alias="ADMIN_MFA_PENDING_EXPIRES_SECONDS")
    admin_mfa_verify_rate_limit_per_minute: int = Field(default=10, alias="ADMIN_MFA_VERIFY_RATE_LIMIT_PER_MINUTE")
    app_proof_mode: Literal["disabled", "report_only", "soft_enforce", "enforce_login"] = Field(
        default="disabled",
        alias="APP_PROOF_MODE",
    )
    app_proof_challenge_ttl_seconds: int = Field(default=300, alias="APP_PROOF_CHALLENGE_TTL_SECONDS")
    app_proof_degraded_grace_seconds: int = Field(default=86_400, alias="APP_PROOF_DEGRADED_GRACE_SECONDS")
    app_proof_require_on_admin_bearer_login: bool = Field(
        default=False,
        alias="APP_PROOF_REQUIRE_ON_ADMIN_BEARER_LOGIN",
    )
    app_proof_provider_timeout_seconds: float = Field(default=5.0, alias="APP_PROOF_PROVIDER_TIMEOUT_SECONDS")
    app_proof_android_enabled: bool = Field(default=True, alias="APP_PROOF_ANDROID_ENABLED")
    app_proof_android_package_name: str = Field(
        default="com.wakefromfar.wolrelay",
        alias="APP_PROOF_ANDROID_PACKAGE_NAME",
    )
    app_proof_android_allowed_cert_sha256: str = Field(default="", alias="APP_PROOF_ANDROID_ALLOWED_CERT_SHA256")
    app_proof_android_cloud_project_number: str | None = Field(
        default=None,
        alias="APP_PROOF_ANDROID_CLOUD_PROJECT_NUMBER",
    )
    app_proof_android_require_device_integrity: bool = Field(
        default=True,
        alias="APP_PROOF_ANDROID_REQUIRE_DEVICE_INTEGRITY",
    )
    app_proof_android_require_play_recognized: bool = Field(
        default=True,
        alias="APP_PROOF_ANDROID_REQUIRE_PLAY_RECOGNIZED",
    )
    app_proof_android_require_licensed: bool = Field(
        default=False,
        alias="APP_PROOF_ANDROID_REQUIRE_LICENSED",
    )
    app_proof_android_service_account_json: str | None = Field(
        default=None,
        alias="APP_PROOF_ANDROID_SERVICE_ACCOUNT_JSON",
    )
    app_proof_android_service_account_json_path: Path | None = Field(
        default=None,
        alias="APP_PROOF_ANDROID_SERVICE_ACCOUNT_JSON_PATH",
    )
    app_proof_ios_enabled: bool = Field(default=True, alias="APP_PROOF_IOS_ENABLED")
    app_proof_ios_team_id: str | None = Field(default=None, alias="APP_PROOF_IOS_TEAM_ID")
    app_proof_ios_bundle_id: str | None = Field(default=None, alias="APP_PROOF_IOS_BUNDLE_ID")
    app_proof_ios_allow_devicecheck_report_only: bool = Field(
        default=True,
        alias="APP_PROOF_IOS_ALLOW_DEVICECHECK_REPORT_ONLY",
    )

    login_rate_limit_per_minute: int = Field(default=5, alias="LOGIN_RATE_LIMIT_PER_MINUTE")
    onboarding_rate_limit_per_minute: int = Field(default=5, alias="ONBOARDING_RATE_LIMIT_PER_MINUTE")
    wake_rate_limit_per_minute: int = Field(default=20, alias="WAKE_RATE_LIMIT_PER_MINUTE")
    shutdown_poke_request_rate_limit_per_minute: int = Field(
        default=10,
        alias="SHUTDOWN_POKE_REQUEST_RATE_LIMIT_PER_MINUTE",
    )
    shutdown_poke_seen_rate_limit_per_minute: int = Field(
        default=30,
        alias="SHUTDOWN_POKE_SEEN_RATE_LIMIT_PER_MINUTE",
    )
    shutdown_poke_resolve_rate_limit_per_minute: int = Field(
        default=30,
        alias="SHUTDOWN_POKE_RESOLVE_RATE_LIMIT_PER_MINUTE",
    )
    rate_limit_backend: str = Field(default="memory", alias="RATE_LIMIT_BACKEND")
    rate_limit_redis_url: str = Field(default="redis://127.0.0.1:6379/0", alias="RATE_LIMIT_REDIS_URL")
    enable_api_docs: bool = Field(default=False, alias="ENABLE_API_DOCS")
    apns_enabled: bool = Field(default=False, alias="APNS_ENABLED")
    apns_team_id: str | None = Field(default=None, alias="APNS_TEAM_ID")
    apns_key_id: str | None = Field(default=None, alias="APNS_KEY_ID")
    apns_topic: str | None = Field(default=None, alias="APNS_TOPIC")
    apns_environment: Literal["development", "production"] = Field(
        default="development",
        alias="APNS_ENVIRONMENT",
    )
    apns_private_key: str | None = Field(default=None, alias="APNS_PRIVATE_KEY")
    apns_private_key_path: Path | None = Field(default=None, alias="APNS_PRIVATE_KEY_PATH")
    apns_admin_alert_min_visible_interval_seconds: int = Field(
        default=0,
        alias="APNS_ADMIN_ALERT_MIN_VISIBLE_INTERVAL_SECONDS",
    )

    wake_send_max_attempts: int = Field(default=2, alias="WAKE_SEND_MAX_ATTEMPTS")
    wake_send_backoff_ms: int = Field(default=150, alias="WAKE_SEND_BACKOFF_MS")
    power_check_timeout_seconds: float = Field(default=1.5, alias="POWER_CHECK_TIMEOUT_SECONDS")
    power_state_stale_seconds: int = Field(default=20, alias="POWER_STATE_STALE_SECONDS")
    discovery_enabled: bool = Field(default=True, alias="DISCOVERY_ENABLED")
    discovery_rate_limit_per_minute: int = Field(default=6, alias="DISCOVERY_RATE_LIMIT_PER_MINUTE")
    discovery_max_concurrent_probes: int = Field(default=64, alias="DISCOVERY_MAX_CONCURRENT_PROBES")
    discovery_default_host_cap: int = Field(default=256, alias="DISCOVERY_DEFAULT_HOST_CAP")
    discovery_default_tcp_ports: str = Field(default="22,80,443,445", alias="DISCOVERY_DEFAULT_TCP_PORTS")
    discovery_run_timeout_seconds: int = Field(default=120, alias="DISCOVERY_RUN_TIMEOUT_SECONDS")
    scheduled_wake_runner: bool = Field(default=False, alias="SCHEDULED_WAKE_RUNNER")
    scheduled_wake_poll_seconds: float = Field(default=10.0, alias="SCHEDULED_WAKE_POLL_SECONDS")
    scheduled_wake_max_jobs_per_poll: int = Field(default=10, alias="SCHEDULED_WAKE_MAX_JOBS_PER_POLL")

    @property
    def db_path(self) -> Path:
        return self.data_dir / self.db_filename

    @property
    def allowed_cidrs(self) -> list[str]:
        return _split_csv(self.ip_allowlist_cidrs)

    @property
    def trusted_proxy_cidrs_list(self) -> list[str]:
        return _split_csv(self.trusted_proxy_cidrs)

    @property
    def private_http_allowed_cidrs_list(self) -> list[str]:
        return _split_csv(self.private_http_allowed_cidrs)

    @property
    def admin_allowed_cidrs_list(self) -> list[str]:
        return _split_csv(self.admin_ip_allowlist_cidrs)

    @property
    def parsed_admin_allowed_cidrs(self) -> list[str]:
        valid, invalid = _parse_cidrs(self.admin_ip_allowlist_cidrs)
        if invalid:
            invalid_values = ", ".join(invalid)
            raise ValueError(
                "ADMIN_IP_ALLOWLIST_CIDRS contains invalid CIDR entries: "
                f"{invalid_values}. Set ADMIN_IP_ALLOWLIST_CIDRS to a comma-separated list of valid CIDRs."
            )
        if not valid:
            raise ValueError(
                "ADMIN_IP_ALLOWLIST_CIDRS is empty. Set ADMIN_IP_ALLOWLIST_CIDRS to a comma-separated list of "
                "valid CIDRs."
            )
        return valid

    @property
    def discovery_default_tcp_ports_list(self) -> list[int]:
        ports: list[int] = []
        for part in self.discovery_default_tcp_ports.split(","):
            text = part.strip()
            if not text:
                continue
            try:
                value = int(text)
            except ValueError:
                continue
            if 1 <= value <= 65535:
                ports.append(value)
        return ports or [22, 80, 443, 445]

    @property
    def apns_private_key_text(self) -> str | None:
        if self.apns_private_key:
            return self.apns_private_key.replace("\\n", "\n").strip() or None
        if self.apns_private_key_path and self.apns_private_key_path.exists():
            return self.apns_private_key_path.read_text(encoding="utf-8").strip() or None
        return None

    @property
    def app_proof_android_allowed_cert_sha256_list(self) -> list[str]:
        return _split_csv(self.app_proof_android_allowed_cert_sha256)

    @property
    def app_proof_android_service_account_json_dict(self) -> dict[str, object] | None:
        raw = self.app_proof_android_service_account_json
        if raw:
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return None
        if self.app_proof_android_service_account_json_path and self.app_proof_android_service_account_json_path.exists():
            try:
                return json.loads(self.app_proof_android_service_account_json_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return None
        return None

    @property
    def app_proof_ios_app_id(self) -> str:
        if not self.app_proof_ios_team_id or not self.app_proof_ios_bundle_id:
            return ""
        return f"{self.app_proof_ios_team_id}.{self.app_proof_ios_bundle_id}"


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    return settings
