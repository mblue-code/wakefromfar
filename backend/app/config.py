from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_secret: str = Field(default="change-me", alias="APP_SECRET")
    token_expires_seconds: int = Field(default=28_800, alias="TOKEN_EXPIRES_SECONDS")

    data_dir: Path = Field(default=Path("/data"), alias="DATA_DIR")
    db_filename: str = Field(default="wol.db", alias="DB_FILENAME")

    admin_user: str | None = Field(default=None, alias="ADMIN_USER")
    admin_pass: str | None = Field(default=None, alias="ADMIN_PASS")

    enforce_ip_allowlist: bool = Field(default=False, alias="ENFORCE_IP_ALLOWLIST")
    ip_allowlist_cidrs: str = Field(
        default="100.64.0.0/10,fd7a:115c:a1e0::/48,127.0.0.1/32,::1/128",
        alias="IP_ALLOWLIST_CIDRS",
    )
    trust_proxy_headers: bool = Field(default=False, alias="TRUST_PROXY_HEADERS")
    trusted_proxy_cidrs: str = Field(default="127.0.0.1/32,::1/128", alias="TRUSTED_PROXY_CIDRS")

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

    @property
    def db_path(self) -> Path:
        return self.data_dir / self.db_filename

    @property
    def allowed_cidrs(self) -> list[str]:
        return [part.strip() for part in self.ip_allowlist_cidrs.split(",") if part.strip()]

    @property
    def trusted_proxy_cidrs_list(self) -> list[str]:
        return [part.strip() for part in self.trusted_proxy_cidrs.split(",") if part.strip()]

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


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    return settings
