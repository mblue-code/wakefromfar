from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Generator, Literal

from .config import get_settings


@contextmanager
def get_conn() -> Generator[sqlite3.Connection, None, None]:
    settings = get_settings()
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _table_has_column(conn: sqlite3.Connection, table_name: str, column_name: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return any(row["name"] == column_name for row in rows)


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1",
        (table_name,),
    ).fetchone()
    return row is not None


_APP_TABLES = [
    "ios_app_attest_keys",
    "app_installations",
    "app_proof_challenges",
    "notification_devices",
    "shutdown_poke_requests",
    "activity_events",
    "discovery_events",
    "discovery_candidates",
    "discovery_runs",
    "admin_audit_logs",
    "power_check_logs",
    "wake_logs",
    "scheduled_wake_runs",
    "scheduled_wake_jobs",
    "invite_tokens",
    "device_memberships",
    "user_device_access",
    "hosts",
    "users",
    "schema_migrations",
    "ios_entitlements",
]


def _device_membership_columns(conn: sqlite3.Connection) -> set[str]:
    if not _table_exists(conn, "device_memberships"):
        return set()
    rows = conn.execute("PRAGMA table_info(device_memberships)").fetchall()
    return {str(row["name"]) for row in rows}


def _schema_requires_reset(conn: sqlite3.Connection) -> bool:
    if _table_exists(conn, "schema_migrations"):
        return True
    if _table_exists(conn, "user_device_access"):
        return True
    if _table_exists(conn, "hosts") and not _table_has_column(conn, "hosts", "updated_at"):
        return True
    membership_columns = _device_membership_columns(conn)
    if membership_columns and membership_columns != {
        "id",
        "user_id",
        "device_id",
        "can_view_status",
        "can_wake",
        "can_request_shutdown",
        "can_manage_schedule",
        "is_favorite",
        "sort_order",
        "created_at",
        "updated_at",
    }:
        return True
    return False


def _reset_app_schema(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA foreign_keys = OFF")
    for table_name in _APP_TABLES:
        conn.execute(f"DROP TABLE IF EXISTS {table_name}")
    conn.execute("PRAGMA foreign_keys = ON")


def _create_schema(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
            token_version INTEGER NOT NULL DEFAULT 0,
            mfa_enabled INTEGER NOT NULL DEFAULT 0 CHECK(mfa_enabled IN (0, 1)),
            mfa_totp_secret_encrypted TEXT,
            mfa_enabled_at TEXT,
            mfa_updated_at TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS hosts (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            display_name TEXT,
            mac TEXT NOT NULL,
            group_name TEXT,
            broadcast TEXT,
            subnet_cidr TEXT,
            udp_port INTEGER NOT NULL DEFAULT 9,
            interface TEXT,
            source_ip TEXT,
            source_network_cidr TEXT,
            check_method TEXT NOT NULL CHECK(check_method IN ('tcp', 'icmp')) DEFAULT 'tcp',
            check_target TEXT,
            check_port INTEGER,
            last_power_state TEXT NOT NULL CHECK(last_power_state IN ('on', 'off', 'unknown')) DEFAULT 'unknown',
            last_power_checked_at TEXT,
            provisioning_source TEXT NOT NULL DEFAULT 'manual' CHECK(provisioning_source IN ('manual', 'discovery')),
            discovery_confidence TEXT CHECK(discovery_confidence IN ('high', 'medium', 'low', 'unknown')),
            last_discovered_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS device_memberships (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            device_id TEXT NOT NULL,
            can_view_status INTEGER NOT NULL DEFAULT 1 CHECK(can_view_status IN (0, 1)),
            can_wake INTEGER NOT NULL DEFAULT 1 CHECK(can_wake IN (0, 1)),
            can_request_shutdown INTEGER NOT NULL DEFAULT 1 CHECK(can_request_shutdown IN (0, 1)),
            can_manage_schedule INTEGER NOT NULL DEFAULT 0 CHECK(can_manage_schedule IN (0, 1)),
            is_favorite INTEGER NOT NULL DEFAULT 0 CHECK(is_favorite IN (0, 1)),
            sort_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(user_id, device_id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(device_id) REFERENCES hosts(id)
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_device_memberships_user_sort "
        "ON device_memberships(user_id, is_favorite DESC, sort_order ASC, updated_at DESC, device_id ASC)"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_device_memberships_device_id ON device_memberships(device_id)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS wake_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id TEXT NOT NULL,
            actor_username TEXT NOT NULL,
            sent_to TEXT NOT NULL,
            created_at TEXT NOT NULL,
            result TEXT NOT NULL DEFAULT 'sent',
            error_detail TEXT,
            precheck_state TEXT NOT NULL DEFAULT 'unknown',
            FOREIGN KEY(host_id) REFERENCES hosts(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scheduled_wake_jobs (
            id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            created_by_user_id INTEGER NOT NULL,
            label TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
            timezone TEXT NOT NULL,
            days_of_week_json TEXT NOT NULL,
            local_time TEXT NOT NULL,
            next_run_at TEXT,
            last_run_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scheduled_wake_jobs_enabled_next_run "
        "ON scheduled_wake_jobs(enabled, next_run_at)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scheduled_wake_jobs_device_enabled "
        "ON scheduled_wake_jobs(device_id, enabled)"
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scheduled_wake_runs (
            id TEXT PRIMARY KEY,
            job_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            result TEXT NOT NULL CHECK(result IN ('sent', 'already_on', 'failed', 'skipped')),
            detail TEXT,
            wake_log_id INTEGER
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scheduled_wake_runs_job_started_at "
        "ON scheduled_wake_runs(job_id, started_at DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scheduled_wake_runs_device_started_at "
        "ON scheduled_wake_runs(device_id, started_at DESC)"
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS invite_tokens (
            id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL,
            username TEXT NOT NULL,
            backend_url_hint TEXT,
            expires_at TEXT NOT NULL,
            claimed_at TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS power_check_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            method TEXT NOT NULL CHECK(method IN ('tcp', 'icmp')),
            result TEXT NOT NULL CHECK(result IN ('on', 'off', 'unknown')),
            detail TEXT NOT NULL,
            latency_ms INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY(device_id) REFERENCES hosts(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS admin_audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_username TEXT NOT NULL,
            action TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            detail TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS discovery_runs (
            id TEXT PRIMARY KEY,
            requested_by TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('queued','running','completed','failed','canceled')),
            options_json TEXT NOT NULL,
            summary_json TEXT,
            started_at TEXT,
            finished_at TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS discovery_candidates (
            id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            hostname TEXT,
            mac TEXT,
            ip TEXT,
            source_interface TEXT,
            source_ip TEXT,
            source_network_cidr TEXT,
            broadcast_ip TEXT,
            wol_confidence TEXT NOT NULL CHECK(wol_confidence IN ('high','medium','low','unknown')),
            power_check_method TEXT,
            power_check_target TEXT,
            power_check_port INTEGER,
            power_data_source TEXT NOT NULL DEFAULT 'inferred' CHECK(power_data_source IN ('none','inferred','agent','api')),
            imported_host_id TEXT,
            notes_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(run_id) REFERENCES discovery_runs(id),
            FOREIGN KEY(imported_host_id) REFERENCES hosts(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS discovery_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            candidate_id TEXT,
            event_type TEXT NOT NULL,
            detail TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(run_id) REFERENCES discovery_runs(id),
            FOREIGN KEY(candidate_id) REFERENCES discovery_candidates(id)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_discovery_runs_created_at ON discovery_runs(created_at DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_discovery_runs_status ON discovery_runs(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_discovery_candidates_run_id ON discovery_candidates(run_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_discovery_candidates_mac ON discovery_candidates(mac)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_discovery_candidates_ip ON discovery_candidates(ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_discovery_candidates_imported_host_id ON discovery_candidates(imported_host_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_discovery_events_run_id ON discovery_events(run_id, id DESC)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS activity_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            actor_user_id INTEGER,
            actor_username TEXT,
            target_type TEXT NOT NULL,
            target_id TEXT,
            server_id TEXT,
            summary TEXT NOT NULL,
            metadata_json TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(actor_user_id) REFERENCES users(id),
            FOREIGN KEY(server_id) REFERENCES hosts(id)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_activity_events_created_at ON activity_events(created_at DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_activity_events_event_type_created_at ON activity_events(event_type, created_at DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_activity_events_server_id_created_at ON activity_events(server_id, created_at DESC)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS shutdown_poke_requests (
            id TEXT PRIMARY KEY,
            server_id TEXT NOT NULL,
            requester_user_id INTEGER NOT NULL,
            requester_username TEXT NOT NULL,
            message TEXT,
            status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'seen', 'resolved')),
            created_at TEXT NOT NULL,
            seen_at TEXT,
            resolved_at TEXT,
            resolved_by_user_id INTEGER,
            FOREIGN KEY(server_id) REFERENCES hosts(id),
            FOREIGN KEY(requester_user_id) REFERENCES users(id),
            FOREIGN KEY(resolved_by_user_id) REFERENCES users(id)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_shutdown_poke_requests_status_created_at ON shutdown_poke_requests(status, created_at DESC)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS notification_devices (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            installation_id TEXT NOT NULL,
            platform TEXT NOT NULL CHECK(platform IN ('ios')),
            provider TEXT NOT NULL CHECK(provider IN ('apns')),
            token TEXT NOT NULL,
            app_bundle_id TEXT NOT NULL,
            environment TEXT NOT NULL CHECK(environment IN ('development', 'production')),
            is_active INTEGER NOT NULL DEFAULT 1,
            last_registered_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            last_alert_sent_at TEXT,
            suppressed_shutdown_count INTEGER NOT NULL DEFAULT 0,
            invalidated_at TEXT,
            invalidation_reason TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(installation_id, provider)
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_notification_devices_user_active "
        "ON notification_devices(user_id, is_active, updated_at DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_notification_devices_provider_env_active "
        "ON notification_devices(provider, environment, is_active, updated_at DESC)"
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS app_proof_challenges (
            id TEXT PRIMARY KEY,
            purpose TEXT NOT NULL CHECK(purpose IN ('enroll', 'login', 'reauth')),
            platform TEXT NOT NULL CHECK(platform IN ('android', 'ios')),
            installation_id TEXT NOT NULL,
            username_hint TEXT,
            challenge_nonce TEXT NOT NULL,
            app_version TEXT,
            os_version TEXT,
            client_ip TEXT,
            expires_at TEXT NOT NULL,
            consumed_at TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_app_proof_challenges_installation_created "
        "ON app_proof_challenges(installation_id, created_at DESC)"
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS app_installations (
            installation_id TEXT PRIMARY KEY,
            platform TEXT NOT NULL CHECK(platform IN ('android', 'ios')),
            status TEXT NOT NULL CHECK(status IN ('pending', 'trusted', 'report_only', 'revoked')),
            user_id INTEGER,
            session_version INTEGER NOT NULL DEFAULT 1,
            proof_method TEXT,
            app_id TEXT,
            app_version TEXT,
            os_version TEXT,
            last_verified_at TEXT,
            last_login_at TEXT,
            last_seen_ip TEXT,
            last_provider_status TEXT,
            last_provider_error TEXT,
            last_verdict_json TEXT,
            last_failure_reason TEXT,
            last_failure_detail TEXT,
            last_failure_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            revoked_at TEXT,
            revoked_reason TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_app_installations_user_updated "
        "ON app_installations(user_id, updated_at DESC)"
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ios_app_attest_keys (
            installation_id TEXT PRIMARY KEY,
            key_id TEXT NOT NULL,
            public_key_pem TEXT NOT NULL,
            sign_count INTEGER NOT NULL DEFAULT 0,
            receipt_b64 TEXT,
            last_asserted_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(installation_id) REFERENCES app_installations(installation_id)
        )
        """
    )


def init_db() -> None:
    with get_conn() as conn:
        if _schema_requires_reset(conn):
            _reset_app_schema(conn)
        _create_schema(conn)
        _ensure_user_mfa_columns(conn)
        _ensure_app_installation_columns(conn)


def _ensure_user_mfa_columns(conn: sqlite3.Connection) -> None:
    if not _table_has_column(conn, "users", "mfa_enabled"):
        conn.execute(
            "ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0 CHECK(mfa_enabled IN (0, 1))"
        )
    if not _table_has_column(conn, "users", "mfa_totp_secret_encrypted"):
        conn.execute("ALTER TABLE users ADD COLUMN mfa_totp_secret_encrypted TEXT")
    if not _table_has_column(conn, "users", "mfa_enabled_at"):
        conn.execute("ALTER TABLE users ADD COLUMN mfa_enabled_at TEXT")
    if not _table_has_column(conn, "users", "mfa_updated_at"):
        conn.execute("ALTER TABLE users ADD COLUMN mfa_updated_at TEXT")


def _ensure_app_installation_columns(conn: sqlite3.Connection) -> None:
    if not _table_exists(conn, "app_installations"):
        return
    if not _table_has_column(conn, "app_installations", "last_failure_reason"):
        conn.execute("ALTER TABLE app_installations ADD COLUMN last_failure_reason TEXT")
    if not _table_has_column(conn, "app_installations", "last_failure_detail"):
        conn.execute("ALTER TABLE app_installations ADD COLUMN last_failure_detail TEXT")
    if not _table_has_column(conn, "app_installations", "last_failure_at"):
        conn.execute("ALTER TABLE app_installations ADD COLUMN last_failure_at TEXT")


def get_user_by_id(user_id: int) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def list_users() -> list[sqlite3.Row]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, username, role, created_at FROM users ORDER BY username COLLATE NOCASE ASC"
        ).fetchall()
        return list(rows)


def count_admin_users() -> int:
    with get_conn() as conn:
        row = conn.execute("SELECT COUNT(*) AS cnt FROM users WHERE role = 'admin'").fetchone()
        return int(row["cnt"] if row else 0)


def update_user_password(username: str, password_hash: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE users SET password_hash = ?, token_version = COALESCE(token_version, 0) + 1 WHERE username = ?",
            (password_hash, username),
        )
        return cur.rowcount > 0


def update_user_password_by_id(user_id: int, password_hash: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE users SET password_hash = ?, token_version = COALESCE(token_version, 0) + 1 WHERE id = ?",
            (password_hash, user_id),
        )
        return cur.rowcount > 0


def update_user_role(user_id: int, role: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE users SET role = ? WHERE id = ?",
            (role, user_id),
        )
        return cur.rowcount > 0


def delete_user(user_id: int) -> bool:
    with get_conn() as conn:
        conn.execute("DELETE FROM device_memberships WHERE user_id = ?", (user_id,))
        cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        return cur.rowcount > 0


def get_user_by_username(username: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def enable_user_mfa(user_id: int, encrypted_secret: str) -> bool:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE users
            SET mfa_enabled = 1,
                mfa_totp_secret_encrypted = ?,
                mfa_enabled_at = COALESCE(mfa_enabled_at, ?),
                mfa_updated_at = ?
            WHERE id = ?
            """,
            (encrypted_secret, now, now, user_id),
        )
        return cur.rowcount > 0


def disable_user_mfa_by_username(username: str) -> bool:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE users
            SET mfa_enabled = 0,
                mfa_totp_secret_encrypted = NULL,
                mfa_enabled_at = NULL,
                mfa_updated_at = ?,
                token_version = COALESCE(token_version, 0) + 1
            WHERE username = ? AND role = 'admin'
            """,
            (now, username),
        )
        return cur.rowcount > 0


def create_user(username: str, password_hash: str, role: str) -> int:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO users(
                username,
                password_hash,
                role,
                token_version,
                mfa_enabled,
                mfa_totp_secret_encrypted,
                mfa_enabled_at,
                mfa_updated_at,
                created_at
            ) VALUES (?, ?, ?, 0, 0, NULL, NULL, NULL, ?)
            """,
            (username, password_hash, role, now),
        )
        return int(cur.lastrowid)


def upsert_admin(username: str, password_hash: str) -> None:
    existing = get_user_by_username(username)
    if existing:
        return
    create_user(username=username, password_hash=password_hash, role="admin")


def issue_app_proof_challenge(
    *,
    challenge_id: str,
    purpose: str,
    platform: str,
    installation_id: str,
    username_hint: str | None,
    challenge_nonce: str,
    expires_in_seconds: int,
    client_ip: str | None,
    app_version: str | None,
    os_version: str | None,
) -> sqlite3.Row:
    now = datetime.now(UTC)
    expires_at = now + timedelta(seconds=expires_in_seconds)
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO app_proof_challenges(
                id,
                purpose,
                platform,
                installation_id,
                username_hint,
                challenge_nonce,
                app_version,
                os_version,
                client_ip,
                expires_at,
                consumed_at,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
            """,
            (
                challenge_id,
                purpose,
                platform,
                installation_id,
                username_hint,
                challenge_nonce,
                app_version,
                os_version,
                client_ip,
                expires_at.isoformat(),
                now.isoformat(),
            ),
        )
        return conn.execute("SELECT * FROM app_proof_challenges WHERE id = ?", (challenge_id,)).fetchone()


def get_app_proof_challenge(challenge_id: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM app_proof_challenges WHERE id = ?", (challenge_id,)).fetchone()


def consume_app_proof_challenge(challenge_id: str) -> sqlite3.Row | None:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE app_proof_challenges
            SET consumed_at = ?
            WHERE id = ? AND consumed_at IS NULL
            """,
            (now, challenge_id),
        )
        if cur.rowcount <= 0:
            return None
        return conn.execute("SELECT * FROM app_proof_challenges WHERE id = ?", (challenge_id,)).fetchone()


def mark_app_proof_challenge_consumed(challenge_id: str, *, consume_even_if_missing: bool = True) -> bool:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE app_proof_challenges
            SET consumed_at = COALESCE(consumed_at, ?)
            WHERE id = ?
            """,
            (now, challenge_id),
        )
        if consume_even_if_missing:
            return cur.rowcount > 0
        row = conn.execute("SELECT consumed_at FROM app_proof_challenges WHERE id = ?", (challenge_id,)).fetchone()
        return row is not None


def get_app_installation(installation_id: str | None) -> sqlite3.Row | None:
    if not installation_id:
        return None
    with get_conn() as conn:
        return conn.execute("SELECT * FROM app_installations WHERE installation_id = ?", (installation_id,)).fetchone()


def list_app_installations(
    *,
    user_id: int | None = None,
    platform: str | None = None,
    status: str | None = None,
    limit: int | None = None,
) -> list[sqlite3.Row]:
    query = "SELECT * FROM app_installations"
    filters: list[str] = []
    params: list[object] = []
    if user_id is not None:
        filters.append("user_id = ?")
        params.append(user_id)
    if platform is not None:
        filters.append("platform = ?")
        params.append(platform)
    if status is not None:
        filters.append("status = ?")
        params.append(status)
    if filters:
        query += " WHERE " + " AND ".join(filters)
    query += " ORDER BY updated_at DESC, installation_id ASC"
    if limit is not None:
        query += " LIMIT ?"
        params.append(limit)
    with get_conn() as conn:
        return list(conn.execute(query, tuple(params)).fetchall())


def _upsert_app_installation(
    *,
    installation_id: str,
    platform: str,
    status: str,
    proof_method: str,
    app_id: str | None,
    app_version: str | None,
    os_version: str | None,
    client_ip: str | None,
    provider_status: str | None,
    provider_error: str | None,
    verdict_json: str | None,
) -> sqlite3.Row:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT installation_id, session_version FROM app_installations WHERE installation_id = ?",
            (installation_id,),
        ).fetchone()
        if existing:
            conn.execute(
                """
                UPDATE app_installations
                SET platform = ?,
                    status = CASE WHEN status = 'revoked' THEN status ELSE ? END,
                    proof_method = ?,
                    app_id = ?,
                    app_version = ?,
                    os_version = ?,
                    last_verified_at = ?,
                    last_seen_ip = ?,
                    last_provider_status = ?,
                    last_provider_error = ?,
                    last_verdict_json = ?,
                    last_failure_reason = NULL,
                    last_failure_detail = NULL,
                    last_failure_at = NULL,
                    updated_at = ?
                WHERE installation_id = ?
                """,
                (
                    platform,
                    status,
                    proof_method,
                    app_id,
                    app_version,
                    os_version,
                    now,
                    client_ip,
                    provider_status,
                    provider_error,
                    verdict_json,
                    now,
                    installation_id,
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO app_installations(
                    installation_id,
                    platform,
                    status,
                    user_id,
                    session_version,
                    proof_method,
                    app_id,
                    app_version,
                    os_version,
                    last_verified_at,
                    last_login_at,
                    last_seen_ip,
                    last_provider_status,
                    last_provider_error,
                    last_verdict_json,
                    last_failure_reason,
                    last_failure_detail,
                    last_failure_at,
                    created_at,
                    updated_at,
                    revoked_at,
                    revoked_reason
                ) VALUES (?, ?, ?, NULL, 1, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?, NULL, NULL)
                """,
                (
                    installation_id,
                    platform,
                    status,
                    proof_method,
                    app_id,
                    app_version,
                    os_version,
                    now,
                    client_ip,
                    provider_status,
                    provider_error,
                    verdict_json,
                    now,
                    now,
                ),
            )
        return conn.execute("SELECT * FROM app_installations WHERE installation_id = ?", (installation_id,)).fetchone()


def record_android_attestation(
    *,
    installation_id: str,
    app_id: str,
    app_version: str | None,
    os_version: str | None,
    client_ip: str | None,
    provider_status: str | None,
    provider_error: str | None,
    verdict_json: str | None,
) -> sqlite3.Row:
    return _upsert_app_installation(
        installation_id=installation_id,
        platform="android",
        status="trusted",
        proof_method="android_play_integrity",
        app_id=app_id,
        app_version=app_version,
        os_version=os_version,
        client_ip=client_ip,
        provider_status=provider_status,
        provider_error=provider_error,
        verdict_json=verdict_json,
    )


def record_ios_app_attest_enrollment(
    *,
    installation_id: str,
    key_id: str,
    public_key_pem: str,
    receipt_b64: str | None,
    app_id: str,
    app_version: str | None,
    os_version: str | None,
    client_ip: str | None,
    provider_status: str | None,
    provider_error: str | None,
    verdict_json: str | None,
) -> sqlite3.Row:
    installation = _upsert_app_installation(
        installation_id=installation_id,
        platform="ios",
        status="trusted",
        proof_method="ios_app_attest",
        app_id=app_id,
        app_version=app_version,
        os_version=os_version,
        client_ip=client_ip,
        provider_status=provider_status,
        provider_error=provider_error,
        verdict_json=verdict_json,
    )
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT installation_id FROM ios_app_attest_keys WHERE installation_id = ?",
            (installation_id,),
        ).fetchone()
        if existing:
            conn.execute(
                """
                UPDATE ios_app_attest_keys
                SET key_id = ?,
                    public_key_pem = ?,
                    sign_count = 0,
                    receipt_b64 = ?,
                    updated_at = ?
                WHERE installation_id = ?
                """,
                (key_id, public_key_pem, receipt_b64, now, installation_id),
            )
        else:
            conn.execute(
                """
                INSERT INTO ios_app_attest_keys(
                    installation_id,
                    key_id,
                    public_key_pem,
                    sign_count,
                    receipt_b64,
                    last_asserted_at,
                    created_at,
                    updated_at
                ) VALUES (?, ?, ?, 0, ?, NULL, ?, ?)
                """,
                (installation_id, key_id, public_key_pem, receipt_b64, now, now),
            )
    return installation


def get_ios_app_attest_key(installation_id: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM ios_app_attest_keys WHERE installation_id = ?",
            (installation_id,),
        ).fetchone()


def record_ios_app_attest_assertion(
    *,
    installation_id: str,
    sign_count: int,
    app_version: str | None,
    os_version: str | None,
    client_ip: str | None,
    provider_status: str | None,
    provider_error: str | None,
    verdict_json: str | None,
) -> sqlite3.Row:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE ios_app_attest_keys
            SET sign_count = ?,
                last_asserted_at = ?,
                updated_at = ?
            WHERE installation_id = ?
            """,
            (sign_count, now, now, installation_id),
        )
        conn.execute(
            """
            UPDATE app_installations
            SET status = CASE WHEN status = 'revoked' THEN status ELSE 'trusted' END,
                proof_method = 'ios_app_attest',
                app_version = COALESCE(?, app_version),
                os_version = COALESCE(?, os_version),
                last_verified_at = ?,
                last_seen_ip = ?,
                last_provider_status = ?,
                last_provider_error = ?,
                last_verdict_json = ?,
                last_failure_reason = NULL,
                last_failure_detail = NULL,
                last_failure_at = NULL,
                updated_at = ?
            WHERE installation_id = ?
            """,
            (
                app_version,
                os_version,
                now,
                client_ip,
                provider_status,
                provider_error,
                verdict_json,
                now,
                installation_id,
            ),
        )
        return conn.execute("SELECT * FROM app_installations WHERE installation_id = ?", (installation_id,)).fetchone()


def update_installation_after_login(*, installation_id: str, user_id: int, client_ip: str | None) -> sqlite3.Row:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE app_installations
            SET user_id = ?,
                last_login_at = ?,
                last_seen_ip = ?,
                updated_at = ?
            WHERE installation_id = ?
            """,
            (user_id, now, client_ip, now, installation_id),
        )
        return conn.execute("SELECT * FROM app_installations WHERE installation_id = ?", (installation_id,)).fetchone()


def record_app_installation_failure(
    *,
    installation_id: str,
    platform: str,
    reason: str,
    detail: str,
    client_ip: str | None,
    provider_status: str | None = None,
    provider_error: str | None = None,
) -> sqlite3.Row:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT installation_id FROM app_installations WHERE installation_id = ?",
            (installation_id,),
        ).fetchone()
        effective_provider_status = provider_status or "rejected"
        effective_provider_error = provider_error or reason
        if existing:
            conn.execute(
                """
                UPDATE app_installations
                SET platform = ?,
                    last_seen_ip = ?,
                    last_provider_status = ?,
                    last_provider_error = ?,
                    last_failure_reason = ?,
                    last_failure_detail = ?,
                    last_failure_at = ?,
                    updated_at = ?
                WHERE installation_id = ?
                """,
                (
                    platform,
                    client_ip,
                    effective_provider_status,
                    effective_provider_error,
                    reason,
                    detail,
                    now,
                    now,
                    installation_id,
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO app_installations(
                    installation_id,
                    platform,
                    status,
                    user_id,
                    session_version,
                    proof_method,
                    app_id,
                    app_version,
                    os_version,
                    last_verified_at,
                    last_login_at,
                    last_seen_ip,
                    last_provider_status,
                    last_provider_error,
                    last_verdict_json,
                    last_failure_reason,
                    last_failure_detail,
                    last_failure_at,
                    created_at,
                    updated_at,
                    revoked_at,
                    revoked_reason
                ) VALUES (?, ?, 'pending', NULL, 1, NULL, NULL, NULL, NULL, NULL, NULL, ?, ?, ?, NULL, ?, ?, ?, ?, ?, NULL, NULL)
                """,
                (
                    installation_id,
                    platform,
                    client_ip,
                    effective_provider_status,
                    effective_provider_error,
                    reason,
                    detail,
                    now,
                    now,
                    now,
                ),
            )
        return conn.execute("SELECT * FROM app_installations WHERE installation_id = ?", (installation_id,)).fetchone()


def revoke_app_installation(installation_id: str, *, reason: str | None) -> sqlite3.Row | None:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE app_installations
            SET status = 'revoked',
                session_version = COALESCE(session_version, 0) + 1,
                last_failure_reason = 'revoked',
                last_failure_detail = COALESCE(?, ''),
                last_failure_at = ?,
                revoked_at = ?,
                revoked_reason = ?,
                updated_at = ?
            WHERE installation_id = ?
            """,
            (reason, now, now, reason, now, installation_id),
        )
        if cur.rowcount <= 0:
            return None
        return conn.execute("SELECT * FROM app_installations WHERE installation_id = ?", (installation_id,)).fetchone()


_DEVICE_SELECT_COLUMNS = """
                h.id,
                h.name,
                h.mac,
                h.group_name,
                h.broadcast,
                h.subnet_cidr,
                h.udp_port,
                h.interface,
                h.source_ip,
                h.source_network_cidr,
                h.created_at,
                h.updated_at,
                h.display_name,
                h.check_method,
                h.check_target,
                h.check_port,
                h.last_power_state,
                h.last_power_checked_at,
                h.provisioning_source,
                h.discovery_confidence,
                h.last_discovered_at,
                sws.total_count AS scheduled_wake_total_count,
                sws.enabled_count AS scheduled_wake_enabled_count,
                sws.next_run_at AS scheduled_wake_next_run_at
"""

_DEVICE_SCHEDULE_SUMMARY_JOIN = """
            LEFT JOIN (
                SELECT
                    device_id,
                    COUNT(*) AS total_count,
                    SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) AS enabled_count,
                    MIN(CASE WHEN enabled = 1 THEN next_run_at END) AS next_run_at
                FROM scheduled_wake_jobs
                GROUP BY device_id
            ) sws ON sws.device_id = h.id
"""


def list_hosts() -> list[sqlite3.Row]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT
{columns}
            FROM hosts h
{schedule_join}
            ORDER BY COALESCE(NULLIF(display_name, ''), name) COLLATE NOCASE ASC, id ASC
            """.format(columns=_DEVICE_SELECT_COLUMNS, schedule_join=_DEVICE_SCHEDULE_SUMMARY_JOIN)
        ).fetchall()
        return list(rows)


def list_visible_devices_for_user(user_id: int) -> list[sqlite3.Row]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT
{columns},
                dm.id AS membership_id,
                dm.can_view_status,
                dm.can_wake,
                dm.can_request_shutdown,
                dm.can_manage_schedule,
                dm.is_favorite,
                dm.sort_order,
                dm.created_at AS membership_created_at,
                dm.updated_at AS membership_updated_at
            FROM hosts h
            INNER JOIN device_memberships dm ON dm.device_id = h.id
{schedule_join}
            WHERE dm.user_id = ?
            ORDER BY
                dm.is_favorite DESC,
                CASE
                    WHEN dm.is_favorite = 1 THEN 0
                    WHEN NULLIF(h.group_name, '') IS NULL THEN 1
                    ELSE 0
                END ASC,
                CASE
                    WHEN dm.is_favorite = 1 OR NULLIF(h.group_name, '') IS NULL THEN ''
                    ELSE h.group_name
                END COLLATE NOCASE ASC,
                dm.sort_order ASC,
                COALESCE(NULLIF(h.display_name, ''), h.name) COLLATE NOCASE ASC,
                h.id ASC
            """.format(columns=_DEVICE_SELECT_COLUMNS, schedule_join=_DEVICE_SCHEDULE_SUMMARY_JOIN),
            (user_id,),
        ).fetchall()
        return list(rows)


def get_visible_device_for_user(user_id: int, device_id: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT
{columns},
                dm.id AS membership_id,
                dm.can_view_status,
                dm.can_wake,
                dm.can_request_shutdown,
                dm.can_manage_schedule,
                dm.is_favorite,
                dm.sort_order,
                dm.created_at AS membership_created_at,
                dm.updated_at AS membership_updated_at
            FROM hosts h
            INNER JOIN device_memberships dm ON dm.device_id = h.id
{schedule_join}
            WHERE dm.user_id = ? AND h.id = ?
            """.format(columns=_DEVICE_SELECT_COLUMNS, schedule_join=_DEVICE_SCHEDULE_SUMMARY_JOIN),
            (user_id, device_id),
        ).fetchone()


def list_all_devices_for_user_preferences(user_id: int) -> list[sqlite3.Row]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT
{columns},
                dm.id AS membership_id,
                dm.can_view_status,
                dm.can_wake,
                dm.can_request_shutdown,
                dm.can_manage_schedule,
                dm.is_favorite,
                dm.sort_order,
                dm.created_at AS membership_created_at,
                dm.updated_at AS membership_updated_at
            FROM hosts h
            LEFT JOIN device_memberships dm
                ON dm.device_id = h.id AND dm.user_id = ?
{schedule_join}
            ORDER BY
                COALESCE(dm.is_favorite, 0) DESC,
                CASE
                    WHEN COALESCE(dm.is_favorite, 0) = 1 THEN 0
                    WHEN NULLIF(h.group_name, '') IS NULL THEN 1
                    ELSE 0
                END ASC,
                CASE
                    WHEN COALESCE(dm.is_favorite, 0) = 1 OR NULLIF(h.group_name, '') IS NULL THEN ''
                    ELSE h.group_name
                END COLLATE NOCASE ASC,
                COALESCE(dm.sort_order, 0) ASC,
                COALESCE(NULLIF(h.display_name, ''), h.name) COLLATE NOCASE ASC,
                h.id ASC
            """.format(columns=_DEVICE_SELECT_COLUMNS, schedule_join=_DEVICE_SCHEDULE_SUMMARY_JOIN),
            (user_id,),
        ).fetchall()
        return list(rows)


def get_device_for_user_preferences(user_id: int, device_id: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT
{columns},
                dm.id AS membership_id,
                dm.can_view_status,
                dm.can_wake,
                dm.can_request_shutdown,
                dm.can_manage_schedule,
                dm.is_favorite,
                dm.sort_order,
                dm.created_at AS membership_created_at,
                dm.updated_at AS membership_updated_at
            FROM hosts h
            LEFT JOIN device_memberships dm
                ON dm.device_id = h.id AND dm.user_id = ?
{schedule_join}
            WHERE h.id = ?
            """.format(columns=_DEVICE_SELECT_COLUMNS, schedule_join=_DEVICE_SCHEDULE_SUMMARY_JOIN),
            (user_id, device_id),
        ).fetchone()


def get_host_by_id(host_id: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()


def get_host_by_mac(mac: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM hosts WHERE mac = ? ORDER BY created_at ASC LIMIT 1",
            (mac,),
        ).fetchone()


def create_device_membership(
    *,
    user_id: int,
    device_id: str,
    can_view_status: bool = True,
    can_wake: bool = True,
    can_request_shutdown: bool = True,
    can_manage_schedule: bool = False,
    is_favorite: bool = False,
    sort_order: int = 0,
) -> sqlite3.Row:
    membership_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO device_memberships(
                id,
                user_id,
                device_id,
                can_view_status,
                can_wake,
                can_request_shutdown,
                can_manage_schedule,
                is_favorite,
                sort_order,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                membership_id,
                user_id,
                device_id,
                int(can_view_status),
                int(can_wake),
                int(can_request_shutdown),
                int(can_manage_schedule),
                int(is_favorite),
                sort_order,
                now,
                now,
            ),
        )
        row = conn.execute(
            """
            SELECT
                dm.*,
                u.username,
                h.name AS device_name,
                h.display_name AS device_display_name
            FROM device_memberships dm
            INNER JOIN users u ON u.id = dm.user_id
            INNER JOIN hosts h ON h.id = dm.device_id
            WHERE dm.id = ?
            """,
            (membership_id,),
        ).fetchone()
        if row is None:
            raise RuntimeError("device membership insert failed")
        return row


def update_device_membership(membership_id: str, updates: dict[str, object | None]) -> sqlite3.Row | None:
    if not updates:
        return get_device_membership_by_id(membership_id)
    normalized_updates = dict(updates)
    normalized_updates["updated_at"] = datetime.now(UTC).isoformat()
    columns = ", ".join(f"{key} = ?" for key in normalized_updates.keys())
    values = list(normalized_updates.values())
    values.append(membership_id)
    with get_conn() as conn:
        cur = conn.execute(f"UPDATE device_memberships SET {columns} WHERE id = ?", tuple(values))
        if cur.rowcount == 0:
            return None
    return get_device_membership_by_id(membership_id)


def delete_device_membership(membership_id: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM device_memberships WHERE id = ?", (membership_id,))
        return cur.rowcount > 0


def get_device_membership_by_id(membership_id: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT
                dm.*,
                u.username,
                h.name AS device_name,
                h.display_name AS device_display_name
            FROM device_memberships dm
            INNER JOIN users u ON u.id = dm.user_id
            INNER JOIN hosts h ON h.id = dm.device_id
            WHERE dm.id = ?
            """,
            (membership_id,),
        ).fetchone()


def get_device_membership_for_user_device(user_id: int, device_id: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT
                dm.*,
                u.username,
                h.name AS device_name,
                h.display_name AS device_display_name
            FROM device_memberships dm
            INNER JOIN users u ON u.id = dm.user_id
            INNER JOIN hosts h ON h.id = dm.device_id
            WHERE dm.user_id = ? AND dm.device_id = ?
            """,
            (user_id, device_id),
        ).fetchone()


def list_device_memberships() -> list[sqlite3.Row]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT
                dm.*,
                u.username,
                h.name AS device_name,
                h.display_name AS device_display_name
            FROM device_memberships dm
            INNER JOIN users u ON u.id = dm.user_id
            INNER JOIN hosts h ON h.id = dm.device_id
            ORDER BY
                u.username COLLATE NOCASE ASC,
                COALESCE(NULLIF(h.display_name, ''), h.name) COLLATE NOCASE ASC,
                dm.id ASC
            """
        ).fetchall()
        return list(rows)


def create_host(
    name: str,
    mac: str,
    group_name: str | None,
    broadcast: str | None,
    subnet_cidr: str | None,
    udp_port: int,
    interface: str | None,
    source_ip: str | None,
    source_network_cidr: str | None = None,
    host_id: str | None = None,
    display_name: str | None = None,
    check_method: str = "tcp",
    check_target: str | None = None,
    check_port: int | None = None,
    provisioning_source: str = "manual",
    discovery_confidence: str | None = None,
    last_discovered_at: str | None = None,
) -> str:
    generated_id = host_id or str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO hosts(
                id,
                name,
                mac,
                group_name,
                broadcast,
                subnet_cidr,
                udp_port,
                interface,
                source_ip,
                source_network_cidr,
                created_at,
                updated_at,
                display_name,
                check_method,
                check_target,
                check_port,
                last_power_state,
                last_power_checked_at,
                provisioning_source,
                discovery_confidence,
                last_discovered_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unknown', NULL, ?, ?, ?)
            """,
            (
                generated_id,
                name,
                mac,
                group_name,
                broadcast,
                subnet_cidr,
                udp_port,
                interface,
                source_ip,
                source_network_cidr,
                now,
                now,
                display_name,
                check_method,
                check_target,
                check_port,
                provisioning_source,
                discovery_confidence,
                last_discovered_at,
            ),
        )
    return generated_id


_SCHEDULED_WAKE_JOB_SELECT = """
    SELECT
        j.*,
        h.name AS device_name,
        h.display_name AS device_display_name,
        u.username AS created_by_username,
        (
            SELECT r.result
            FROM scheduled_wake_runs r
            WHERE r.job_id = j.id
            ORDER BY r.started_at DESC, r.id DESC
            LIMIT 1
        ) AS recent_run_result,
        (
            SELECT r.detail
            FROM scheduled_wake_runs r
            WHERE r.job_id = j.id
            ORDER BY r.started_at DESC, r.id DESC
            LIMIT 1
        ) AS recent_run_detail,
        (
            SELECT r.started_at
            FROM scheduled_wake_runs r
            WHERE r.job_id = j.id
            ORDER BY r.started_at DESC, r.id DESC
            LIMIT 1
        ) AS recent_run_started_at
    FROM scheduled_wake_jobs j
    LEFT JOIN hosts h ON h.id = j.device_id
    LEFT JOIN users u ON u.id = j.created_by_user_id
"""


def create_scheduled_wake_job(
    *,
    device_id: str,
    created_by_user_id: int,
    label: str,
    enabled: bool,
    timezone: str,
    days_of_week: list[str],
    local_time: str,
    next_run_at: str | None,
) -> sqlite3.Row:
    job_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO scheduled_wake_jobs(
                id,
                device_id,
                created_by_user_id,
                label,
                enabled,
                timezone,
                days_of_week_json,
                local_time,
                next_run_at,
                last_run_at,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
            """,
            (
                job_id,
                device_id,
                created_by_user_id,
                label,
                int(enabled),
                timezone,
                json.dumps(days_of_week, separators=(",", ":")),
                local_time,
                next_run_at,
                now,
                now,
            ),
        )
        row = conn.execute(f"{_SCHEDULED_WAKE_JOB_SELECT} WHERE j.id = ?", (job_id,)).fetchone()
        if row is None:
            raise RuntimeError("scheduled wake job insert failed")
        return row


def get_scheduled_wake_job(job_id: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute(f"{_SCHEDULED_WAKE_JOB_SELECT} WHERE j.id = ?", (job_id,)).fetchone()


def list_scheduled_wake_jobs(
    limit: int = 200,
    *,
    device_id: str | None = None,
    enabled: bool | None = None,
) -> list[sqlite3.Row]:
    safe_limit = max(1, min(limit, 500))
    where_clauses: list[str] = []
    params: list[object] = []
    if device_id:
        where_clauses.append("j.device_id = ?")
        params.append(device_id)
    if enabled is not None:
        where_clauses.append("j.enabled = ?")
        params.append(int(enabled))
    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    with get_conn() as conn:
        rows = conn.execute(
            f"""
            {_SCHEDULED_WAKE_JOB_SELECT}
            {where_sql}
            ORDER BY
                j.enabled DESC,
                CASE WHEN j.next_run_at IS NULL OR j.next_run_at = '' THEN 1 ELSE 0 END ASC,
                j.next_run_at ASC,
                j.label COLLATE NOCASE ASC,
                j.id ASC
            LIMIT ?
            """,
            (*params, safe_limit),
        ).fetchall()
        return list(rows)


def update_scheduled_wake_job(job_id: str, updates: dict[str, object | None]) -> sqlite3.Row | None:
    if not updates:
        return get_scheduled_wake_job(job_id)

    normalized_updates = dict(updates)
    if "days_of_week" in normalized_updates:
        normalized_updates["days_of_week_json"] = json.dumps(
            normalized_updates.pop("days_of_week"),
            separators=(",", ":"),
        )
    normalized_updates["updated_at"] = datetime.now(UTC).isoformat()
    columns = ", ".join(f"{key} = ?" for key in normalized_updates.keys())
    values = list(normalized_updates.values())
    values.append(job_id)
    with get_conn() as conn:
        cur = conn.execute(f"UPDATE scheduled_wake_jobs SET {columns} WHERE id = ?", tuple(values))
        if cur.rowcount == 0:
            return None
    return get_scheduled_wake_job(job_id)


def delete_scheduled_wake_job(job_id: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM scheduled_wake_jobs WHERE id = ?", (job_id,))
        return cur.rowcount > 0


def list_due_scheduled_wake_jobs(now_utc: str, limit: int = 25) -> list[sqlite3.Row]:
    safe_limit = max(1, min(limit, 500))
    with get_conn() as conn:
        rows = conn.execute(
            f"""
            {_SCHEDULED_WAKE_JOB_SELECT}
            WHERE j.enabled = 1
              AND j.next_run_at IS NOT NULL
              AND j.next_run_at <= ?
            ORDER BY j.next_run_at ASC, j.id ASC
            LIMIT ?
            """,
            (now_utc, safe_limit),
        ).fetchall()
        return list(rows)


def claim_scheduled_wake_job(
    *,
    job_id: str,
    expected_next_run_at: str,
    claimed_next_run_at: str | None,
    claimed_at: str,
) -> sqlite3.Row | None:
    with get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE scheduled_wake_jobs
            SET next_run_at = ?, updated_at = ?
            WHERE id = ?
              AND enabled = 1
              AND next_run_at = ?
            """,
            (claimed_next_run_at, claimed_at, job_id, expected_next_run_at),
        )
        if cur.rowcount == 0:
            return None
        return conn.execute(f"{_SCHEDULED_WAKE_JOB_SELECT} WHERE j.id = ?", (job_id,)).fetchone()


def mark_scheduled_wake_job_executed(
    *,
    job_id: str,
    last_run_at: str,
    next_run_at: str | None,
) -> sqlite3.Row | None:
    with get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE scheduled_wake_jobs
            SET last_run_at = ?, next_run_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (last_run_at, next_run_at, last_run_at, job_id),
        )
        if cur.rowcount == 0:
            return None
        return conn.execute(f"{_SCHEDULED_WAKE_JOB_SELECT} WHERE j.id = ?", (job_id,)).fetchone()


def record_scheduled_wake_run(
    *,
    job_id: str,
    device_id: str,
    started_at: str,
    finished_at: str | None,
    result: str,
    detail: str | None = None,
    wake_log_id: int | None = None,
) -> sqlite3.Row:
    run_id = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO scheduled_wake_runs(
                id,
                job_id,
                device_id,
                started_at,
                finished_at,
                result,
                detail,
                wake_log_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                job_id,
                device_id,
                started_at,
                finished_at,
                result,
                detail,
                wake_log_id,
            ),
        )
        row = conn.execute("SELECT * FROM scheduled_wake_runs WHERE id = ?", (run_id,)).fetchone()
        if row is None:
            raise RuntimeError("scheduled wake run insert failed")
        return row


def list_scheduled_wake_runs(
    *,
    limit: int = 50,
    job_id: str | None = None,
    device_id: str | None = None,
) -> list[sqlite3.Row]:
    safe_limit = max(1, min(limit, 500))
    params: list[object] = []
    where_clauses: list[str] = []
    if job_id:
        where_clauses.append("r.job_id = ?")
        params.append(job_id)
    if device_id:
        where_clauses.append("r.device_id = ?")
        params.append(device_id)

    query = """
        SELECT
            r.*,
            h.name AS device_name,
            h.display_name AS device_display_name,
            j.label AS job_label
        FROM scheduled_wake_runs r
        LEFT JOIN hosts h ON h.id = r.device_id
        LEFT JOIN scheduled_wake_jobs j ON j.id = r.job_id
    """
    if where_clauses:
        query += " WHERE " + " AND ".join(where_clauses)
    query += " ORDER BY r.started_at DESC, r.id DESC LIMIT ?"
    params.append(safe_limit)

    with get_conn() as conn:
        rows = conn.execute(query, tuple(params)).fetchall()
        return list(rows)


def update_host(host_id: str, updates: dict[str, object | None]) -> bool:
    if not updates:
        return False

    normalized_updates = dict(updates)
    normalized_updates["updated_at"] = datetime.now(UTC).isoformat()
    columns = ", ".join([f"{key} = ?" for key in normalized_updates.keys()])
    values = list(normalized_updates.values())
    values.append(host_id)

    with get_conn() as conn:
        cur = conn.execute(f"UPDATE hosts SET {columns} WHERE id = ?", tuple(values))
        return cur.rowcount > 0


def delete_host(host_id: str) -> bool:
    with get_conn() as conn:
        conn.execute("DELETE FROM device_memberships WHERE device_id = ?", (host_id,))
        conn.execute("DELETE FROM wake_logs WHERE host_id = ?", (host_id,))
        conn.execute("DELETE FROM power_check_logs WHERE device_id = ?", (host_id,))
        cur = conn.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
        return cur.rowcount > 0


def update_host_power_state(host_id: str, state: str, checked_at: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE hosts SET last_power_state = ?, last_power_checked_at = ?, updated_at = ? WHERE id = ?",
            (state, checked_at, checked_at, host_id),
        )


def log_power_check(
    device_id: str,
    method: str,
    result: str,
    detail: str,
    latency_ms: int | None,
) -> None:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO power_check_logs(device_id, method, result, detail, latency_ms, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (device_id, method, result, detail, latency_ms, now),
        )


def list_power_check_logs(limit: int = 100) -> list[sqlite3.Row]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, device_id, method, result, detail, latency_ms, created_at
            FROM power_check_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return list(rows)


def create_invite_token(
    invite_id: str,
    token_hash: str,
    username: str,
    backend_url_hint: str | None,
    expires_at: str,
    created_by: str,
) -> None:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO invite_tokens(
                id,
                token_hash,
                username,
                backend_url_hint,
                expires_at,
                claimed_at,
                created_by,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, NULL, ?, ?)
            """,
            (invite_id, token_hash, username, backend_url_hint, expires_at, created_by, now),
        )


def list_invite_tokens(limit: int = 200) -> list[sqlite3.Row]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, username, backend_url_hint, expires_at, claimed_at, created_by, created_at
            FROM invite_tokens
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return list(rows)


def get_invite_by_hash(token_hash: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT *
            FROM invite_tokens
            WHERE token_hash = ?
            """,
            (token_hash,),
        ).fetchone()


def claim_invite(invite_id: str, claimed_at: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE invite_tokens
            SET claimed_at = ?
            WHERE id = ? AND claimed_at IS NULL
            """,
            (claimed_at, invite_id),
        )
        return cur.rowcount > 0


def revoke_invite(invite_id: str) -> bool:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE invite_tokens
            SET expires_at = ?
            WHERE id = ? AND claimed_at IS NULL
            """,
            (now, invite_id),
        )
        return cur.rowcount > 0


def log_wake(
    host_id: str,
    actor_username: str,
    sent_to: str,
    result: str = "sent",
    error_detail: str | None = None,
    precheck_state: str = "unknown",
) -> int:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO wake_logs(
                host_id,
                actor_username,
                sent_to,
                created_at,
                result,
                error_detail,
                precheck_state
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (host_id, actor_username, sent_to, now, result, error_detail, precheck_state),
        )
        return int(cur.lastrowid)


def list_wake_logs(limit: int = 100) -> list[sqlite3.Row]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, host_id, actor_username, sent_to, result, error_detail, precheck_state, created_at
            FROM wake_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return list(rows)


def list_claimed_invites(limit: int = 1000) -> list[sqlite3.Row]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, username, claimed_at, expires_at, created_at
            FROM invite_tokens
            WHERE claimed_at IS NOT NULL
            ORDER BY claimed_at ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return list(rows)


def list_successful_wakes(limit: int = 5000) -> list[sqlite3.Row]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, actor_username, host_id, result, created_at
            FROM wake_logs
            WHERE result IN ('sent', 'already_on')
            ORDER BY created_at ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return list(rows)


def log_admin_action(
    actor_username: str,
    action: str,
    target_type: str,
    target_id: str,
    detail: str | None = None,
) -> None:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO admin_audit_logs(actor_username, action, target_type, target_id, detail, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (actor_username, action, target_type, target_id, detail, now),
        )


def list_admin_audit_logs(limit: int = 200) -> list[sqlite3.Row]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, actor_username, action, target_type, target_id, detail, created_at
            FROM admin_audit_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return list(rows)


def create_activity_event(
    event_type: str,
    target_type: str,
    summary: str,
    actor_user_id: int | None = None,
    actor_username: str | None = None,
    target_id: str | None = None,
    server_id: str | None = None,
    metadata_json: str | None = None,
) -> int:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO activity_events(
                event_type,
                actor_user_id,
                actor_username,
                target_type,
                target_id,
                server_id,
                summary,
                metadata_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_type,
                actor_user_id,
                actor_username,
                target_type,
                target_id,
                server_id,
                summary,
                metadata_json,
                now,
            ),
        )
        return int(cur.lastrowid)


def list_activity_events(
    limit: int = 50,
    cursor_id: int | None = None,
    event_types: list[str] | None = None,
) -> list[sqlite3.Row]:
    safe_limit = max(1, min(limit, 200))
    params: list[object] = []
    where_clauses: list[str] = []
    if cursor_id is not None:
        where_clauses.append("id < ?")
        params.append(cursor_id)
    if event_types:
        placeholders = ",".join("?" for _ in event_types)
        where_clauses.append(f"event_type IN ({placeholders})")
        params.extend(event_types)

    query = """
        SELECT id, event_type, actor_user_id, actor_username, target_type, target_id, server_id, summary, metadata_json, created_at
        FROM activity_events
    """
    if where_clauses:
        query += " WHERE " + " AND ".join(where_clauses)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(safe_limit)

    with get_conn() as conn:
        rows = conn.execute(query, tuple(params)).fetchall()
        return list(rows)


def create_shutdown_poke_request(
    *,
    server_id: str,
    requester_user_id: int,
    requester_username: str,
    message: str | None = None,
) -> sqlite3.Row:
    now = datetime.now(UTC).isoformat()
    poke_id = str(uuid.uuid4())
    normalized_message = (message or "").strip() or None
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO shutdown_poke_requests(
                id,
                server_id,
                requester_user_id,
                requester_username,
                message,
                status,
                created_at,
                seen_at,
                resolved_at,
                resolved_by_user_id
            )
            VALUES (?, ?, ?, ?, ?, 'open', ?, NULL, NULL, NULL)
            """,
            (poke_id, server_id, requester_user_id, requester_username, normalized_message, now),
        )
        row = conn.execute(
            """
            SELECT r.*, h.name AS device_name, h.display_name AS device_display_name, u.username AS resolved_by_username
            FROM shutdown_poke_requests r
            LEFT JOIN hosts h ON h.id = r.server_id
            LEFT JOIN users u ON u.id = r.resolved_by_user_id
            WHERE r.id = ?
            """,
            (poke_id,),
        ).fetchone()
        if row is None:
            raise RuntimeError("shutdown poke request insert failed")
        return row


def get_shutdown_poke_request(poke_id: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT r.*, h.name AS device_name, h.display_name AS device_display_name, u.username AS resolved_by_username
            FROM shutdown_poke_requests r
            LEFT JOIN hosts h ON h.id = r.server_id
            LEFT JOIN users u ON u.id = r.resolved_by_user_id
            WHERE r.id = ?
            """,
            (poke_id,),
        ).fetchone()


def list_shutdown_poke_requests(
    *,
    status_filter: Literal["open", "seen", "resolved"] | None = None,
    limit: int = 50,
) -> list[sqlite3.Row]:
    safe_limit = max(1, min(limit, 200))
    with get_conn() as conn:
        if status_filter:
            rows = conn.execute(
                """
                SELECT r.*, h.name AS device_name, h.display_name AS device_display_name, u.username AS resolved_by_username
                FROM shutdown_poke_requests r
                LEFT JOIN hosts h ON h.id = r.server_id
                LEFT JOIN users u ON u.id = r.resolved_by_user_id
                WHERE r.status = ?
                ORDER BY r.created_at DESC
                LIMIT ?
                """,
                (status_filter, safe_limit),
            ).fetchall()
            return list(rows)
        rows = conn.execute(
            """
            SELECT r.*, h.name AS device_name, h.display_name AS device_display_name, u.username AS resolved_by_username
            FROM shutdown_poke_requests r
            LEFT JOIN hosts h ON h.id = r.server_id
            LEFT JOIN users u ON u.id = r.resolved_by_user_id
            ORDER BY r.created_at DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()
        return list(rows)


def mark_shutdown_poke_seen(
    *,
    poke_id: str,
) -> sqlite3.Row | None:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE shutdown_poke_requests
            SET status = 'seen',
                seen_at = COALESCE(seen_at, ?)
            WHERE id = ? AND status = 'open'
            """,
            (now, poke_id),
        )
        return conn.execute(
            """
            SELECT r.*, h.name AS device_name, h.display_name AS device_display_name, u.username AS resolved_by_username
            FROM shutdown_poke_requests r
            LEFT JOIN hosts h ON h.id = r.server_id
            LEFT JOIN users u ON u.id = r.resolved_by_user_id
            WHERE r.id = ?
            """,
            (poke_id,),
        ).fetchone()


def mark_shutdown_poke_resolved(
    *,
    poke_id: str,
    actor_user_id: int,
) -> sqlite3.Row | None:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE shutdown_poke_requests
            SET status = 'resolved',
                seen_at = COALESCE(seen_at, ?),
                resolved_at = COALESCE(resolved_at, ?),
                resolved_by_user_id = COALESCE(resolved_by_user_id, ?)
            WHERE id = ? AND status IN ('open', 'seen')
            """,
            (now, now, actor_user_id, poke_id),
        )
        return conn.execute(
            """
            SELECT r.*, h.name AS device_name, h.display_name AS device_display_name, u.username AS resolved_by_username
            FROM shutdown_poke_requests r
            LEFT JOIN hosts h ON h.id = r.server_id
            LEFT JOIN users u ON u.id = r.resolved_by_user_id
            WHERE r.id = ?
            """,
            (poke_id,),
        ).fetchone()


def upsert_notification_device(
    *,
    user_id: int,
    installation_id: str,
    platform: Literal["ios"],
    provider: Literal["apns"],
    token: str,
    app_bundle_id: str,
    environment: Literal["development", "production"],
) -> sqlite3.Row:
    now = datetime.now(UTC).isoformat()
    normalized_installation_id = installation_id.strip()
    normalized_token = token.strip()
    normalized_bundle_id = app_bundle_id.strip()
    with get_conn() as conn:
        existing = conn.execute(
            """
            SELECT *
            FROM notification_devices
            WHERE installation_id = ? AND provider = ?
            """,
            (normalized_installation_id, provider),
        ).fetchone()
        if existing:
            reset_alert_state = (
                int(existing["user_id"]) != user_id
                or str(existing["token"]) != normalized_token
                or str(existing["environment"]) != environment
            )
            last_alert_sent_at = None if reset_alert_state else existing["last_alert_sent_at"]
            suppressed_shutdown_count = 0 if reset_alert_state else int(existing["suppressed_shutdown_count"] or 0)
            conn.execute(
                """
                UPDATE notification_devices
                SET user_id = ?,
                    platform = ?,
                    token = ?,
                    app_bundle_id = ?,
                    environment = ?,
                    is_active = 1,
                    last_registered_at = ?,
                    last_seen_at = ?,
                    last_alert_sent_at = ?,
                    suppressed_shutdown_count = ?,
                    invalidated_at = NULL,
                    invalidation_reason = NULL,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    user_id,
                    platform,
                    normalized_token,
                    normalized_bundle_id,
                    environment,
                    now,
                    now,
                    last_alert_sent_at,
                    suppressed_shutdown_count,
                    now,
                    existing["id"],
                ),
            )
            device_id = str(existing["id"])
        else:
            device_id = str(uuid.uuid4())
            conn.execute(
                """
                INSERT INTO notification_devices(
                    id,
                    user_id,
                    installation_id,
                    platform,
                    provider,
                    token,
                    app_bundle_id,
                    environment,
                    is_active,
                    last_registered_at,
                    last_seen_at,
                    last_alert_sent_at,
                    suppressed_shutdown_count,
                    invalidated_at,
                    invalidation_reason,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, NULL, 0, NULL, NULL, ?, ?)
                """,
                (
                    device_id,
                    user_id,
                    normalized_installation_id,
                    platform,
                    provider,
                    normalized_token,
                    normalized_bundle_id,
                    environment,
                    now,
                    now,
                    now,
                    now,
                ),
            )
        row = conn.execute(
            """
            SELECT *
            FROM notification_devices
            WHERE id = ?
            """,
            (device_id,),
        ).fetchone()
        if row is None:
            raise RuntimeError("notification device upsert failed")
        return row


def deactivate_notification_device(
    *,
    user_id: int,
    installation_id: str,
    provider: Literal["apns"],
) -> bool:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE notification_devices
            SET is_active = 0,
                suppressed_shutdown_count = 0,
                updated_at = ?
            WHERE user_id = ? AND installation_id = ? AND provider = ? AND is_active = 1
            """,
            (now, user_id, installation_id.strip(), provider),
        )
        return cur.rowcount > 0


def list_notification_devices(*, user_id: int | None = None) -> list[sqlite3.Row]:
    params: list[object] = []
    query = "SELECT * FROM notification_devices"
    if user_id is not None:
        query += " WHERE user_id = ?"
        params.append(user_id)
    query += " ORDER BY updated_at DESC"
    with get_conn() as conn:
        return list(conn.execute(query, tuple(params)).fetchall())


def list_active_admin_notification_devices(
    *,
    provider: Literal["apns"],
    platform: Literal["ios"],
    environment: Literal["development", "production"],
) -> list[sqlite3.Row]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT d.*, u.username
            FROM notification_devices d
            INNER JOIN users u ON u.id = d.user_id
            WHERE d.provider = ?
              AND d.platform = ?
              AND d.environment = ?
              AND d.is_active = 1
              AND u.role = 'admin'
            ORDER BY d.updated_at DESC
            """,
            (provider, platform, environment),
        ).fetchall()
        return list(rows)


def record_notification_device_alert_sent(device_id: str, sent_at: str | None = None) -> None:
    timestamp = sent_at or datetime.now(UTC).isoformat()
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE notification_devices
            SET last_alert_sent_at = ?,
                suppressed_shutdown_count = 0,
                updated_at = ?
            WHERE id = ?
            """,
            (timestamp, timestamp, device_id),
        )


def reserve_notification_device_visible_alert(
    device_id: str,
    *,
    min_interval_seconds: int,
    reserved_at: str | None = None,
) -> bool:
    timestamp = reserved_at or datetime.now(UTC).isoformat()
    threshold = None
    if min_interval_seconds > 0:
        threshold = (datetime.fromisoformat(timestamp) - timedelta(seconds=min_interval_seconds)).isoformat()

    with get_conn() as conn:
        if threshold is None:
            result = conn.execute(
                """
                UPDATE notification_devices
                SET last_alert_sent_at = ?,
                    updated_at = ?
                WHERE id = ?
                  AND is_active = 1
                """,
                (timestamp, timestamp, device_id),
            )
        else:
            result = conn.execute(
                """
                UPDATE notification_devices
                SET last_alert_sent_at = ?,
                    updated_at = ?
                WHERE id = ?
                  AND is_active = 1
                  AND (
                    last_alert_sent_at IS NULL
                    OR last_alert_sent_at = ''
                    OR last_alert_sent_at <= ?
                  )
                """,
                (timestamp, timestamp, device_id, threshold),
            )
        return result.rowcount > 0


def release_notification_device_visible_alert_reservation(
    device_id: str,
    *,
    reserved_at: str,
    previous_last_alert_sent_at: str | None,
) -> None:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE notification_devices
            SET last_alert_sent_at = ?,
                updated_at = ?
            WHERE id = ?
              AND last_alert_sent_at = ?
            """,
            (previous_last_alert_sent_at, now, device_id, reserved_at),
        )


def increment_notification_device_suppressed_shutdown_count(device_id: str) -> None:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE notification_devices
            SET suppressed_shutdown_count = COALESCE(suppressed_shutdown_count, 0) + 1,
                updated_at = ?
            WHERE id = ?
            """,
            (now, device_id),
        )


def invalidate_notification_device(device_id: str, reason: str | None = None) -> None:
    now = datetime.now(UTC).isoformat()
    normalized_reason = (reason or "").strip() or None
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE notification_devices
            SET is_active = 0,
                invalidated_at = ?,
                invalidation_reason = ?,
                suppressed_shutdown_count = 0,
                updated_at = ?
            WHERE id = ?
            """,
            (now, normalized_reason, now, device_id),
        )


def set_notification_device_last_alert_sent_at(device_id: str, timestamp: str | None) -> None:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE notification_devices
            SET last_alert_sent_at = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (timestamp, now, device_id),
        )


def create_discovery_run(requested_by: str, options_json: str) -> str:
    now = datetime.now(UTC).isoformat()
    run_id = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO discovery_runs(id, requested_by, status, options_json, summary_json, started_at, finished_at, created_at)
            VALUES (?, ?, 'queued', ?, NULL, NULL, NULL, ?)
            """,
            (run_id, requested_by, options_json, now),
        )
    return run_id


def mark_discovery_run_running(run_id: str) -> bool:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE discovery_runs
            SET status = 'running', started_at = COALESCE(started_at, ?)
            WHERE id = ? AND status IN ('queued', 'running')
            """,
            (now, run_id),
        )
        return cur.rowcount > 0


def complete_discovery_run(run_id: str, summary_json: str) -> bool:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE discovery_runs
            SET status = 'completed', summary_json = ?, finished_at = ?
            WHERE id = ?
            """,
            (summary_json, now, run_id),
        )
        return cur.rowcount > 0


def fail_discovery_run(run_id: str, summary_json: str) -> bool:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE discovery_runs
            SET status = 'failed', summary_json = ?, finished_at = ?
            WHERE id = ?
            """,
            (summary_json, now, run_id),
        )
        return cur.rowcount > 0


def get_discovery_run(run_id: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM discovery_runs WHERE id = ?", (run_id,)).fetchone()


def list_discovery_runs(limit: int = 20) -> list[sqlite3.Row]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM discovery_runs
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return list(rows)


def create_discovery_candidate(
    run_id: str,
    hostname: str | None,
    mac: str | None,
    ip: str | None,
    source_interface: str | None,
    source_ip: str | None,
    source_network_cidr: str | None,
    broadcast_ip: str | None,
    wol_confidence: str,
    power_check_method: str | None,
    power_check_target: str | None,
    power_check_port: int | None,
    power_data_source: str,
    notes_json: str | None,
) -> str:
    candidate_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO discovery_candidates(
                id,
                run_id,
                hostname,
                mac,
                ip,
                source_interface,
                source_ip,
                source_network_cidr,
                broadcast_ip,
                wol_confidence,
                power_check_method,
                power_check_target,
                power_check_port,
                power_data_source,
                imported_host_id,
                notes_json,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
            """,
            (
                candidate_id,
                run_id,
                hostname,
                mac,
                ip,
                source_interface,
                source_ip,
                source_network_cidr,
                broadcast_ip,
                wol_confidence,
                power_check_method,
                power_check_target,
                power_check_port,
                power_data_source,
                notes_json,
                now,
                now,
            ),
        )
    return candidate_id


def list_discovery_candidates(
    run_id: str,
    only_unimported: bool = False,
    wol_confidence: str | None = None,
    source_network_cidr: str | None = None,
) -> list[sqlite3.Row]:
    query = "SELECT * FROM discovery_candidates WHERE run_id = ?"
    params: list[object] = [run_id]
    if only_unimported:
        query += " AND imported_host_id IS NULL"
    if wol_confidence:
        query += " AND wol_confidence = ?"
        params.append(wol_confidence)
    if source_network_cidr:
        query += " AND source_network_cidr = ?"
        params.append(source_network_cidr)
    query += " ORDER BY created_at ASC"
    with get_conn() as conn:
        rows = conn.execute(query, tuple(params)).fetchall()
        return list(rows)


def get_discovery_candidate(candidate_id: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM discovery_candidates WHERE id = ?", (candidate_id,)).fetchone()


def mark_discovery_candidate_imported(candidate_id: str, imported_host_id: str) -> bool:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE discovery_candidates
            SET imported_host_id = ?, updated_at = ?
            WHERE id = ?
            """,
            (imported_host_id, now, candidate_id),
        )
        return cur.rowcount > 0


def log_discovery_event(run_id: str, event_type: str, detail: str, candidate_id: str | None = None) -> None:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO discovery_events(run_id, candidate_id, event_type, detail, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (run_id, candidate_id, event_type, detail, now),
        )


def list_discovery_events(run_id: str, limit: int = 200) -> list[sqlite3.Row]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, run_id, candidate_id, event_type, detail, created_at
            FROM discovery_events
            WHERE run_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (run_id, limit),
        ).fetchall()
        return list(rows)
