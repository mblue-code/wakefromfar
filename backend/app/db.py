from __future__ import annotations

import sqlite3
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
import ipaddress
from typing import Generator

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


def _add_column_if_missing(
    conn: sqlite3.Connection,
    table_name: str,
    column_name: str,
    column_def: str,
) -> None:
    if _table_has_column(conn, table_name, column_name):
        return
    conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_def}")


def _migration_001_base_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS hosts (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            mac TEXT NOT NULL,
            group_name TEXT,
            broadcast TEXT,
            subnet_cidr TEXT,
            udp_port INTEGER NOT NULL DEFAULT 9,
            interface TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS wake_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id TEXT NOT NULL,
            actor_username TEXT NOT NULL,
            sent_to TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(host_id) REFERENCES hosts(id)
        )
        """
    )


def _migration_002_sprint1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS user_device_access (
            user_id INTEGER NOT NULL,
            device_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (user_id, device_id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(device_id) REFERENCES hosts(id)
        )
        """
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

    _add_column_if_missing(conn, "hosts", "display_name", "TEXT")
    _add_column_if_missing(conn, "hosts", "check_method", "TEXT NOT NULL DEFAULT 'tcp'")
    _add_column_if_missing(conn, "hosts", "check_target", "TEXT")
    _add_column_if_missing(conn, "hosts", "check_port", "INTEGER")
    _add_column_if_missing(conn, "hosts", "last_power_state", "TEXT NOT NULL DEFAULT 'unknown'")
    _add_column_if_missing(conn, "hosts", "last_power_checked_at", "TEXT")

    _add_column_if_missing(conn, "wake_logs", "result", "TEXT NOT NULL DEFAULT 'sent'")
    _add_column_if_missing(conn, "wake_logs", "error_detail", "TEXT")
    _add_column_if_missing(conn, "wake_logs", "precheck_state", "TEXT NOT NULL DEFAULT 'unknown'")


def _migration_003_admin_audit(conn: sqlite3.Connection) -> None:
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


def _migration_004_source_ip(conn: sqlite3.Connection) -> None:
    _add_column_if_missing(conn, "hosts", "source_ip", "TEXT")


def _migration_005_discovery_schema(conn: sqlite3.Connection) -> None:
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

    _add_column_if_missing(conn, "hosts", "source_network_cidr", "TEXT")
    _add_column_if_missing(conn, "hosts", "provisioning_source", "TEXT NOT NULL DEFAULT 'manual'")
    _add_column_if_missing(conn, "hosts", "discovery_confidence", "TEXT")
    _add_column_if_missing(conn, "hosts", "last_discovered_at", "TEXT")

    conn.execute("UPDATE hosts SET provisioning_source = 'manual' WHERE provisioning_source IS NULL OR provisioning_source = ''")

    rows = conn.execute("SELECT id, source_ip, subnet_cidr, source_network_cidr FROM hosts").fetchall()
    for row in rows:
        if row["source_network_cidr"]:
            continue
        source_ip = str(row["source_ip"] or "").strip()
        subnet_cidr = str(row["subnet_cidr"] or "").strip()
        if not source_ip or not subnet_cidr:
            continue
        try:
            ip_obj = ipaddress.ip_address(source_ip)
            net_obj = ipaddress.ip_network(subnet_cidr, strict=False)
        except ValueError:
            continue
        if ip_obj in net_obj:
            conn.execute(
                "UPDATE hosts SET source_network_cidr = ? WHERE id = ?",
                (str(net_obj), row["id"]),
            )


def init_db() -> None:
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
            """
        )
        applied = {
            row["version"]
            for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version ASC").fetchall()
        }
        migrations = {
            1: _migration_001_base_schema,
            2: _migration_002_sprint1,
            3: _migration_003_admin_audit,
            4: _migration_004_source_ip,
            5: _migration_005_discovery_schema,
        }
        for version in sorted(migrations.keys()):
            if version in applied:
                continue
            migrations[version](conn)
            conn.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (version, datetime.now(UTC).isoformat()),
            )


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
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (password_hash, username),
        )
        return cur.rowcount > 0


def update_user_password_by_id(user_id: int, password_hash: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
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
        conn.execute("DELETE FROM user_device_access WHERE user_id = ?", (user_id,))
        cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        return cur.rowcount > 0


def get_user_by_username(username: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def create_user(username: str, password_hash: str, role: str) -> int:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO users(username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, password_hash, role, now),
        )
        return int(cur.lastrowid)


def upsert_admin(username: str, password_hash: str) -> None:
    existing = get_user_by_username(username)
    if existing:
        return
    create_user(username=username, password_hash=password_hash, role="admin")


def list_hosts() -> list[sqlite3.Row]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT
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
                display_name,
                check_method,
                check_target,
                check_port,
                last_power_state,
                last_power_checked_at,
                provisioning_source,
                discovery_confidence,
                last_discovered_at
            FROM hosts
            ORDER BY name COLLATE NOCASE ASC
            """
        ).fetchall()
        return list(rows)


def list_assigned_hosts(user_id: int) -> list[sqlite3.Row]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT
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
                h.display_name,
                h.check_method,
                h.check_target,
                h.check_port,
                h.last_power_state,
                h.last_power_checked_at,
                h.provisioning_source,
                h.discovery_confidence,
                h.last_discovered_at
            FROM hosts h
            INNER JOIN user_device_access uda ON uda.device_id = h.id
            WHERE uda.user_id = ?
            ORDER BY h.name COLLATE NOCASE ASC
            """,
            (user_id,),
        ).fetchall()
        return list(rows)


def get_host_by_id(host_id: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()


def get_host_by_mac(mac: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM hosts WHERE mac = ? ORDER BY created_at ASC LIMIT 1",
            (mac,),
        ).fetchone()


def get_assigned_host_by_id(user_id: int, host_id: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT h.*
            FROM hosts h
            INNER JOIN user_device_access uda ON uda.device_id = h.id
            WHERE uda.user_id = ? AND h.id = ?
            """,
            (user_id, host_id),
        ).fetchone()


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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unknown', NULL, ?, ?, ?)
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


def update_host(host_id: str, updates: dict[str, object | None]) -> bool:
    if not updates:
        return False

    columns = ", ".join([f"{key} = ?" for key in updates.keys()])
    values = list(updates.values())
    values.append(host_id)

    with get_conn() as conn:
        cur = conn.execute(f"UPDATE hosts SET {columns} WHERE id = ?", tuple(values))
        return cur.rowcount > 0


def delete_host(host_id: str) -> bool:
    with get_conn() as conn:
        conn.execute("DELETE FROM user_device_access WHERE device_id = ?", (host_id,))
        conn.execute("DELETE FROM wake_logs WHERE host_id = ?", (host_id,))
        conn.execute("DELETE FROM power_check_logs WHERE device_id = ?", (host_id,))
        cur = conn.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
        return cur.rowcount > 0


def update_host_power_state(host_id: str, state: str, checked_at: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE hosts SET last_power_state = ?, last_power_checked_at = ? WHERE id = ?",
            (state, checked_at, host_id),
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


def assign_device_to_user(user_id: int, device_id: str) -> None:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO user_device_access(user_id, device_id, created_at)
            VALUES (?, ?, ?)
            """,
            (user_id, device_id, now),
        )


def remove_assignment(user_id: int, device_id: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "DELETE FROM user_device_access WHERE user_id = ? AND device_id = ?",
            (user_id, device_id),
        )
        return cur.rowcount > 0


def is_device_assigned_to_user(user_id: int, device_id: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT 1
            FROM user_device_access
            WHERE user_id = ? AND device_id = ?
            LIMIT 1
            """,
            (user_id, device_id),
        ).fetchone()
        return row is not None


def list_assignments() -> list[sqlite3.Row]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT
                uda.user_id,
                u.username,
                uda.device_id,
                h.name AS device_name,
                uda.created_at
            FROM user_device_access uda
            INNER JOIN users u ON u.id = uda.user_id
            INNER JOIN hosts h ON h.id = uda.device_id
            ORDER BY u.username COLLATE NOCASE ASC, h.name COLLATE NOCASE ASC
            """
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
) -> None:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        conn.execute(
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
