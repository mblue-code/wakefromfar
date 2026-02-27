from __future__ import annotations

import sqlite3
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
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


def init_db() -> None:
    with get_conn() as conn:
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


def get_user_by_username(username: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def create_user(username: str, password_hash: str, role: str) -> None:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO users(username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, password_hash, role, now),
        )


def upsert_admin(username: str, password_hash: str) -> None:
    existing = get_user_by_username(username)
    if existing:
        return
    create_user(username=username, password_hash=password_hash, role="admin")


def list_hosts() -> list[sqlite3.Row]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM hosts ORDER BY name COLLATE NOCASE ASC").fetchall()
        return list(rows)


def get_host_by_id(host_id: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()


def create_host(
    name: str,
    mac: str,
    group_name: str | None,
    broadcast: str | None,
    subnet_cidr: str | None,
    udp_port: int,
    interface: str | None,
    host_id: str | None = None,
) -> str:
    generated_id = host_id or str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO hosts(id, name, mac, group_name, broadcast, subnet_cidr, udp_port, interface, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (generated_id, name, mac, group_name, broadcast, subnet_cidr, udp_port, interface, now),
        )
    return generated_id


def log_wake(host_id: str, actor_username: str, sent_to: str) -> None:
    now = datetime.now(UTC).isoformat()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO wake_logs(host_id, actor_username, sent_to, created_at) VALUES (?, ?, ?, ?)",
            (host_id, actor_username, sent_to, now),
        )
