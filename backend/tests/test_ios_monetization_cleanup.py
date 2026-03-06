from __future__ import annotations

import sqlite3


def test_legacy_ios_entitlement_routes_are_removed(client):
    assert client.get("/me/entitlements").status_code == 404
    assert client.post("/me/entitlements/app-store/sync", json={"entitlements": []}).status_code == 404


def test_openapi_does_not_expose_legacy_ios_entitlement_paths():
    from app.main import app

    openapi = app.openapi()
    assert "/me/entitlements" not in openapi["paths"]
    assert "/me/entitlements/app-store/sync" not in openapi["paths"]


def test_runtime_does_not_create_ios_entitlements_table(client, tmp_path):
    with sqlite3.connect(tmp_path / "test.db") as conn:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'ios_entitlements'"
        ).fetchone()
    assert row is None


def test_migration_11_drops_legacy_ios_entitlements_table(tmp_path, monkeypatch):
    db_path = tmp_path / "legacy.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
            """
        )
        for version in range(1, 11):
            conn.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, '2026-03-05T00:00:00Z')",
                (version,),
            )
        conn.execute("CREATE TABLE ios_entitlements (id TEXT PRIMARY KEY)")
        conn.commit()

    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("DB_FILENAME", "legacy.db")

    from app.config import get_settings
    from app.db import init_db

    get_settings.cache_clear()
    init_db()

    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'ios_entitlements'"
        ).fetchone()
        migration = conn.execute(
            "SELECT version FROM schema_migrations WHERE version = 11"
        ).fetchone()

    get_settings.cache_clear()

    assert row is None
    assert migration == (11,)
