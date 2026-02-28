#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
import sys


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Create a consistent SQLite backup of WakeFromFar DB.")
    parser.add_argument(
        "--source",
        type=Path,
        default=repo_root / "data" / "wol.db",
        help="Path to source SQLite DB (default: ./data/wol.db).",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=repo_root / "backups",
        help="Directory for backup files (default: ./backups).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source = args.source.resolve()
    out_dir = args.out_dir.resolve()

    if not source.exists():
        print(f"Source DB does not exist: {source}", file=sys.stderr)
        return 1

    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    destination = out_dir / f"wol-{ts}.db"

    src_conn = sqlite3.connect(source)
    dst_conn = sqlite3.connect(destination)
    try:
        with dst_conn:
            src_conn.backup(dst_conn)
    finally:
        src_conn.close()
        dst_conn.close()

    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
