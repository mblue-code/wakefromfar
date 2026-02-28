#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import sys


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Restore WakeFromFar SQLite DB from a backup file.")
    parser.add_argument("backup_file", type=Path, help="Backup file created by backup_db.py.")
    parser.add_argument(
        "--target",
        type=Path,
        default=repo_root / "data" / "wol.db",
        help="Target SQLite DB path (default: ./data/wol.db).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite target DB without confirmation prompt.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source = args.backup_file.resolve()
    target = args.target.resolve()

    if not source.exists():
        print(f"Backup file does not exist: {source}", file=sys.stderr)
        return 1

    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and not args.force:
        print(f"Target already exists: {target}", file=sys.stderr)
        print("Use --force to overwrite.", file=sys.stderr)
        return 1

    shutil.copy2(source, target)
    print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
