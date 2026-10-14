"""CHECKPOINT + gzip snapshot backup: python -m app.backup [backup_dir].

Keeps the last 14 archives matching observatory-YYYYmmdd-HHMMSS.duckdb.gz.
"""

from __future__ import annotations

import argparse
import gzip
import logging
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import duckdb

logger = logging.getLogger(__name__)

KEEP_BACKUPS = 14
DEFAULT_BACKUP_DIR = "/backups"
DEFAULT_DB_PATH = "/data/observatory.duckdb"
COPY_CHUNK_BYTES = 1 << 20
ARCHIVE_PATTERN = "observatory-*.duckdb.gz"


def backup_database(db_path: str, backup_dir: str, keep: int = KEEP_BACKUPS) -> str:
    """Gzip-copy an (already checkpointed) DuckDB file; returns the archive path."""
    source = Path(db_path)
    if not source.is_file():
        raise FileNotFoundError(f"database not found: {db_path}")
    out_dir = Path(backup_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    target = out_dir / f"observatory-{stamp}.duckdb.gz"
    with source.open("rb") as src, gzip.open(target, "wb", compresslevel=6) as dst:
        shutil.copyfileobj(src, dst, COPY_CHUNK_BYTES)
    prune_backups(out_dir, keep)
    return str(target)


def prune_backups(backup_dir: Path, keep: int = KEEP_BACKUPS) -> list[Path]:
    """Delete the oldest archives beyond the retention count."""
    archives = sorted(backup_dir.glob(ARCHIVE_PATTERN))
    remove = archives[:-keep] if keep < len(archives) else []
    for path in remove:
        path.unlink(missing_ok=True)
        logger.info("pruned old backup: %s", path)
    return remove


def checkpoint_database(db_path: str, memory_limit: str = "128MB") -> None:
    """Checkpoint the database standalone (CLI path; the app checkpoints via its writer)."""
    conn = duckdb.connect(db_path)
    try:
        conn.execute(f"PRAGMA memory_limit='{memory_limit}'")
        conn.execute("PRAGMA threads=1")
        conn.execute("CHECKPOINT")
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create a gzipped Attack Observatory backup")
    parser.add_argument("backup_dir", nargs="?", default=DEFAULT_BACKUP_DIR)
    parser.add_argument("--db-path", default=os.environ.get("OBS_DB_PATH", DEFAULT_DB_PATH))
    parser.add_argument("--memory-limit", default=os.environ.get("OBS_DB_MEMORY_LIMIT", "128MB"))
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    checkpoint_database(args.db_path, args.memory_limit)
    target = backup_database(args.db_path, args.backup_dir)
    logger.info("backup written: %s", target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
