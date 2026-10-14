"""APScheduler wiring: retention hourly, geoip weekly, backup daily 03:00 (contract section 8)."""

from __future__ import annotations

import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.backup import backup_database
from app.config import Settings
from app.db import DuckDBManager
from app.geoip import GeoEnricher

logger = logging.getLogger(__name__)

BACKUP_DIR = "/backups"


async def run_retention(db: DuckDBManager, retention_days: int) -> int:
    """Delete events older than the retention window, then checkpoint."""
    days = max(1, int(retention_days))
    async with db.write_lock:
        cursor = db.writer.execute(
            f"DELETE FROM events WHERE timestamp < now() - interval '{days} days'"
        )
        row = cursor.fetchone()
        deleted = int(row[0]) if row and row[0] is not None else 0
        db.writer.execute("CHECKPOINT")
    if deleted:
        logger.info("retention deleted %d events (older than %d days)", deleted, days)
    return deleted


async def run_geoip_refresh(db: DuckDBManager, geoip: GeoEnricher, force: bool = False) -> bool:
    """Download/refresh geo databases, then geolocate events that lack a country."""
    ready = await geoip.ensure_databases(force=force)
    backfilled = 0
    if ready:
        backfilled = await backfill_missing_geo(db, geoip)
    logger.info(
        "geoip refresh complete (ready=%s provider=%s backfilled_ips=%d)",
        ready, geoip.provider, backfilled,
    )
    return ready


async def backfill_missing_geo(db: DuckDBManager, geoip: GeoEnricher, days: int = 90) -> int:
    """Geolocate distinct source IPs whose events predate working GeoIP."""
    with db.read() as conn:
        rows = conn.execute(
            "SELECT DISTINCT source_ip FROM events "
            "WHERE country IS NULL AND source_ip IS NOT NULL "
            f"AND timestamp >= now() - interval '{max(1, int(days))} days'"
        ).fetchall()
    updates = []
    for (ip,) in rows:
        info = geoip.enrich(ip)
        if info.country is None and info.asn is None:
            continue
        updates.append((info.country, info.city, info.asn, info.lat, info.lon, ip))
    if updates:
        async with db.write_lock:
            db.writer.executemany(
                "UPDATE events SET country = ?, city = ?, asn = ?, lat = ?, lon = ? "
                "WHERE source_ip = ? AND country IS NULL",
                updates,
            )
            db.writer.execute("CHECKPOINT")
    return len(updates)


BACKFILL_KIND_SQL = """
UPDATE events SET event_kind = CASE
    WHEN attack_type = 'Malware Download' AND payload LIKE 'http%' THEN 'file_download'
    WHEN payload IS NOT NULL AND payload NOT LIKE 'http%' AND payload NOT LIKE 'https%' THEN 'command'
    WHEN username IS NOT NULL THEN 'failed_password'
    ELSE 'connect'
END
WHERE honeypot = 'cowrie' AND event_kind IS NULL
"""


def backfill_event_kinds(db: DuckDBManager) -> int:
    """Approximate event_kind for historical cowrie rows; idempotent, SQL only.

    Rows without a payload and without credentials are treated as plain
    connection probes; command/file_download guesses follow the pre-event_kind
    normalizer conventions. Safe to run repeatedly.
    """
    cursor = db.writer.execute(BACKFILL_KIND_SQL)
    updated = cursor.fetchall()[0][0] if cursor.description else 0
    if updated:
        logger.info("backfilled event_kind on %d cowrie events", int(updated))
    return int(updated)


async def run_backup(db: DuckDBManager, db_path: str, backup_dir: str = BACKUP_DIR) -> str:
    """Checkpoint through the writer, then gzip-copy the DB file."""
    async with db.write_lock:
        db.writer.execute("CHECKPOINT")
    target = backup_database(db_path, backup_dir)
    logger.info("backup written: %s", target)
    return target


def build_scheduler(db: DuckDBManager, geoip: GeoEnricher, settings: Settings) -> AsyncIOScheduler:
    scheduler = AsyncIOScheduler(timezone="UTC")
    scheduler.add_job(
        run_retention,
        "interval",
        hours=1,
        args=(db, settings.retention_days),
        id="retention",
        coalesce=True,
        max_instances=1,
    )
    scheduler.add_job(
        run_geoip_refresh,
        "interval",
        weeks=1,
        args=(db, geoip, True),
        id="geoip",
        coalesce=True,
        max_instances=1,
    )
    scheduler.add_job(
        run_backup,
        "cron",
        hour=3,
        minute=0,
        args=(db, settings.db_path, BACKUP_DIR),
        id="backup",
        coalesce=True,
        max_instances=1,
    )
    scheduler.add_job(
        backfill_event_kinds,
        "interval",
        weeks=1,
        args=(db,),
        id="event-kind-backfill",
        coalesce=True,
        max_instances=1,
    )
    return scheduler
