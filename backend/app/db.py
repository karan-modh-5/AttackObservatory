"""DuckDB persistence: single writer connection + read-only readers (contract section 1)."""

from __future__ import annotations

import asyncio
import logging
import queue
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Sequence

import duckdb

logger = logging.getLogger(__name__)

_READ_POOL_SIZE = 4

DDL: tuple[str, ...] = (
    "CREATE SEQUENCE IF NOT EXISTS events_id_seq;",
    """
    CREATE TABLE IF NOT EXISTS events (
        id          BIGINT DEFAULT nextval('events_id_seq'),
        timestamp   TIMESTAMPTZ NOT NULL,
        source_ip   VARCHAR,
        country     VARCHAR,
        city        VARCHAR,
        asn         VARCHAR,
        lat         DOUBLE,
        lon         DOUBLE,
        honeypot    VARCHAR NOT NULL,
        service     VARCHAR NOT NULL,
        attack_type VARCHAR NOT NULL,
        username    VARCHAR,
        password    VARCHAR,
        payload     VARCHAR,
        severity    VARCHAR NOT NULL,
        session_id  VARCHAR,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_events_ts        ON events (timestamp);",
    # Lightweight idempotent migration for databases created before actor
    # intelligence metadata existed; no-ops when the columns are present.
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS event_kind VARCHAR;",
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS sha256 VARCHAR;",
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS size_bytes BIGINT;",
    "CREATE INDEX IF NOT EXISTS idx_events_kind ON events (event_kind);",
    "CREATE INDEX IF NOT EXISTS idx_events_sha ON events (sha256);",
    "CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events (source_ip);",
    "CREATE INDEX IF NOT EXISTS idx_events_type      ON events (attack_type);",
    "CREATE INDEX IF NOT EXISTS idx_events_honeypot  ON events (honeypot);",
)


class DuckDBManager:
    """Owns the only writable connection plus helpers for read-only access.

    Writes are serialized through `write_lock` (asyncio). Readers always use
    `read_only=True` connections; when a DuckDB build refuses to open a
    read-only connection next to the writer (instance-cache config clash),
    reads fall back to cursor connections of the writer, which share the same
    database instance but are only ever used for SELECTs by this class.
    """

    def __init__(self, db_path: str, memory_limit: str = "128MB") -> None:
        self.db_path = db_path
        self.memory_limit = memory_limit
        self.write_lock = asyncio.Lock()
        self._writer: duckdb.DuckDBPyConnection | None = None
        self._read_via_cursor = False
        # Long-lived read cursors. DuckDB cursor() forks the whole instance
        # context (~0.5-1s against a warmed database), so per-call creation
        # taxed every endpoint; pool them and reuse across requests instead.
        self._read_pool: queue.Queue[duckdb.DuckDBPyConnection] = queue.Queue()

    def connect(self) -> None:
        path = Path(self.db_path)
        if str(path.parent) not in ("", "."):
            path.parent.mkdir(parents=True, exist_ok=True)
        self._writer = duckdb.connect(self.db_path)
        self._apply_pragmas(self._writer)
        self._read_via_cursor = not self._probe_read_only()
        if self._read_via_cursor:
            for _ in range(_READ_POOL_SIZE):
                self._read_pool.put(self._new_read_cursor())

    def _apply_pragmas(self, conn: duckdb.DuckDBPyConnection) -> None:
        conn.execute(f"PRAGMA memory_limit='{self.memory_limit}'")
        conn.execute("PRAGMA threads=1")
        conn.execute("SET TimeZone='UTC'")

    def _probe_read_only(self) -> bool:
        """Check whether a read_only connection can coexist with the writer."""
        try:
            probe = duckdb.connect(self.db_path, read_only=True)
        except duckdb.Error as exc:
            logger.info("read_only connections unavailable beside writer; using cursors: %s", exc)
            return False
        probe.close()
        return True

    @property
    def writer(self) -> duckdb.DuckDBPyConnection:
        if self._writer is None:
            raise RuntimeError("database manager is not connected")
        return self._writer

    def init_schema(self) -> None:
        for statement in DDL:
            self.writer.execute(statement)

    @contextmanager
    def read(self) -> Iterator[duckdb.DuckDBPyConnection]:
        """Yield a pooled read connection for SELECT workloads."""
        conn = self._acquire_read()
        ok = False
        try:
            yield conn
            ok = True
        finally:
            self._release_read(conn, reuse=ok)

    def _acquire_read(self) -> duckdb.DuckDBPyConnection:
        if not self._read_via_cursor:
            conn = duckdb.connect(self.db_path, read_only=True)
            self._apply_pragmas(conn)
            return conn
        try:
            return self._read_pool.get_nowait()
        except queue.Empty:
            return self._new_read_cursor()

    def _release_read(self, conn: duckdb.DuckDBPyConnection, reuse: bool) -> None:
        if self._read_via_cursor and reuse and self._read_pool.qsize() < _READ_POOL_SIZE:
            self._read_pool.put(conn)
        else:
            conn.close()

    def _new_read_cursor(self) -> duckdb.DuckDBPyConnection:
        if self._writer is None:
            raise RuntimeError("database manager is not connected")
        conn = self._writer.cursor()
        self._apply_pragmas(conn)
        return conn

    def fetch_all(self, sql: str, params: Sequence[Any] | None = None) -> list[tuple]:
        with self.read() as conn:
            return conn.execute(sql, list(params or [])).fetchall()

    async def fetch_all_async(self, sql: str, params: Sequence[Any] | None = None) -> list[tuple]:
        """fetch_all off the event loop.

        Routers are `async def`; calling the sync fetch_all directly would block
        the loop and serialize every parallel page request behind the slowest
        query. to_thread keeps the loop responsive while the pool guarantees a
        cursor is checked out by at most one thread at a time.
        """
        return await asyncio.to_thread(self.fetch_all, sql, params)

    async def execute_write(self, sql: str, params: Sequence[Any] | None = None) -> None:
        async with self.write_lock:
            self.writer.execute(sql, list(params or []))

    async def checkpoint(self) -> None:
        async with self.write_lock:
            self.writer.execute("CHECKPOINT")

    def checkpoint_sync(self) -> None:
        self.writer.execute("CHECKPOINT")

    def close(self) -> None:
        if self._writer is not None:
            self._writer.close()
            self._writer = None
