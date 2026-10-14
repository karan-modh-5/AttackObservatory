"""Ingest pipeline: bounded asyncio.Queue -> batched DuckDB flush -> WS fan-out.

Flush happens at >= 500 queued events or 1.0 s after the first pending event,
whichever comes first. Inserts run under the manager's asyncio write lock;
after each flush the batch is broadcast to WebSocket subscribers. When the
queue is full events are dropped and counted (graceful degradation).
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from app.classify import ClassificationEngine
from app.db import DuckDBManager
from app.geoip import GeoEnricher
from app.models import Event
from app.normalize import normalize
from app.ws import ConnectionHub

logger = logging.getLogger(__name__)

FLUSH_SIZE = 500
FLUSH_INTERVAL_SECONDS = 1.0
IDLE_POLL_SECONDS = 0.25

INSERT_SQL = (
    "INSERT INTO events (id, timestamp, source_ip, country, city, asn, lat, lon, "
    "honeypot, service, attack_type, username, password, payload, severity, session_id, "
    "event_kind, sha256, size_bytes) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)

_FLUSHED_COLUMNS = (
    "timestamp, source_ip, country, city, asn, lat, lon, honeypot, service, "
    "attack_type, username, password, payload, severity, session_id"
)


class IngestPipeline:
    """Single-consumer batching queue between the API and DuckDB."""

    def __init__(
        self,
        db: DuckDBManager,
        geoip: GeoEnricher,
        engine: ClassificationEngine,
        hub: ConnectionHub,
        queue_maxsize: int,
    ) -> None:
        self.db = db
        self.geoip = geoip
        self.engine = engine
        self.hub = hub
        self.queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=queue_maxsize)
        self.dropped = 0
        self._buffer: list[Event] = []
        self._oldest_enqueued_at: float | None = None
        self._flush_lock = asyncio.Lock()
        self._consumer: asyncio.Task[None] | None = None
        self._stopping = False

    # --- ingest side (called from request handlers) ----------------------

    def process(self, source: str, record: dict[str, Any]) -> Event | None:
        """normalize -> geo enrich -> classify; None means the record was rejected."""
        event = normalize(source, record)
        if event is None:
            return None
        info = self.geoip.enrich(event.source_ip)
        event.country = info.country
        event.city = info.city
        event.asn = info.asn
        event.lat = info.lat
        event.lon = info.lon
        return self.engine.classify(event, record)

    def enqueue(self, event: Event) -> bool:
        try:
            self.queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            self.dropped += 1
            logger.warning("ingest queue full; event dropped (dropped=%d)", self.dropped)
            return False

    @property
    def queue_depth(self) -> int:
        return self.queue.qsize()

    # --- lifecycle --------------------------------------------------------

    async def start(self) -> None:
        self._stopping = False
        self._consumer = asyncio.create_task(self._consume(), name="ingest-consumer")

    async def stop(self) -> None:
        self._stopping = True
        consumer = self._consumer
        if consumer is not None:
            try:
                await consumer
            except asyncio.CancelledError:
                logger.warning("ingest consumer cancelled during shutdown")
        self._consumer = None

    # --- consumer ---------------------------------------------------------

    async def _consume(self) -> None:
        while True:
            event: Event | None = None
            try:
                event = await asyncio.wait_for(self.queue.get(), timeout=IDLE_POLL_SECONDS)
            except asyncio.TimeoutError:
                event = None
            if event is not None:
                if not self._buffer:
                    self._oldest_enqueued_at = time.monotonic()
                self._buffer.append(event)
                while len(self._buffer) < FLUSH_SIZE:
                    try:
                        self._buffer.append(self.queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break
            due = len(self._buffer) >= FLUSH_SIZE or (
                bool(self._buffer)
                and self._oldest_enqueued_at is not None
                and time.monotonic() - self._oldest_enqueued_at >= FLUSH_INTERVAL_SECONDS
            )
            if due:
                await self.flush()
            if self._stopping and self.queue.empty() and not self._buffer:
                return

    async def flush(self) -> int:
        """Drain queue + buffer into DuckDB, then broadcast; returns rows written."""
        async with self._flush_lock:
            while not self.queue.empty():
                try:
                    if not self._buffer:
                        self._oldest_enqueued_at = time.monotonic()
                    self._buffer.append(self.queue.get_nowait())
                except asyncio.QueueEmpty:
                    break
            if not self._buffer:
                self._oldest_enqueued_at = None
                return 0
            batch = self._buffer
            self._buffer = []
            self._oldest_enqueued_at = None

            rows: list[tuple[Any, ...]] = []
            events = batch
            async with self.db.write_lock:
                first_id = int(self.db.writer.execute("SELECT nextval('events_id_seq')").fetchone()[0])
                for offset, event in enumerate(events):
                    event.id = first_id + offset
                    rows.append(
                        (
                            event.id,
                            event.timestamp,
                            event.source_ip,
                            event.country,
                            event.city,
                            event.asn,
                            event.lat,
                            event.lon,
                            event.honeypot,
                            event.service,
                            event.attack_type,
                            event.username,
                            event.password,
                            event.payload,
                            event.severity,
                            event.session_id,
                            event.event_kind,
                            event.sha256,
                            event.size_bytes,
                        )
                    )
                self.db.writer.executemany(INSERT_SQL, rows)
            frames = [event.model_dump(mode="json") for event in events]
            await self.hub.broadcast_batch(frames)
            logger.debug("flushed %d events to duckdb", len(rows))
            return len(rows)
