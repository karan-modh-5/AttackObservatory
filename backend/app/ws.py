"""WebSocket fan-out hub for live events."""

from __future__ import annotations

import asyncio
import logging

import orjson
from fastapi import WebSocket

logger = logging.getLogger(__name__)

SEND_TIMEOUT_SECONDS = 10.0


class ConnectionHub:
    """Tracks connected websockets and broadcasts event frames to all of them."""

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections.add(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(websocket)
        try:
            await websocket.close(code=1000)
        except Exception:  # noqa: BLE001 - socket may already be closed
            logger.debug("websocket already closed", exc_info=True)

    async def broadcast(self, event: dict[str, object]) -> None:
        await self.broadcast_batch([event])

    async def broadcast_batch(self, events: list[dict[str, object]]) -> None:
        """Best-effort send to every subscriber; broken sockets are dropped."""
        if not events or not self._connections:
            return
        frames = [orjson.dumps(event).decode("utf-8") for event in events]
        stale: list[WebSocket] = []
        for websocket in list(self._connections):
            try:
                for frame in frames:
                    await asyncio.wait_for(websocket.send_text(frame), timeout=SEND_TIMEOUT_SECONDS)
            except Exception:  # noqa: BLE001 - any send failure drops the subscriber
                stale.append(websocket)
        for websocket in stale:
            await self.disconnect(websocket)
