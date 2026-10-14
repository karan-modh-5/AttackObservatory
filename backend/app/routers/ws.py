"""WebSocket live feed: WS /ws/live?token=<jwt>; closes 4401 on a bad token."""

from __future__ import annotations

import jwt as pyjwt
import logging
import orjson
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from app.security import decode_access_token

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ws"])

INVALID_TOKEN_CLOSE = 4401


@router.websocket("/ws/live")
async def live(websocket: WebSocket, token: str = Query(default="")) -> None:
    settings = websocket.app.state.settings
    try:
        decode_access_token(token, settings.secret_key)
    except pyjwt.PyJWTError:
        await websocket.accept()
        await websocket.close(code=INVALID_TOKEN_CLOSE, reason="invalid token")
        return
    hub = websocket.app.state.hub
    await hub.connect(websocket)
    try:
        while True:
            message = await websocket.receive_text()
            try:
                data = orjson.loads(message)
            except orjson.JSONDecodeError:
                continue
            if isinstance(data, dict) and data.get("type") == "ping":
                await websocket.send_text(orjson.dumps({"type": "pong"}).decode("utf-8"))
    except WebSocketDisconnect:
        logger.debug("websocket client disconnected", exc_info=True)
    finally:
        await hub.disconnect(websocket)
