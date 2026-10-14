"""HTTP + WebSocket routers mounted under /api/v1 (contract section 4)."""

from app.routers.auth import router as auth_router
from app.routers.credentials import router as credentials_router
from app.routers.events import router as events_router
from app.routers.health import router as health_router
from app.routers.ingest import router as ingest_router
from app.routers.ioc import router as ioc_router
from app.routers.map import router as map_router
from app.routers.network import router as network_router
from app.routers.stats import router as stats_router
from app.routers.ssh import router as ssh_router
from app.routers.webstats import router as webstats_router
from app.routers.ws import router as ws_router

# JWT-protected routers (Authorization: Bearer).
PROTECTED_ROUTERS = (
    credentials_router,
    events_router,
    ioc_router,
    map_router,
    network_router,
    stats_router,
    ssh_router,
    webstats_router,
)

# Routers that handle their own credentials (login, ingest key, public health, WS token).
PUBLIC_ROUTERS = (
    auth_router,
    health_router,
    ingest_router,
    ws_router,
)

__all__ = ["PROTECTED_ROUTERS", "PUBLIC_ROUTERS"]
