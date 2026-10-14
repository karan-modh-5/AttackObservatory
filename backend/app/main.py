"""FastAPI application factory: logging, middleware, routers, lifecycle (contract section 4/5)."""

from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from app.classify import ClassificationEngine
from app.config import Settings, get_settings
from app.db import DuckDBManager
from app.deps import require_admin
from app.geoip import GeoEnricher
from app.ingest import IngestPipeline
from app.jobs import backfill_event_kinds, build_scheduler, run_geoip_refresh
from app.logging_setup import configure_logging, request_id_ctx
from app.routers import PUBLIC_ROUTERS, PROTECTED_ROUTERS
from app.ratelimit import limiter
from app.ws import ConnectionHub

logger = logging.getLogger(__name__)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assigns X-Request-ID, correlates logs and emits one access log per request."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        rid = request.headers.get("x-request-id") or str(uuid.uuid4())
        token = request_id_ctx.set(rid)
        started = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            request_id_ctx.reset(token)
            logger.info(
                "request",
                extra={
                    "http_method": request.method,
                    "http_path": request.url.path,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                },
            )
        response.headers["X-Request-ID"] = rid
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings

    db = DuckDBManager(settings.db_path, settings.db_memory_limit)
    db.connect()
    db.init_schema()

    geoip = GeoEnricher(settings.geoip_dir, settings.maxmind_license_key, enabled=settings.geoip_enabled)
    await run_geoip_refresh(db, geoip)

    try:
        backfill_event_kinds(db)
    except Exception:  # noqa: BLE001 - startup must not die on backfill issues
        logger.error("event_kind backfill failed", exc_info=True)

    hub = ConnectionHub()
    pipeline = IngestPipeline(db, geoip, ClassificationEngine(), hub, settings.queue_maxsize)
    await pipeline.start()

    scheduler = build_scheduler(db, geoip, settings)
    scheduler.start()

    app.state.db = db
    app.state.geoip = geoip
    app.state.hub = hub
    app.state.pipeline = pipeline
    app.state.scheduler = scheduler
    logger.info("attack observatory api started", extra={"db_path": settings.db_path})
    try:
        yield
    finally:
        scheduler.shutdown(wait=False)
        await pipeline.stop()
        try:
            await db.checkpoint()
        except Exception:  # noqa: BLE001 - shutdown must proceed even if checkpoint fails
            logger.error("final checkpoint failed", exc_info=True)
        geoip.close()
        db.close()
        logger.info("attack observatory api stopped")


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()
    configure_logging(resolved.log_level)

    app = FastAPI(title="Attack Observatory", version="1.0.0", lifespan=lifespan)
    app.state.settings = resolved
    app.state.limiter = limiter

    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(SlowAPIMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID"],
    )
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    for router in PROTECTED_ROUTERS:
        app.include_router(router, prefix="/api/v1", dependencies=[Depends(require_admin)])
    for router in PUBLIC_ROUTERS:
        app.include_router(router, prefix="/api/v1")
    return app


app = create_app()
