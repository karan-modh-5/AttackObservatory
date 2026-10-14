"""Health probes: GET /health, GET /health/ready."""

from __future__ import annotations

import time

from fastapi import APIRouter, Request

from app.models import HealthResponse, ReadinessResponse

router = APIRouter(tags=["health"])

_PROCESS_START = time.monotonic()


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get("/health/ready", response_model=ReadinessResponse)
async def readiness(request: Request) -> ReadinessResponse:
    db = request.app.state.db
    geoip = request.app.state.geoip
    pipeline = request.app.state.pipeline
    try:
        with db.read() as conn:
            conn.execute("SELECT 1").fetchone()
        database = "ok"
    except Exception:  # noqa: BLE001 - readiness must report, not raise
        database = "error"
    if geoip.is_ready():
        geoip_state = geoip.provider
    elif not geoip.enabled or geoip.download_failed:
        geoip_state = "disabled"
    else:
        geoip_state = "downloading"
    overall = "ok" if database == "ok" else "degraded"
    uptime_seconds = int(time.monotonic() - _PROCESS_START)
    return ReadinessResponse(status=overall, database=database, geoip=geoip_state, queue_depth=pipeline.queue_depth, uptime_seconds=uptime_seconds)
