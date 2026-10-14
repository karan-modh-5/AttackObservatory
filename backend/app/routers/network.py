"""Suricata network statistics: GET /network/stats."""

from __future__ import annotations

from fastapi import APIRouter, Query, Request, Response
from app.deps import DbDep
from app.models import Facet, NetworkStatsResponse, SourceFacet
from app.ratelimit import READ_LIMIT, limiter, resolve_annotations

router = APIRouter(tags=["network"])

_FACET_LIMIT = 20


@router.get("/network/stats", response_model=NetworkStatsResponse)
@limiter.limit(READ_LIMIT)
@resolve_annotations
async def network_stats(
    request: Request,
    response: Response,
    db: DbDep,
    days: int = Query(default=7, ge=1, le=365),
) -> NetworkStatsResponse:
    window = f"honeypot = 'suricata' AND timestamp >= now() - interval '{int(days)} days'"

    total_alerts = int((await db.fetch_all_async(f"SELECT COUNT(*) FROM events WHERE {window}"))[0][0])
    signature_rows = await db.fetch_all_async(
        f"SELECT payload AS name, COUNT(*) AS count FROM events WHERE payload IS NOT NULL AND {window} "
        f"GROUP BY payload ORDER BY count DESC, name LIMIT {_FACET_LIMIT}"
    )
    protocol_rows = await db.fetch_all_async(
        f"SELECT service AS name, COUNT(*) AS count FROM events WHERE {window} "
        f"GROUP BY service ORDER BY count DESC, name LIMIT {_FACET_LIMIT}"
    )
    source_rows = await db.fetch_all_async(
        f"SELECT source_ip AS name, MAX(country) AS country, COUNT(*) AS count FROM events "
        f"WHERE source_ip IS NOT NULL AND {window} "
        f"GROUP BY source_ip ORDER BY count DESC, name LIMIT {_FACET_LIMIT}"
    )
    return NetworkStatsResponse(
        total_alerts=total_alerts,
        signatures=[Facet(name=str(name), count=int(count)) for name, count in signature_rows],
        protocols=[Facet(name=str(name), count=int(count)) for name, count in protocol_rows],
        top_sources=[
            SourceFacet(name=str(name), country=country if isinstance(country, str) else None, count=int(count))
            for name, country, count in source_rows
        ],
    )
