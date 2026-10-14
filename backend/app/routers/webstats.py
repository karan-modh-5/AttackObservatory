"""Web honeypot statistics: GET /web/stats (module webstats, route /web/stats)."""

from __future__ import annotations

from fastapi import APIRouter, Query, Request, Response
from app.db import DuckDBManager
from app.deps import DbDep
from app.models import Facet, TypeCount, WebStatsResponse
from app.ratelimit import READ_LIMIT, limiter, resolve_annotations

router = APIRouter(tags=["web"])

_FACET_LIMIT = 20

# Snare payloads look like: GET /path 404 "user-agent"
_URL_EXTRACT = "regexp_extract(payload, '^\\S+\\s+(\\S+)\\s+\\d{3}', 1)"
_UA_EXTRACT = "regexp_extract(payload, '\"([^\"]*)\"\\s*$', 1)"


async def _extract_facet(db: DuckDBManager, extract: str, window: str) -> list[Facet]:
    rows = await db.fetch_all_async(
        f"""
        SELECT name, hits FROM (
            SELECT {extract} AS name, COUNT(*) AS hits
            FROM events
            WHERE honeypot IN ('snare', 'tanner') AND payload IS NOT NULL AND {window}
            GROUP BY 1
        ) sub
        WHERE name <> ''
        ORDER BY hits DESC, name
        LIMIT {_FACET_LIMIT}
        """
    )
    return [Facet(name=str(name), count=int(hits)) for name, hits in rows]


@router.get("/web/stats", response_model=WebStatsResponse)
@limiter.limit(READ_LIMIT)
@resolve_annotations
async def web_stats(request: Request, response: Response, db: DbDep, days: int = Query(default=30, ge=1, le=365)) -> WebStatsResponse:
    window = f"timestamp >= now() - interval '{int(days)} days'"

    scanner_events = int(
        (await db.fetch_all_async(
            f"SELECT COUNT(*) FROM events WHERE attack_type IN ('Web Scanning', 'Directory Scanning') "
            f"AND {window}"
        ))[0][0]
    )
    exploit_rows = await db.fetch_all_async(
        f"SELECT payload AS name, COUNT(*) AS count FROM events WHERE attack_type IN "
        f"('SQL Injection', 'LFI', 'RFI') AND payload IS NOT NULL AND {window} "
        f"GROUP BY payload ORDER BY count DESC, name LIMIT {_FACET_LIMIT}"
    )
    type_rows = await db.fetch_all_async(
        f"SELECT attack_type, COUNT(*) AS count FROM events WHERE honeypot IN ('snare', 'tanner') "
        f"AND {window} GROUP BY attack_type ORDER BY count DESC, attack_type LIMIT {_FACET_LIMIT}"
    )
    return WebStatsResponse(
        scanner_events=scanner_events,
        top_urls=await _extract_facet(db, _URL_EXTRACT, window),
        top_user_agents=await _extract_facet(db, _UA_EXTRACT, window),
        exploit_payloads=[Facet(name=str(name), count=int(count)) for name, count in exploit_rows],
        attack_types=[TypeCount(attack_type=str(label), count=int(count)) for label, count in type_rows],
    )
