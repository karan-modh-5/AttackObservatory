"""Aggregated statistics: GET /stats/overview, GET /stats/timeseries."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Query, Request, Response
from app.deps import DbDep
from app.models import OverviewResponse, TimeseriesPoint, TimeseriesResponse, TypeCount
from app.ratelimit import READ_LIMIT, limiter, resolve_annotations

router = APIRouter(tags=["stats"])


@router.get("/stats/overview", response_model=OverviewResponse)
@limiter.limit(READ_LIMIT)
@resolve_annotations
async def overview(request: Request, response: Response, db: DbDep) -> OverviewResponse:
    row = (await db.fetch_all_async(
        """
        SELECT
            COUNT(*) AS total_attacks,
            COUNT(DISTINCT source_ip) AS unique_attackers,
            COUNT(DISTINCT country) AS countries,
            COUNT(*) FILTER (WHERE username IS NOT NULL) AS credentials_captured,
            COUNT(*) FILTER (WHERE honeypot = 'cowrie' AND payload IS NOT NULL) AS commands_executed,
            COUNT(*) FILTER (WHERE timestamp >= now() - INTERVAL 24 HOUR) AS last_24h,
            COUNT(*) FILTER (WHERE honeypot = 'cowrie') AS ssh_events,
            COUNT(DISTINCT source_ip) FILTER (WHERE honeypot = 'cowrie') AS ssh_unique_ips
        FROM events
        """
    ))[0]
    return OverviewResponse(
        total_attacks=int(row[0]),
        unique_attackers=int(row[1]),
        countries=int(row[2]),
        credentials_captured=int(row[3]),
        commands_executed=int(row[4]),
        last_24h=int(row[5]),
        ssh_events=int(row[6]),
        ssh_unique_ips=int(row[7]),
    )


@router.get("/stats/timeseries", response_model=TimeseriesResponse)
@limiter.limit(READ_LIMIT)
@resolve_annotations
async def timeseries(
    request: Request,
    response: Response,
    db: DbDep,
    days: int = Query(default=7, ge=1, le=365),
    interval: Literal["hour", "day"] = Query(default="hour"),
) -> TimeseriesResponse:
    window = f"timestamp >= now() - interval '{int(days)} days'"
    point_rows = await db.fetch_all_async(
        f"""
        SELECT date_trunc('{interval}', timestamp) AS bucket, COUNT(*) AS total
        FROM events
        WHERE {window}
        GROUP BY 1
        ORDER BY 1
        """
    )
    type_rows = await db.fetch_all_async(
        f"""
        SELECT attack_type, COUNT(*) AS count
        FROM events
        WHERE {window}
        GROUP BY attack_type
        ORDER BY count DESC, attack_type
        LIMIT 20
        """
    )
    points = []
    for bucket, total in point_rows:
        moment = bucket if isinstance(bucket, datetime) else None
        if moment is None:
            bucket_text = str(bucket)
        else:
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
            bucket_text = moment.isoformat()
        points.append(TimeseriesPoint(bucket=bucket_text, total=int(total)))
    return TimeseriesResponse(
        interval=interval,
        points=points,
        by_type=[TypeCount(attack_type=str(label), count=int(count)) for label, count in type_rows],
    )
