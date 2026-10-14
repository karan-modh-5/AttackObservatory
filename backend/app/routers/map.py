"""Geographic aggregation for the attack map: GET /map/points."""

from __future__ import annotations

from fastapi import APIRouter, Query, Request, Response
from app.deps import DbDep
from app.models import Facet, MapPoint, MapResponse
from app.ratelimit import READ_LIMIT, limiter, resolve_annotations

router = APIRouter(tags=["map"])

_POINT_LIMIT = 500
_COUNTRY_LIMIT = 20


@router.get("/map/points", response_model=MapResponse)
@limiter.limit(READ_LIMIT)
@resolve_annotations
async def map_points(request: Request, response: Response, db: DbDep, days: int = Query(default=7, ge=1, le=365)) -> MapResponse:
    window = f"timestamp >= now() - interval '{int(days)} days'"
    point_rows = await db.fetch_all_async(
        f"SELECT ROUND(lat, 2) AS lat, ROUND(lon, 2) AS lon, COUNT(*) AS weight, MAX(country) AS country "
        f"FROM events WHERE lat IS NOT NULL AND lon IS NOT NULL AND {window} "
        f"GROUP BY 1, 2 ORDER BY weight DESC LIMIT {_POINT_LIMIT}"
    )
    country_rows = await db.fetch_all_async(
        f"SELECT country AS name, COUNT(*) AS count FROM events WHERE country IS NOT NULL AND {window} "
        f"GROUP BY country ORDER BY count DESC, name LIMIT {_COUNTRY_LIMIT}"
    )
    return MapResponse(
        points=[
            MapPoint(lat=float(lat), lon=float(lon), weight=int(weight), country=country if isinstance(country, str) else None)
            for lat, lon, weight, country in point_rows
        ],
        top_countries=[Facet(name=str(name), count=int(count)) for name, count in country_rows],
    )
