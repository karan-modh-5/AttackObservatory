"""Credential statistics: GET /credentials/stats."""

from __future__ import annotations

from fastapi import APIRouter, Query, Request, Response
from app.deps import DbDep
from app.models import CredentialsStatsResponse, CredentialReusePair, Facet
from app.ratelimit import READ_LIMIT, limiter, resolve_annotations

router = APIRouter(tags=["credentials"])

_FACET_LIMIT = 20


@router.get("/credentials/stats", response_model=CredentialsStatsResponse)
@limiter.limit(READ_LIMIT)
@resolve_annotations
async def credentials_stats(
    request: Request,
    response: Response,
    db: DbDep,
    days: int = Query(default=30, ge=1, le=365),
) -> CredentialsStatsResponse:
    window = f"timestamp >= now() - interval '{int(days)} days'"
    cred_filter = "username IS NOT NULL AND password IS NOT NULL"

    unique_pairs = int(
        (await db.fetch_all_async(
            f"SELECT COUNT(*) FROM (SELECT DISTINCT username, password FROM events "
            f"WHERE {cred_filter} AND {window})"
        ))[0][0]
    )
    by_service_rows = await db.fetch_all_async(
        f"SELECT service AS name, COUNT(*) AS count FROM events WHERE username IS NOT NULL "
        f"AND {window} GROUP BY service ORDER BY count DESC, name LIMIT {_FACET_LIMIT}"
    )
    top_usernames_rows = await db.fetch_all_async(
        f"SELECT username AS name, COUNT(*) AS count FROM events WHERE username IS NOT NULL "
        f"AND {window} GROUP BY username ORDER BY count DESC, name LIMIT {_FACET_LIMIT}"
    )
    top_passwords_rows = await db.fetch_all_async(
        f"SELECT password AS name, COUNT(*) AS count FROM events WHERE password IS NOT NULL "
        f"AND {window} GROUP BY password ORDER BY count DESC, name LIMIT {_FACET_LIMIT}"
    )
    reuse_rows = await db.fetch_all_async(
        f"SELECT username, password, COUNT(DISTINCT source_ip) AS ips FROM events "
        f"WHERE {cred_filter} AND source_ip IS NOT NULL AND {window} "
        f"GROUP BY username, password HAVING COUNT(DISTINCT source_ip) >= 2 "
        f"ORDER BY ips DESC, username LIMIT {_FACET_LIMIT}"
    )

    def facets(rows: list[tuple]) -> list[Facet]:
        return [Facet(name=str(name), count=int(count)) for name, count in rows]

    return CredentialsStatsResponse(
        unique_pairs=unique_pairs,
        by_service=facets(by_service_rows),
        top_usernames=facets(top_usernames_rows),
        top_passwords=facets(top_passwords_rows),
        reuse_pairs=[
            CredentialReusePair(username=str(username), password=str(password), count=int(ips))
            for username, password, ips in reuse_rows
        ],
    )
