"""Event listing with all contract filters: GET /events."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, Response
from starlette import status

from app.deps import DbDep, PaginationParams
from app.models import EVENT_COLUMNS, Event, EventListResponse, event_from_row
from app.ratelimit import READ_LIMIT, limiter, resolve_annotations

router = APIRouter(tags=["events"])


def _parse_boundary(value: str, name: str) -> datetime:
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"invalid {name}: expected ISO-8601 timestamp",
        ) from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@router.get("/events", response_model=EventListResponse)
@limiter.limit(READ_LIMIT)
@resolve_annotations
async def list_events(
    request: Request,
    response: Response,
    db: DbDep,
    pagination: PaginationParams,
    honeypot: str | None = Query(default=None),
    service: str | None = Query(default=None),
    attack_type: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    ip: str | None = Query(default=None),
    since: str | None = Query(default=None),
    until: str | None = Query(default=None),
) -> EventListResponse:
    limit, offset = pagination
    clauses: list[str] = []
    params: list[Any] = []
    for column, value in (
        ("honeypot", honeypot),
        ("service", service),
        ("attack_type", attack_type),
        ("severity", severity),
        ("source_ip", ip),
    ):
        if value:
            clauses.append(f"{column} = ?")
            params.append(value)
    if since:
        clauses.append("timestamp >= ?")
        params.append(_parse_boundary(since, "since"))
    if until:
        clauses.append("timestamp <= ?")
        params.append(_parse_boundary(until, "until"))
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""

    total: int
    rows: list[tuple]
    with db.read() as conn:
        total = int(conn.execute(f"SELECT COUNT(*) FROM events{where}", params).fetchone()[0])
        rows = conn.execute(
            f"SELECT {EVENT_COLUMNS} FROM events{where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
    return EventListResponse(total=total, items=[event_from_row(row) for row in rows])
