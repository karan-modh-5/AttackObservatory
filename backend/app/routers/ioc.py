"""IOC listing and export: GET /ioc, GET /ioc/export."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, Response
from starlette import status

from app.deps import DbDep
from app.ioc import TYPES, collect_iocs, export_csv, export_json, parse_types
from app.models import IocHit, IocIp, IocResponse
from app.ratelimit import READ_LIMIT, limiter, resolve_annotations

router = APIRouter(tags=["ioc"])


@router.get("/ioc", response_model=IocResponse)
@limiter.limit(READ_LIMIT)
@resolve_annotations
async def list_iocs(request: Request, response: Response, db: DbDep, days: int = Query(default=7, ge=1, le=365)) -> IocResponse:
    iocs = collect_iocs(db, days)
    return IocResponse(
        ips=[IocIp(**item) for item in iocs["ips"]],
        urls=[IocHit(**item) for item in iocs["urls"]],
        domains=[IocHit(**item) for item in iocs["domains"]],
        hashes=[IocHit(**item) for item in iocs["hashes"]],
    )


@router.get("/ioc/export")
@limiter.limit(READ_LIMIT)
@resolve_annotations
async def export_iocs(
    request: Request,
    response: Response,
    db: DbDep,
    format: str = Query(default="csv", pattern="^(csv|json)$"),
    types: str = Query(default="ip,url,domain,hash"),
    days: int = Query(default=7, ge=1, le=365),
) -> Response:
    try:
        selected = parse_types(types)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    iocs = collect_iocs(db, days)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    if format == "csv":
        body: Any = export_csv(iocs, selected)
        media_type = "text/csv; charset=utf-8"
        extension = "csv"
    else:
        body = export_json(iocs, selected)
        media_type = "application/json"
        extension = "json"
    return Response(
        content=body,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="ioc_{stamp}.{extension}"'},
    )
