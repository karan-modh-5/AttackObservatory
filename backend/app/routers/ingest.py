"""Ingest endpoint: POST /ingest/{source} with X-API-Key (contract section 5)."""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Body, Header, HTTPException, Request, status

from app.config import Settings
from app.models import IngestResponse
from app.normalize import SOURCES
from app.security import ingest_key_matches

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ingest"])

MAX_BATCH = 5000


@router.post("/ingest/{source}", response_model=IngestResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest(
    source: str,
    request: Request,
    records: Annotated[list[dict[str, Any]], Body()],
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> IngestResponse:
    settings: Settings = request.app.state.settings
    if not ingest_key_matches(x_api_key, settings.ingest_api_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing X-API-Key")
    if source not in SOURCES:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"unknown source: {source}")
    if len(records) > MAX_BATCH:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"batch too large: max {MAX_BATCH} records",
        )
    pipeline = request.app.state.pipeline
    accepted = 0
    rejected = 0
    for record in records:
        event = pipeline.process(source, record)
        if event is not None and pipeline.enqueue(event):
            accepted += 1
        else:
            rejected += 1
    logger.info("ingest batch", extra={"source": source, "accepted": accepted, "rejected": rejected})
    return IngestResponse(accepted=accepted, rejected=rejected)
