"""Shared FastAPI dependencies: settings access, admin auth, pagination, DB handle."""

from __future__ import annotations

from typing import Annotated

import jwt as pyjwt
from fastapi import Depends, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import Settings
from app.db import DuckDBManager
from app.security import decode_access_token

_bearer = HTTPBearer(auto_error=False, description="JWT access token")


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_db(request: Request) -> DuckDBManager:
    db: DuckDBManager = request.app.state.db
    return db


def require_admin(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> str:
    """Validate the bearer JWT and return the admin username."""
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    settings: Settings = request.app.state.settings
    try:
        return decode_access_token(credentials.credentials, settings.secret_key)
    except pyjwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


async def pagination(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> tuple[int, int]:
    return limit, offset


PaginationParams = Annotated[tuple[int, int], Depends(pagination)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
DbDep = Annotated[DuckDBManager, Depends(get_db)]
