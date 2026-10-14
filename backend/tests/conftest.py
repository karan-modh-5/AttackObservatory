"""Shared fixtures: OBS_* env defaults, temp DuckDB app with geoip disabled."""

from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("OBS_SECRET_KEY", "test-secret-key")
os.environ.setdefault("OBS_ADMIN_PASSWORD", "test-password")
os.environ.setdefault("OBS_INGEST_API_KEY", "test-ingest-key")
os.environ.setdefault("OBS_LOG_LEVEL", "WARNING")

from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.config import Settings
from app.main import create_app
from app.ratelimit import limiter

ADMIN_PASSWORD = "test-password"
INGEST_KEY = "test-ingest-key"


def make_settings(tmp_path: Any) -> Settings:
    """Build Settings bound to a temp database.

    pydantic-settings ignores field-name init kwargs when validation_alias is
    set (it reads only the OBS_* environment), so tests must configure through
    the environment. Values are captured into the returned Settings object and
    the process env is restored afterwards.
    """
    tmp = Path(tmp_path)
    overrides = {
        "OBS_SECRET_KEY": "test-secret-key",
        "OBS_ADMIN_USER": "admin",
        "OBS_ADMIN_PASSWORD": ADMIN_PASSWORD,
        "OBS_INGEST_API_KEY": INGEST_KEY,
        "OBS_TOKEN_EXPIRE_MINUTES": "1440",
        "OBS_DB_PATH": str(tmp / "observatory.duckdb"),
        "OBS_GEOIP_DIR": str(tmp / "geoip"),
        "OBS_GEOIP_ENABLED": "false",
        "OBS_MAXMIND_LICENSE_KEY": "",
        "OBS_LOG_LEVEL": "WARNING",
        "OBS_CORS_ORIGINS": "http://localhost:5173",
    }
    saved: dict[str, str | None] = {key: os.environ.get(key) for key in overrides}
    os.environ.update(overrides)
    try:
        return Settings()
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@pytest.fixture()
async def app_client(tmp_path: Any) -> AsyncIterator[tuple[FastAPI, AsyncClient]]:
    limiter.reset()
    app = create_app(make_settings(tmp_path))
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            yield app, client


def iso_utc(seconds_ago: int) -> str:
    moment = datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def apache_utc(seconds_ago: int) -> str:
    moment = datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
    return moment.strftime("%d/%b/%Y:%H:%M:%S +0000")
