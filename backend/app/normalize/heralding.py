"""Heralding auth CSV normalizer (heralding_auth.csv lines).

Heralding 1.0.7 writes a named-header CSV:
timestamp,auth_id,session_id,source_ip,source_port,destination_ip,destination_port,
protocol,username,password,password_hash

Fluent Bit posts each CSV line as its own record, so data lines arrive without
the header row; fields are therefore mapped positionally onto the known header
names via csv.DictReader(fieldnames=...). The header line itself maps to
values like protocol="protocol" and is rejected by the service check. The
legacy contract shape (time_retrieved/src_ip/...) is kept as a fallback.
Timestamps are naive local strings; the container runs TZ=UTC so they are UTC.
"""

from __future__ import annotations

import csv
import io
from typing import Any

from app.models import Event
from app.normalize import build_event

SERVICES: frozenset[str] = frozenset({"ssh", "telnet", "http", "https", "ftp", "smtp", "imap", "pop3"})

_STANDARD_FIELDS = (
    "timestamp", "auth_id", "session_id", "source_ip", "source_port",
    "destination_ip", "destination_port", "protocol", "username", "password",
    "password_hash",
)
_LEGACY_FIELDS = (
    "time_retrieved", "src_ip", "src_port", "dst_ip", "dst_port",
    "protocol", "username", "password",
)


def _pick(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = row.get(name)
        if value is not None and str(value).strip():
            return value
    return None


def normalize_record(record: dict[str, Any]) -> Event | None:
    raw = record.get("log")
    if not isinstance(raw, str):
        return None
    line = raw.strip()
    if not line:
        return None
    for fieldnames in (_STANDARD_FIELDS, _LEGACY_FIELDS):
        reader = csv.DictReader(io.StringIO(line), fieldnames=fieldnames, restval=None)
        row = next(reader, None)
        if row is None:
            return None
        service = str(row.get("protocol") or "").strip().lower()
        if service not in SERVICES:
            continue  # header row, wrong shape, or unknown protocol
        return build_event(
            source="heralding",
            service=service,
            timestamp=_pick(row, "timestamp", "time_retrieved"),
            source_ip=_pick(row, "source_ip", "src_ip"),
            username=row.get("username"),
            password=row.get("password"),
            session_id=_pick(row, "session_id", "auth_id"),
        )
    return None
