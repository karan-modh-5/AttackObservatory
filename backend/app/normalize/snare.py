"""Snare normalizer: raw access-log lines (or parsed JSON objects), service http."""

from __future__ import annotations

import json
import re
from typing import Any

from app.models import Event
from app.normalize import build_event

_ACCESS_LINE_RE = re.compile(
    # Combined log format has two ident fields ("- -"); aiohttp's access log
    # (snare's real format) omits them, so the group is optional.
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?:\s+\S+\s+\S+)?\s+"
    r"\[(?P<time>[^\]]+)\]\s+"
    r"\"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<proto>[^\"]*))?\"\s+"
    r"(?P<status>\d{3})\s+(?P<size>\d+|-)"
    r"(?:\s+\"(?P<ref>[^\"]*)\"\s+\"(?P<ua>[^\"]*)\")?\s*$"
)


def _payload(method: str, path: str, status: Any, user_agent: Any) -> str:
    try:
        status_text = f"{int(status):03d}"
    except (TypeError, ValueError):
        status_text = "000"
    return f"{method} {path} {status_text} \"{user_agent or ''}\""


def _from_access_line(line: str) -> Event | None:
    # Real snare output prefixes each access line with its python-logging
    # header (e.g. "2026-10-08 20:51:21 INFO:aiohttp.access:log: "); strip
    # everything up to the apache-style remote address.
    if "aiohttp.access:log:" in line:
        line = line.split("aiohttp.access:log:", 1)[1].strip()
    match = _ACCESS_LINE_RE.match(line)
    if match is None:
        return None
    return build_event(
        source="snare",
        service="http",
        timestamp=match.group("time"),
        source_ip=match.group("ip"),
        payload=_payload(match.group("method"), match.group("path"), match.group("status"), match.group("ua")),
    )


def _from_json(record: dict[str, Any]) -> Event | None:
    path = record.get("path") or record.get("url")
    if not isinstance(path, str) or not path.strip():
        return None
    method = record.get("method") if isinstance(record.get("method"), str) else "GET"
    source_ip = record.get("src_ip") or record.get("ip") or record.get("remote_addr")
    user_agent = record.get("user_agent") or record.get("user-agent") or ""
    return build_event(
        source="snare",
        service="http",
        timestamp=record.get("timestamp") or record.get("time"),
        source_ip=source_ip,
        payload=_payload(method, path, record.get("status", 0), user_agent),
    )


def normalize_record(record: dict[str, Any]) -> Event | None:
    raw = record.get("log")
    if isinstance(raw, str):
        line = raw.strip()
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            record = parsed
        else:
            return _from_access_line(line)
    return _from_json(record)
