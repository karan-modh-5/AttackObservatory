"""Tanner normalizer: raw JSON-ish stdout lines, service http.

Detection ids (sqli, lfi, rfi, rfi/include, xss) drive classification, so the
payload is built as "<detection> <path>" (path alone when no detection found).
"""

from __future__ import annotations

import json
import re
from typing import Any

from app.models import Event
from app.normalize import build_event

_DETECTION_RE = re.compile(r"\b(?:rfi/include|rfi|sqli|lfi|xss)\b", re.IGNORECASE)
_ACCESS_RE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\S*\s+.*?\"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+[^\"]*)?\""
)
_BRACKET_TIME_RE = re.compile(r"\[(?P<time>[^\]]+)\]")


def _payload(detection: str, path: str) -> str:
    return f"{detection} {path}" if detection else path


def _bracket_time(line: str | None) -> Any:
    if not line:
        return None
    match = _BRACKET_TIME_RE.search(line)
    return match.group("time") if match else None


def _from_detection(record: dict[str, Any], line: str | None) -> Event | None:
    detection_raw = (
        record.get("detection")
        or record.get("det_id")
        or record.get("id")
        or record.get("name")
    )
    if isinstance(detection_raw, dict):
        detection_raw = detection_raw.get("name")
    detection = str(detection_raw).strip().lower() if isinstance(detection_raw, str) else ""
    path = record.get("path") or record.get("url")
    path = str(path).strip() if isinstance(path, str) and path.strip() else ""
    if not detection and not path:
        return None
    source_ip = record.get("src_ip") or record.get("ip")
    if not isinstance(source_ip, str) or not source_ip.strip():
        source_ip = None
    return build_event(
        source="tanner",
        service="http",
        timestamp=record.get("timestamp") or _bracket_time(line),
        source_ip=source_ip,
        payload=_payload(detection, path),
    )


def _from_line(line: str) -> Event | None:
    detection_match = _DETECTION_RE.search(line)
    detection = detection_match.group(0).lower() if detection_match else ""
    access_match = _ACCESS_RE.match(line)
    path = access_match.group("path") if access_match else ""
    if not detection and not path:
        return None
    source_ip = access_match.group("ip") if access_match else None
    return build_event(
        source="tanner",
        service="http",
        timestamp=_bracket_time(line),
        source_ip=source_ip,
        payload=_payload(detection, path),
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
            return _from_detection(parsed, line)
        return _from_line(line)
    return _from_detection(record, None)
