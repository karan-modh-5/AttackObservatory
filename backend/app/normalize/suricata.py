"""Suricata EVE JSON normalizer: alert events only, service scan."""

from __future__ import annotations

from typing import Any

from app.models import Event
from app.normalize import build_event


def normalize_record(record: dict[str, Any]) -> Event | None:
    if record.get("event_type") != "alert":
        return None
    alert = record.get("alert")
    if not isinstance(alert, dict):
        return None
    signature = alert.get("signature")
    if not isinstance(signature, str) or not signature.strip():
        return None
    flow_id = record.get("flow_id")
    return build_event(
        source="suricata",
        service="scan",
        timestamp=record.get("timestamp"),
        source_ip=record.get("src_ip"),
        payload=signature,
        session_id=str(flow_id) if flow_id is not None else None,
    )
