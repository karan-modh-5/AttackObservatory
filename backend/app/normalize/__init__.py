"""Record normalizers: raw honeypot output -> Event (contract section 3).

Shared helpers are defined before the submodule imports at the bottom of this
module, so submodules can `from app.normalize import build_event` while the
package initializes.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable

from app.models import Event

logger = logging.getLogger(__name__)

MAX_PAYLOAD_BYTES = 8 * 1024

SOURCES: frozenset[str] = frozenset({"cowrie", "snare", "tanner", "heralding", "suricata"})

_FALLBACK_TIME_FORMATS = (
    "%d/%b/%Y:%H:%M:%S %z",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(value: Any) -> datetime:
    """Parse epoch seconds / ISO-8601 / apache log dates; naive means UTC."""
    if value is None:
        return utcnow()
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    text = str(value).strip()
    if not text:
        return utcnow()
    if text.replace(".", "", 1).isdigit():
        return datetime.fromtimestamp(float(text), tz=timezone.utc)
    iso_text = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        parsed = datetime.fromisoformat(iso_text)
    except ValueError:
        for fmt in _FALLBACK_TIME_FORMATS:
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            raise ValueError(f"unparsable timestamp: {text!r}") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def clean(value: Any, limit: int = MAX_PAYLOAD_BYTES) -> str | None:
    """Trim to str and cap at `limit` bytes; empty results become None."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    encoded = text.encode("utf-8")[:limit]
    return encoded.decode("utf-8", errors="ignore")


def build_event(
    *,
    source: str,
    service: str,
    timestamp: Any = None,
    source_ip: Any = None,
    username: Any = None,
    password: Any = None,
    payload: Any = None,
    session_id: Any = None,
    event_kind: str | None = None,
    sha256: str | None = None,
    size_bytes: int | None = None,
) -> Event:
    """Construct an Event with UTC timestamp, cleaned fields and capped payload."""
    return Event(
        timestamp=parse_timestamp(timestamp),
        source_ip=clean(source_ip),
        honeypot=source,  # type: ignore[arg-type]
        service=service,
        attack_type="",
        username=clean(username),
        password=clean(password),
        payload=clean(payload),
        severity="",
        session_id=clean(session_id),
        event_kind=event_kind,
        sha256=sha256,
        size_bytes=size_bytes,
    )


def normalize(source: str, record: Any) -> Event | None:
    """Dispatch to the source normalizer; malformed input -> None, never raises."""
    handler = _HANDLERS.get(source)
    if handler is None or not isinstance(record, dict):
        return None
    try:
        return handler(record)
    except Exception:  # noqa: BLE001 - malformed records must never break ingest
        logger.debug("dropping malformed %s record", source, exc_info=True)
        return None


from app.normalize.cowrie import normalize_record as _cowrie_record  # noqa: E402
from app.normalize.heralding import normalize_record as _heralding_record  # noqa: E402
from app.normalize.snare import normalize_record as _snare_record  # noqa: E402
from app.normalize.suricata import normalize_record as _suricata_record  # noqa: E402
from app.normalize.tanner import normalize_record as _tanner_record  # noqa: E402

_HANDLERS: dict[str, Callable[[dict[str, Any]], Event | None]] = {
    "cowrie": _cowrie_record,
    "heralding": _heralding_record,
    "snare": _snare_record,
    "tanner": _tanner_record,
    "suricata": _suricata_record,
}
