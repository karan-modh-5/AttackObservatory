"""Cowrie JSON-lines normalizer (ssh + telnet)."""

from __future__ import annotations

from typing import Any

from app.models import Event
from app.normalize import build_event

_KNOWN_PREFIXES = ("cowrie.session.", "cowrie.login.", "cowrie.command.", "cowrie.client.", "cowrie.telnet.")

# Session -> username memory so command.input / file_download / file_upload
# events (which carry only a session) can be attributed to the actor that
# authenticated. Single event loop -> deliberately not thread-safe. Bounded at
# MAX_SESSION_USERS; when full the oldest half is dropped to stay under cap.
MAX_SESSION_USERS = 50_000

_SESSION_USERS: dict[str, str] = {}


def _remember_user(session: Any, username: str) -> None:
    session_id = session if isinstance(session, str) and session.strip() else None
    if session_id is None:
        return
    if len(_SESSION_USERS) >= MAX_SESSION_USERS and session_id not in _SESSION_USERS:
        for key in list(_SESSION_USERS)[: MAX_SESSION_USERS // 2]:
            _SESSION_USERS.pop(key, None)
    _SESSION_USERS[session_id] = username


def _inherited_user(session: Any) -> str | None:
    if not isinstance(session, str):
        return None
    return _SESSION_USERS.get(session)


def _client_version_payload(record: dict[str, Any]) -> str | None:
    version = record.get("version")
    if isinstance(version, (list, tuple)):
        return " ".join(str(item).strip() for item in version if str(item).strip()) or None
    if isinstance(version, str) and version.strip():
        return version.strip()
    return None


def _file_sha256(record: dict[str, Any]) -> str | None:
    shasum = record.get("shasum")
    if not isinstance(shasum, str) or not shasum.strip():
        return None
    text = shasum.strip()
    prefix = "sha256:"
    return text[len(prefix):] if text.lower().startswith(prefix) else text


def _file_size(record: dict[str, Any]) -> int | None:
    filesize = record.get("filesize")
    if isinstance(filesize, bool) or not isinstance(filesize, (int, float, str)):
        return None
    try:
        return int(filesize)
    except (TypeError, ValueError):
        return None


def normalize_record(record: dict[str, Any]) -> Event | None:
    eventid = record.get("eventid")
    if not isinstance(eventid, str) or not eventid.startswith(_KNOWN_PREFIXES):
        return None
    service = "telnet" if eventid.startswith("cowrie.telnet.") else "ssh"
    session = record.get("session")
    if eventid.endswith("login.failed") or eventid.endswith("login.success"):
        username = record.get("username")
        if not isinstance(username, str) or not username.strip():
            return None
        _remember_user(session, username)
        kind = "accepted" if eventid.endswith("login.success") else "failed_password"
        return build_event(
            source="cowrie",
            service=service,
            timestamp=record.get("timestamp"),
            source_ip=record.get("src_ip"),
            username=username,
            password=record.get("password"),
            session_id=session,
            event_kind=kind,
        )
    if eventid.endswith("command.input"):
        command = record.get("input")
        if not isinstance(command, str) or not command.strip():
            return None
        return build_event(
            source="cowrie",
            service=service,
            timestamp=record.get("timestamp"),
            source_ip=record.get("src_ip"),
            payload=command,
            username=_inherited_user(session),
            session_id=session,
            event_kind="command",
        )
    if eventid.endswith("file_download"):
        url = record.get("url") or record.get("outfile")
        if not isinstance(url, str) or not url.strip():
            return None
        return build_event(
            source="cowrie",
            service=service,
            timestamp=record.get("timestamp"),
            source_ip=record.get("src_ip"),
            payload=url,
            username=_inherited_user(session),
            session_id=session,
            event_kind="file_download",
            sha256=_file_sha256(record),
            size_bytes=_file_size(record),
        )
    if eventid.endswith("file_upload"):
        filename = record.get("outfile") or record.get("url")
        payload = filename if isinstance(filename, str) and filename.strip() else "tty upload"
        return build_event(
            source="cowrie",
            service=service,
            timestamp=record.get("timestamp"),
            source_ip=record.get("src_ip"),
            payload=payload,
            username=_inherited_user(session),
            session_id=session,
            event_kind="file_upload",
        )
    if eventid.endswith("client.version"):
        version = _client_version_payload(record)
        if version is None:
            return None
        return build_event(
            source="cowrie",
            service=service,
            timestamp=record.get("timestamp"),
            source_ip=record.get("src_ip"),
            payload=version,
            session_id=session,
            event_kind="client_version",
        )
    if eventid.endswith("session.connect"):
        return build_event(
            source="cowrie",
            service=service,
            timestamp=record.get("timestamp"),
            source_ip=record.get("src_ip"),
            session_id=session,
            event_kind="connect",
        )
    if eventid.endswith("session.closed"):
        # Closed sessions are not probes; event_kind stays NULL.
        return build_event(
            source="cowrie",
            service=service,
            timestamp=record.get("timestamp"),
            source_ip=record.get("src_ip"),
            session_id=session,
        )
    return None
