"""Pydantic models: normalized event plus every API response (contract sections 1 and 4)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Sequence

from pydantic import BaseModel

Honeypot = Literal["cowrie", "snare", "tanner", "heralding", "suricata"]
Service = Literal["ssh", "telnet", "http", "https", "ftp", "smtp", "imap", "pop3", "scan"]
Severity = Literal["info", "low", "medium", "high", "critical"]

ATTACK_TYPES: tuple[str, ...] = (
    "SSH Brute Force",
    "Credential Stuffing",
    "Masscan",
    "Nmap",
    "Mirai",
    "Directory Scanning",
    "Web Scanning",
    "SQL Injection",
    "LFI",
    "RFI",
    "Malware Download",
    "Generic Bot Activity",
)

# Column order used by every SELECT that materializes an Event.
EVENT_COLUMNS = (
    "id, timestamp, source_ip, country, city, asn, lat, lon, honeypot, "
    "service, attack_type, username, password, payload, severity, session_id, "
    "event_kind, sha256, size_bytes"
)


class Event(BaseModel):
    """Normalized attack event; mirrors the DuckDB `events` columns in order."""

    id: int | None = None
    timestamp: datetime
    source_ip: str | None = None
    country: str | None = None
    city: str | None = None
    asn: str | None = None
    lat: float | None = None
    lon: float | None = None
    honeypot: Honeypot
    service: str
    attack_type: str
    username: str | None = None
    password: str | None = None
    payload: str | None = None
    severity: str
    session_id: str | None = None
    event_kind: str | None = None
    sha256: str | None = None
    size_bytes: int | None = None


def event_from_row(row: Sequence[object]) -> Event:
    """Build an Event from a row in EVENT_COLUMNS order; timestamps become UTC-aware."""
    values = list(row)
    ts = values[1]
    if isinstance(ts, datetime) and ts.tzinfo is None:
        values[1] = ts.replace(tzinfo=timezone.utc)
    return Event(
        id=values[0],
        timestamp=values[1],
        source_ip=values[2],
        country=values[3],
        city=values[4],
        asn=values[5],
        lat=values[6],
        lon=values[7],
        honeypot=values[8],
        service=values[9],
        attack_type=values[10],
        username=values[11],
        password=values[12],
        payload=values[13],
        severity=values[14],
        session_id=values[15],
        event_kind=values[16],
        sha256=values[17],
        size_bytes=values[18],
    )


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"


class MeResponse(BaseModel):
    username: str


class IngestResponse(BaseModel):
    accepted: int
    rejected: int


class HealthResponse(BaseModel):
    status: str


class ReadinessResponse(BaseModel):
    status: str
    database: str
    geoip: str
    queue_depth: int
    uptime_seconds: int


class Facet(BaseModel):
    name: str
    count: int


class TypeCount(BaseModel):
    attack_type: str
    count: int


class TimeseriesPoint(BaseModel):
    bucket: str
    total: int


class TimeseriesResponse(BaseModel):
    interval: str
    points: list[TimeseriesPoint]
    by_type: list[TypeCount]


class OverviewResponse(BaseModel):
    total_attacks: int
    unique_attackers: int
    countries: int
    credentials_captured: int
    commands_executed: int
    last_24h: int
    ssh_events: int
    ssh_unique_ips: int


class EventListResponse(BaseModel):
    total: int
    items: list[Event]


class SshStatsResponse(BaseModel):
    sessions: int
    brute_force_events: int
    credentials: int
    commands: int
    top_usernames: list[Facet]
    top_passwords: list[Facet]
    top_commands: list[Facet]
    malware_downloads: list[Facet]
    top_sources: list[Facet]
    event_kinds: list[Facet]


class HeatmapResponse(BaseModel):
    """Hour-bucketed cowrie event-kind matrix over the requested window."""

    hours: list[str]
    kinds: list[str]
    matrix: list[list[int]]


class ActorRow(BaseModel):
    ip: str
    country: str | None = None
    city: str | None = None
    playbook: str
    intent: str
    events: int
    probes: int
    last_cmd: str | None = None
    last_seen: str


class ActorsResponse(BaseModel):
    actors: list[ActorRow]
    playbooks: list[Facet]
    intents: list[Facet]
    event_kinds: list[Facet]
    sources: list[Facet]
    geography: list[Facet]


class PayloadStats(BaseModel):
    tracked_urls: int
    saved: int
    fetching_now: int
    bytes_on_disk: int


class PayloadRow(BaseModel):
    time: str
    url: str
    sha256: str | None = None
    size_bytes: int | None = None
    source_ip: str | None = None
    origin: str


class PayloadsResponse(BaseModel):
    stats: PayloadStats
    items: list[PayloadRow]


class WebStatsResponse(BaseModel):
    scanner_events: int
    top_urls: list[Facet]
    top_user_agents: list[Facet]
    exploit_payloads: list[Facet]
    attack_types: list[TypeCount]


class CredentialReusePair(BaseModel):
    username: str
    password: str
    count: int


class CredentialsStatsResponse(BaseModel):
    unique_pairs: int
    by_service: list[Facet]
    top_usernames: list[Facet]
    top_passwords: list[Facet]
    reuse_pairs: list[CredentialReusePair]


class SourceFacet(BaseModel):
    name: str
    country: str | None = None
    count: int


class NetworkStatsResponse(BaseModel):
    total_alerts: int
    signatures: list[Facet]
    protocols: list[Facet]
    top_sources: list[SourceFacet]


class MapPoint(BaseModel):
    lat: float
    lon: float
    weight: int
    country: str | None = None


class MapResponse(BaseModel):
    points: list[MapPoint]
    top_countries: list[Facet]


class IocIp(BaseModel):
    value: str
    country: str | None = None
    asn: str | None = None
    hits: int
    last_seen: str | None = None


class IocHit(BaseModel):
    value: str
    hits: int


class IocResponse(BaseModel):
    ips: list[IocIp]
    urls: list[IocHit]
    domains: list[IocHit]
    hashes: list[IocHit]
