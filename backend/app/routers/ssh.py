"""SSH honeypot statistics + actor intelligence: /ssh/stats, /ssh/heatmap, /ssh/actors, /ssh/payloads."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Query, Request, Response
from app.actors import ActorFeatures, classify_actor
from app.deps import DbDep
from app.models import (
    ActorRow,
    ActorsResponse,
    Facet,
    HeatmapResponse,
    PayloadRow,
    PayloadStats,
    PayloadsResponse,
    SshStatsResponse,
)
from app.ratelimit import READ_LIMIT, limiter, resolve_annotations

router = APIRouter(tags=["ssh"])

_FACET_LIMIT = 20


@router.get("/ssh/stats", response_model=SshStatsResponse)
@limiter.limit(READ_LIMIT)
@resolve_annotations
async def ssh_stats(request: Request, response: Response, db: DbDep, days: int = Query(default=30, ge=1, le=365)) -> SshStatsResponse:
    window = f"timestamp >= now() - interval '{int(days)} days'"

    sessions = int(
        (await db.fetch_all_async(
            f"SELECT COUNT(DISTINCT session_id) FROM events WHERE honeypot = 'cowrie' "
            f"AND session_id IS NOT NULL AND {window}"
        ))[0][0]
    )
    brute_force_events = int(
        (await db.fetch_all_async(
            f"SELECT COUNT(*) FROM events WHERE attack_type = 'SSH Brute Force' AND {window}"
        ))[0][0]
    )
    credentials = int(
        (await db.fetch_all_async(
            f"SELECT COUNT(*) FROM events WHERE honeypot = 'cowrie' AND username IS NOT NULL "
            f"AND {window}"
        ))[0][0]
    )
    commands = int(
        (await db.fetch_all_async(
            f"SELECT COUNT(*) FROM events WHERE honeypot = 'cowrie' "
            f"AND payload IS NOT NULL AND payload NOT LIKE 'http://%' AND payload NOT LIKE 'https://%' "
            f"AND {window}"
        ))[0][0]
    )

    async def facet(sql: str) -> list[Facet]:
        return [Facet(name=str(name), count=int(count)) for name, count in await db.fetch_all_async(sql)]

    top_usernames = await facet(
        f"SELECT username AS name, COUNT(*) AS count FROM events WHERE username IS NOT NULL "
        f"AND honeypot IN ('cowrie', 'heralding') AND {window} "
        f"GROUP BY username ORDER BY count DESC, name LIMIT {_FACET_LIMIT}"
    )
    top_passwords = await facet(
        f"SELECT password AS name, COUNT(*) AS count FROM events WHERE password IS NOT NULL "
        f"AND honeypot IN ('cowrie', 'heralding') AND {window} "
        f"GROUP BY password ORDER BY count DESC, name LIMIT {_FACET_LIMIT}"
    )
    top_commands = await facet(
        f"SELECT payload AS name, COUNT(*) AS count FROM events WHERE honeypot = 'cowrie' "
        f"AND payload IS NOT NULL AND payload NOT LIKE 'http://%' AND payload NOT LIKE 'https://%' "
        f"AND {window} GROUP BY payload ORDER BY count DESC, name LIMIT {_FACET_LIMIT}"
    )
    malware_downloads = await facet(
        f"SELECT payload AS name, COUNT(*) AS count FROM events WHERE attack_type = 'Malware Download' "
        f"AND payload IS NOT NULL AND {window} "
        f"GROUP BY payload ORDER BY count DESC, name LIMIT {_FACET_LIMIT}"
    )
    top_sources = await facet(
        f"SELECT source_ip AS name, COUNT(*) AS count FROM events "
        f"WHERE source_ip IS NOT NULL AND honeypot = 'cowrie' AND {window} "
        f"GROUP BY source_ip ORDER BY count DESC, name LIMIT {_FACET_LIMIT}"
    )
    event_kinds = await facet(
        "SELECT event_kind AS name, COUNT(*) AS count FROM events "
        "WHERE honeypot = 'cowrie' AND event_kind IS NOT NULL "
        "GROUP BY event_kind ORDER BY count DESC, name"
    )
    return SshStatsResponse(
        sessions=sessions,
        brute_force_events=brute_force_events,
        credentials=credentials,
        commands=commands,
        top_usernames=top_usernames,
        top_passwords=top_passwords,
        top_commands=top_commands,
        malware_downloads=malware_downloads,
        top_sources=top_sources,
        event_kinds=event_kinds,
    )


ACTOR_WINDOW_SQL = """
SELECT
    source_ip,
    COUNT(*)                                                    AS events,
    COUNT(*) FILTER (WHERE event_kind = 'connect')              AS probes,
    COUNT(DISTINCT username)                                    AS usernames,
    COUNT(DISTINCT password)                                    AS passwords,
    COUNT(*) FILTER (WHERE event_kind = 'command')              AS commands,
    COUNT(*) FILTER (WHERE event_kind = 'accepted')             AS accepted,
    COUNT(*) FILTER (WHERE event_kind = 'command'
                      AND (lower(payload) LIKE '%xmrig%'
                           OR lower(payload) LIKE '%miner%'
                           OR lower(payload) LIKE '%crypto%'
                           OR lower(payload) LIKE '%pool.%'
                           OR lower(payload) LIKE '%stratum%')) AS crypto_cmds,
    arg_max(payload, timestamp) FILTER (WHERE event_kind = 'command') AS last_cmd,
    arg_min(country, timestamp) FILTER (WHERE country IS NOT NULL)    AS country,
    arg_min(city, timestamp) FILTER (WHERE city IS NOT NULL)          AS city,
    MAX(timestamp)                                              AS last_seen,
    epoch(MAX(timestamp) - MIN(timestamp)) / 3600.0             AS span_hours
FROM events
WHERE honeypot = 'cowrie' AND source_ip IS NOT NULL AND {window}
GROUP BY source_ip
ORDER BY events DESC
LIMIT 50
"""

ACTOR_ALLTIME_SQL = """
SELECT
    source_ip,
    COUNT(*)                                                    AS events,
    COUNT(*) FILTER (WHERE event_kind = 'connect')              AS probes,
    COUNT(DISTINCT username)                                    AS usernames,
    COUNT(DISTINCT password)                                    AS passwords,
    COUNT(*) FILTER (WHERE event_kind = 'command')              AS commands,
    COUNT(*) FILTER (WHERE event_kind = 'accepted')             AS accepted,
    COUNT(*) FILTER (WHERE event_kind = 'command'
                      AND (lower(payload) LIKE '%xmrig%'
                           OR lower(payload) LIKE '%miner%'
                           OR lower(payload) LIKE '%crypto%'
                           OR lower(payload) LIKE '%pool.%'
                           OR lower(payload) LIKE '%stratum%')) AS crypto_cmds,
    epoch(MAX(timestamp) - MIN(timestamp)) / 3600.0             AS span_hours
FROM events
WHERE honeypot = 'cowrie' AND source_ip IS NOT NULL
GROUP BY source_ip
"""


def _features(row: tuple) -> ActorFeatures:
    (events, probes, usernames, passwords, commands, accepted, crypto_cmds, span_hours) = row
    return ActorFeatures(
        events=int(events),
        probes=int(probes),
        distinct_usernames=int(usernames),
        distinct_passwords=int(passwords),
        commands=int(commands),
        has_success=int(accepted) > 0,
        has_crypto=int(crypto_cmds) > 0,
        events_per_hour=int(events) / max(1.0, float(span_hours or 0.0)),
        span_hours=float(span_hours or 0.0),
    )


@router.get("/ssh/heatmap", response_model=HeatmapResponse)
@limiter.limit(READ_LIMIT)
@resolve_annotations
async def ssh_heatmap(request: Request, response: Response, db: DbDep, hours: int = Query(default=72, ge=6, le=168)) -> HeatmapResponse:
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    start = now - timedelta(hours=hours - 1)
    hour_labels = [(start + timedelta(hours=offset)).isoformat() for offset in range(hours)]
    index = {label: i for i, label in enumerate(hour_labels)}

    rows = await db.fetch_all_async(
        "SELECT event_kind, date_trunc('hour', timestamp) AS bucket, COUNT(*) "
        "FROM events WHERE honeypot = 'cowrie' AND event_kind IS NOT NULL "
        "AND timestamp >= ? AND timestamp < ? "
        "GROUP BY event_kind, bucket",
        [start, now + timedelta(hours=1)],
    )
    totals: dict[str, int] = {}
    cells: dict[tuple[str, int], int] = {}
    for kind, bucket, count in rows:
        label = (bucket if isinstance(bucket, datetime) else datetime.fromisoformat(str(bucket)))
        if label.tzinfo is None:
            label = label.replace(tzinfo=timezone.utc)
        key = label.isoformat()
        if key not in index:
            continue
        name = str(kind)
        totals[name] = totals.get(name, 0) + int(count)
        cells[(name, index[key])] = int(count)

    kinds = sorted(totals, key=lambda name: (-totals[name], name))
    matrix = [[cells.get((kind, i), 0) for i in range(hours)] for kind in kinds]
    return HeatmapResponse(hours=hour_labels, kinds=kinds, matrix=matrix)


@router.get("/ssh/actors", response_model=ActorsResponse)
@limiter.limit(READ_LIMIT)
@resolve_annotations
async def ssh_actors(request: Request, response: Response, db: DbDep, days: int = Query(default=30, ge=1, le=365)) -> ActorsResponse:
    window = f"timestamp >= now() - interval '{int(days)} days'"

    window_rows = await db.fetch_all_async(ACTOR_WINDOW_SQL.format(window=window))
    alltime_rows = await db.fetch_all_async(ACTOR_ALLTIME_SQL)

    actor_playbooks: dict[str, int] = {}
    actor_intents: dict[str, int] = {}
    for row in alltime_rows:
        source_ip = str(row[0])
        playbook, intent = classify_actor(_features(row[1:]))
        actor_playbooks[playbook] = actor_playbooks.get(playbook, 0) + 1
        actor_intents[intent] = actor_intents.get(intent, 0) + 1

    actors: list[ActorRow] = []
    for row in window_rows:
        source_ip = str(row[0])
        last_cmd = row[8]
        country = row[9]
        city = row[10]
        last_seen = row[11]
        playbook, intent = classify_actor(_features(row[1:8] + (row[12],)))
        actors.append(
            ActorRow(
                ip=source_ip,
                country=str(country) if country is not None else None,
                city=str(city) if city is not None else None,
                playbook=playbook,
                intent=intent,
                events=int(row[1]),
                probes=int(row[2]),
                last_cmd=str(last_cmd) if last_cmd is not None else None,
                last_seen=str(last_seen),
            )
        )

    def facet(rows: list[tuple]) -> list[Facet]:
        return [Facet(name=str(name), count=int(count)) for name, count in rows]

    event_kinds = facet(
        await db.fetch_all_async(
            "SELECT event_kind AS name, COUNT(*) AS count FROM events "
            "WHERE honeypot = 'cowrie' AND event_kind IS NOT NULL "
            "GROUP BY event_kind ORDER BY count DESC, name"
        )
    )
    sources = facet(
        await db.fetch_all_async("SELECT honeypot AS name, COUNT(*) AS count FROM events GROUP BY honeypot ORDER BY count DESC, name")
    )
    geography = facet(
        await db.fetch_all_async(
            f"SELECT country AS name, COUNT(*) AS count FROM events "
            f"WHERE honeypot = 'cowrie' AND country IS NOT NULL AND {window} "
            f"GROUP BY country ORDER BY count DESC, name LIMIT 10"
        )
    )
    return ActorsResponse(
        actors=actors,
        playbooks=[Facet(name=name, count=count) for name, count in sorted(actor_playbooks.items(), key=lambda kv: (-kv[1], kv[0]))],
        intents=[Facet(name=name, count=count) for name, count in sorted(actor_intents.items(), key=lambda kv: (-kv[1], kv[0]))],
        event_kinds=event_kinds,
        sources=sources,
        geography=geography,
    )


@router.get("/ssh/payloads", response_model=PayloadsResponse)
@limiter.limit(READ_LIMIT)
@resolve_annotations
async def ssh_payloads(request: Request, response: Response, db: DbDep, limit: int = Query(default=100, ge=1, le=500)) -> PayloadsResponse:
    rows = await db.fetch_all_async(
        "SELECT timestamp, payload, sha256, size_bytes, source_ip "
        "FROM events WHERE honeypot = 'cowrie' AND event_kind = 'file_download' "
        "ORDER BY timestamp DESC LIMIT ?",
        [limit],
    )
    items = [
        PayloadRow(
            time=str(timestamp),
            url=str(payload),
            sha256=str(sha) if sha is not None else None,
            size_bytes=int(size) if size is not None else None,
            source_ip=str(ip) if ip is not None else None,
            origin="cowrie file_download",
        )
        for timestamp, payload, sha, size, ip in rows
    ]
    tracked, saved, bytes_on_disk = (await db.fetch_all_async(
        "SELECT COUNT(DISTINCT payload), COUNT(*), COALESCE(SUM(size_bytes), 0) "
        "FROM events WHERE honeypot = 'cowrie' AND event_kind = 'file_download'"
    ))[0]
    return PayloadsResponse(
        stats=PayloadStats(
            tracked_urls=int(tracked),
            saved=int(saved),
            fetching_now=0,
            bytes_on_disk=int(bytes_on_disk),
        ),
        items=items,
    )
