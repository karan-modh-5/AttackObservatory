"""IOC extraction from stored events plus CSV/JSON export builders."""

from __future__ import annotations

import csv
import io
import ipaddress
import logging
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

import orjson

from app.db import DuckDBManager

logger = logging.getLogger(__name__)

IOC_LIMIT = 1000
SCAN_ROW_LIMIT = 200_000
FETCH_BATCH = 5_000
TYPES: tuple[str, ...] = ("ip", "url", "domain", "hash")

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
IPV6_RE = re.compile(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s\"'<>\\]+", re.IGNORECASE)
URL_TRAILING_PUNCT = ".,;:!?)]}\"'"
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.IGNORECASE
)
HASH_RE = re.compile(r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", re.IGNORECASE)

# Path/file suffixes that the domain regex picks up but that are not real TLDs.
PSEUDO_TLDS: frozenset[str] = frozenset(
    {"php", "asp", "aspx", "jsp", "cgi", "cfm", "do", "action", "html", "htm",
     "json", "xml", "exe", "bin", "dll", "mips", "arm", "sh4"}
)


def _clean_url(value: str) -> str:
    return value.rstrip(URL_TRAILING_PUNCT)


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def collect_iocs(db: DuckDBManager, days: int) -> dict[str, list[dict[str, Any]]]:
    """Aggregate IOCs over the last `days` days.

    IPs come from source_ip values (geo-enriched) and from payload text
    (private/reserved ranges filtered). URLs, domains and hashes are regex
    extracts from payloads. Results are capped at IOC_LIMIT per type, streamed
    with fetchmany so no unbounded result set is materialized.
    """
    since = datetime.now(timezone.utc) - timedelta(days=days)
    ip_stats: dict[str, dict[str, Any]] = {}
    url_counts: Counter[str] = Counter()
    domain_counts: Counter[str] = Counter()
    hash_counts: Counter[str] = Counter()

    def _record_ip(value: str, country: str | None, asn: str | None, ts: datetime) -> None:
        entry = ip_stats.get(value)
        if entry is None:
            entry = {"hits": 0, "country": None, "asn": None, "last_seen": ts}
            ip_stats[value] = entry
        entry["hits"] += 1
        if country and not entry["country"]:
            entry["country"] = country
        if asn and not entry["asn"]:
            entry["asn"] = asn
        if ts > entry["last_seen"]:
            entry["last_seen"] = ts

    with db.read() as conn:
        cursor = conn.execute(
            "SELECT source_ip, country, asn, timestamp, payload FROM events "
            "WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT ?",
            [since, SCAN_ROW_LIMIT],
        )
        while rows := cursor.fetchmany(FETCH_BATCH):
            for source_ip, country, asn, ts, payload in rows:
                seen_at = ts if isinstance(ts, datetime) else datetime.now(timezone.utc)
                if seen_at.tzinfo is None:
                    seen_at = seen_at.replace(tzinfo=timezone.utc)
                if isinstance(source_ip, str) and _is_public_ip(source_ip):
                    _record_ip(source_ip, country if isinstance(country, str) else None,
                               asn if isinstance(asn, str) else None, seen_at)
                if not isinstance(payload, str) or not payload:
                    continue
                for raw_url in set(URL_RE.findall(payload)):
                    url = _clean_url(raw_url)
                    if url:
                        url_counts[url] += 1
                residue = URL_RE.sub(" ", payload)
                for ip_value in set(IPV4_RE.findall(residue)) | set(IPV6_RE.findall(residue)):
                    if _is_public_ip(ip_value):
                        _record_ip(ip_value, None, None, seen_at)
                for domain in set(DOMAIN_RE.findall(residue)):
                    value = domain.lower()
                    if value.rsplit(".", 1)[-1] in PSEUDO_TLDS:
                        continue
                    domain_counts[value] += 1
                for digest in set(HASH_RE.findall(payload)):
                    hash_counts[digest.lower()] += 1

    ranked_ips = sorted(ip_stats.items(), key=lambda kv: (-kv[1]["hits"], kv[0]))[:IOC_LIMIT]
    ips = [
        {
            "value": value,
            "country": stats["country"],
            "asn": stats["asn"],
            "hits": stats["hits"],
            "last_seen": stats["last_seen"].isoformat(),
        }
        for value, stats in ranked_ips
    ]
    return {
        "ips": ips,
        "urls": [{"value": value, "hits": hits} for value, hits in url_counts.most_common(IOC_LIMIT)],
        "domains": [{"value": value, "hits": hits} for value, hits in domain_counts.most_common(IOC_LIMIT)],
        "hashes": [{"value": value, "hits": hits} for value, hits in hash_counts.most_common(IOC_LIMIT)],
    }


def parse_types(types_param: str) -> list[str]:
    """Parse and validate the comma-separated `types` query parameter."""
    selected = [item.strip().lower() for item in types_param.split(",") if item.strip()]
    if not selected:
        return list(TYPES)
    invalid = [item for item in selected if item not in TYPES]
    if invalid:
        raise ValueError(f"unknown IOC types: {','.join(invalid)}")
    return selected


# Export `types` values (singular) map to collect_iocs result keys (plural).
_TYPE_KEYS: dict[str, str] = {"ip": "ips", "url": "urls", "domain": "domains", "hash": "hashes"}


def export_csv(iocs: dict[str, list[dict[str, Any]]], types: list[str]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["type", "value", "country", "asn", "hits", "last_seen"])
    for ioc_type in types:
        for item in iocs[_TYPE_KEYS[ioc_type]]:
            writer.writerow(
                [
                    ioc_type,
                    item["value"],
                    item.get("country") or "",
                    item.get("asn") or "",
                    item["hits"],
                    item.get("last_seen") or "",
                ]
            )
    return buffer.getvalue()


def export_json(iocs: dict[str, list[dict[str, Any]]], types: list[str]) -> str:
    payload = {_TYPE_KEYS[ioc_type]: iocs[_TYPE_KEYS[ioc_type]] for ioc_type in types}
    return orjson.dumps(payload).decode("utf-8")
