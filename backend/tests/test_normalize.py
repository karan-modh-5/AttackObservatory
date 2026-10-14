"""Normalizer tests: one representative record per source plus malformed inputs."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.normalize import normalize


def ts_of(event: Any) -> datetime:
    return event.timestamp


def test_cowrie_login_failed():
    event = normalize(
        "cowrie",
        {
            "eventid": "cowrie.login.failed",
            "session": "abc123",
            "timestamp": "2026-01-05T10:00:01.000Z",
            "src_ip": "203.0.113.9",
            "username": "root",
            "password": "xc3511",
        },
    )
    assert event is not None
    assert event.honeypot == "cowrie"
    assert event.service == "ssh"
    assert event.username == "root"
    assert event.password == "xc3511"
    assert event.session_id == "abc123"
    assert ts_of(event).tzinfo is not None
    assert ts_of(event).utcoffset() == timezone.utc.utcoffset(None)


def test_cowrie_telnet_service_detection():
    event = normalize(
        "cowrie",
        {
            "eventid": "cowrie.session.connect",
            "session": "t1",
            "timestamp": "2026-01-05T10:00:00Z",
            "src_ip": "203.0.113.9",
        },
    )
    assert event is not None and event.service == "ssh"
    event = normalize(
        "cowrie",
        {
            "eventid": "cowrie.telnet.session.connect",
            "session": "t2",
            "timestamp": "2026-01-05T10:00:00Z",
            "src_ip": "203.0.113.9",
        },
    )
    assert event is not None and event.service == "telnet"


def test_cowrie_command_payload_truncated_to_8kib():
    long_command = "echo " + "A" * 20_000
    event = normalize(
        "cowrie",
        {
            "eventid": "cowrie.command.input",
            "session": "c1",
            "timestamp": "2026-01-05T10:00:02Z",
            "src_ip": "203.0.113.9",
            "input": long_command,
        },
    )
    assert event is not None
    assert event.payload is not None
    assert len(event.payload.encode("utf-8")) <= 8 * 1024


def test_cowrie_unknown_eventid_is_rejected():
    assert normalize("cowrie", {"eventid": "cowrie.crypto.verify", "timestamp": "2026-01-05T10:00:00Z"}) is None
    assert normalize("cowrie", {"log": "not a json record"}) is None


def test_heralding_csv_line():
    line = (
        "2026-01-05 10:05:00.123456,ad45d3c3-16ef-4d15-9425-525ce24c8b25,"
        "3571b54e-062d-4dd8-a050-a966e965b800,198.51.100.7,4444,10.0.0.5,21,ftp,bob,secret123,"
    )
    event = normalize("heralding", {"log": line})
    assert event is not None
    assert event.honeypot == "heralding"
    assert event.service == "ftp"
    assert event.source_ip == "198.51.100.7"
    assert event.username == "bob"
    assert event.password == "secret123"
    assert event.session_id == "3571b54e-062d-4dd8-a050-a966e965b800"
    assert ts_of(event).tzinfo is not None
    assert (ts_of(event).hour, ts_of(event).minute) == (10, 5)


def test_heralding_header_record_skipped():
    header = (
        "timestamp,auth_id,session_id,source_ip,source_port,destination_ip,"
        "destination_port,protocol,username,password,password_hash"
    )
    assert normalize("heralding", {"log": header}) is None
    assert normalize("heralding", {"log": ""}) is None


def test_heralding_quoted_commas():
    line = (
        "2026-01-05 10:05:01,auth2,sess2,198.51.100.7,4445,10.0.0.5,21,ftp,"
        '"weird,user",p@ss,'
    )
    event = normalize("heralding", {"log": line})
    assert event is not None
    assert event.username == "weird,user"
    assert event.password == "p@ss"


def test_heralding_unknown_protocol_rejected():
    line = "2026-01-05 10:05:02,auth3,sess3,198.51.100.7,4446,10.0.0.5,9999,gopher,root,toor,"
    assert normalize("heralding", {"log": line}) is None


def test_snare_access_log_line():
    line = (
        '203.0.113.20 - - [05/Jan/2026:10:06:00 +0000] "GET /wp-login.php HTTP/1.1" '
        '404 512 "-" "sqlmap/1.7.2"'
    )
    event = normalize("snare", {"log": line})
    assert event is not None
    assert event.honeypot == "snare"
    assert event.service == "http"
    assert event.source_ip == "203.0.113.20"
    assert event.payload == 'GET /wp-login.php 404 "sqlmap/1.7.2"'
    assert ts_of(event).year == 2026 and ts_of(event).month == 1 and ts_of(event).day == 5


def test_snare_prefixed_access_log_line():
    """Real snare stdout prefixes access lines with a python-logging header."""
    line = (
        "2026-10-08 20:51:21 INFO:aiohttp.access:log: 203.0.113.20 "
        '[08/Oct/2026:20:51:21 +0000] "GET /wp-login.php HTTP/1.1" 404 512 "-" "sqlmap/1.8"'
    )
    event = normalize("snare", {"log": line})
    assert event is not None
    assert event.source_ip == "203.0.113.20"
    assert event.payload == 'GET /wp-login.php 404 "sqlmap/1.8"'
    assert (event.timestamp.month, event.timestamp.day) == (10, 8)


def test_snare_json_record():
    event = normalize(
        "snare",
        {
            "src_ip": "203.0.113.20",
            "timestamp": "2026-01-05T10:06:30Z",
            "method": "POST",
            "path": "/login",
            "status": 200,
            "user_agent": "Mozilla/5.0",
        },
    )
    assert event is not None
    assert event.payload == 'POST /login 200 "Mozilla/5.0"'


def test_snare_malformed_line_is_none():
    assert normalize("snare", {"log": "<<<definitely not a log line>>>"}) is None
    assert normalize("snare", {"log": ""}) is None


def test_tanner_detection_line():
    line = (
        '203.0.113.7 - - [05/Jan/2026:10:07:00 +0000] "GET /news.php?id=1 HTTP/1.1" 200 512 '
        'detection=sqli "tanner"'
    )
    event = normalize("tanner", {"log": line})
    assert event is not None
    assert event.honeypot == "tanner"
    assert event.service == "http"
    assert event.payload == "sqli /news.php?id=1"
    assert event.source_ip == "203.0.113.7"


def test_tanner_json_record():
    event = normalize(
        "tanner",
        {"det_id": "lfi", "path": "/../../etc/passwd", "src_ip": "203.0.113.7", "timestamp": "2026-01-05T10:07:30Z"},
    )
    assert event is not None
    assert event.payload == "lfi /../../etc/passwd"


def test_tanner_garbage_is_none():
    assert normalize("tanner", {"log": "total garbage without detection or path"}) is None


def test_suricata_alert():
    event = normalize(
        "suricata",
        {
            "timestamp": "2026-01-05T10:08:00.123456+0000",
            "event_type": "alert",
            "src_ip": "198.51.100.30",
            "flow_id": 99123,
            "alert": {"signature": "ET SCAN Nmap OS Detection Probe", "severity_id": 2},
        },
    )
    assert event is not None
    assert event.honeypot == "suricata"
    assert event.service == "scan"
    assert event.payload == "ET SCAN Nmap OS Detection Probe"
    assert event.session_id == "99123"


def test_suricata_non_alert_is_none():
    assert normalize(
        "suricata",
        {"timestamp": "2026-01-05T10:08:01+0000", "event_type": "flow", "src_ip": "198.51.100.30"},
    ) is None
    assert normalize("suricata", {"event_type": "alert"}) is None


def test_normalize_never_raises_and_falls_back_to_now():
    assert normalize("unknown", {"anything": 1}) is None
    assert normalize("cowrie", "not-a-dict") is None
    # missing timestamp falls back to receive time (tz-aware UTC)
    event = normalize(
        "cowrie",
        {"eventid": "cowrie.session.closed", "session": "z", "src_ip": "203.0.113.9"},
    )
    assert event is not None
    assert event.timestamp.tzinfo is not None


def test_cowrie_client_version():
    event = normalize(
        "cowrie",
        {
            "eventid": "cowrie.client.version",
            "session": "cv1",
            "timestamp": "2026-01-05T10:00:00Z",
            "src_ip": "203.0.113.7",
            "version": ["SSH-2.0-Go"],
        },
    )
    assert event is not None
    assert event.event_kind == "client_version"
    assert event.payload == "SSH-2.0-Go"
    assert event.service == "ssh"
    assert event.session_id == "cv1"


def test_cowrie_file_upload():
    event = normalize(
        "cowrie",
        {
            "eventid": "cowrie.session.file_upload",
            "session": "fu1",
            "timestamp": "2026-01-05T10:00:00Z",
            "src_ip": "203.0.113.7",
            "outfile": "/tmp/x86",
        },
    )
    assert event is not None
    assert event.event_kind == "file_upload"
    assert event.payload == "/tmp/x86"
    tty_event = normalize(
        "cowrie",
        {
            "eventid": "cowrie.session.file_upload",
            "session": "fu2",
            "timestamp": "2026-01-05T10:00:01Z",
            "src_ip": "203.0.113.7",
        },
    )
    assert tty_event is not None and tty_event.payload == "tty upload"


def test_cowrie_file_download_sha_and_size():
    event = normalize(
        "cowrie",
        {
            "eventid": "cowrie.session.file_download",
            "session": "fd1",
            "timestamp": "2026-01-05T10:00:00Z",
            "src_ip": "203.0.113.7",
            "url": "http://evil.example.com/x86",
            "shasum": "sha256:" + "ab" * 32,
            "filesize": "4096",
        },
    )
    assert event is not None
    assert event.event_kind == "file_download"
    assert event.sha256 == "ab" * 32
    assert event.size_bytes == 4096
    unprefixed = normalize(
        "cowrie",
        {
            "eventid": "cowrie.session.file_download",
            "session": "fd2",
            "timestamp": "2026-01-05T10:00:01Z",
            "src_ip": "203.0.113.7",
            "url": "http://evil.example.com/x86",
            "shasum": "cd" * 32,
        },
    )
    assert unprefixed is not None and unprefixed.sha256 == "cd" * 32


def test_cowrie_session_user_inheritance():
    failed = normalize(
        "cowrie",
        {
            "eventid": "cowrie.login.failed",
            "session": "su1",
            "timestamp": "2026-01-05T10:00:00Z",
            "src_ip": "203.0.113.7",
            "username": "root",
            "password": "xc3511",
        },
    )
    assert failed is not None and failed.event_kind == "failed_password"
    command = normalize(
        "cowrie",
        {
            "eventid": "cowrie.command.input",
            "session": "su1",
            "timestamp": "2026-01-05T10:00:05Z",
            "src_ip": "203.0.113.7",
            "input": "uname -a",
        },
    )
    assert command is not None
    assert command.username == "root"
    assert command.event_kind == "command"
    download = normalize(
        "cowrie",
        {
            "eventid": "cowrie.session.file_download",
            "session": "su1",
            "timestamp": "2026-01-05T10:00:06Z",
            "src_ip": "203.0.113.7",
            "url": "http://evil.example.com/x86",
        },
    )
    assert download is not None and download.username == "root"
    upload = normalize(
        "cowrie",
        {
            "eventid": "cowrie.session.file_upload",
            "session": "su1",
            "timestamp": "2026-01-05T10:00:07Z",
            "src_ip": "203.0.113.7",
        },
    )
    assert upload is not None and upload.username == "root"
    unknown_session = normalize(
        "cowrie",
        {
            "eventid": "cowrie.command.input",
            "session": "su-unknown",
            "timestamp": "2026-01-05T10:00:08Z",
            "src_ip": "203.0.113.7",
            "input": "id",
        },
    )
    assert unknown_session is not None and unknown_session.username is None


def test_cowrie_event_kinds():
    connect = normalize(
        "cowrie",
        {"eventid": "cowrie.session.connect", "session": "k1", "timestamp": "2026-01-05T10:00:00Z", "src_ip": "203.0.113.7"},
    )
    assert connect is not None and connect.event_kind == "connect"
    closed = normalize(
        "cowrie",
        {"eventid": "cowrie.session.closed", "session": "k1", "timestamp": "2026-01-05T10:00:10Z", "src_ip": "203.0.113.7"},
    )
    assert closed is not None and closed.event_kind is None
    success = normalize(
        "cowrie",
        {
            "eventid": "cowrie.login.success",
            "session": "k2",
            "timestamp": "2026-01-05T10:00:00Z",
            "src_ip": "203.0.113.7",
            "username": "root",
            "password": "toor",
        },
    )
    assert success is not None and success.event_kind == "accepted"
