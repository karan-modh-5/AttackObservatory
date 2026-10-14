"""Attack classification engine (contract section 2).

Rules run top to bottom; the first match wins. Burst rules keep bounded
per-key sliding windows (OrderedDict LRU capped at ~10k keys) and are driven
by the event timestamps, so replayed logs do not poison current windows.
"""

from __future__ import annotations

import logging
import re
from collections import OrderedDict, deque
from typing import Any, Callable

from app.models import Event

logger = logging.getLogger(__name__)

MAX_TRACKED_KEYS = 10_000

SEVERITY: dict[str, str] = {
    "Mirai": "high",
    "Malware Download": "high",
    "SQL Injection": "high",
    "LFI": "high",
    "RFI": "high",
    "SSH Brute Force": "medium",
    "Credential Stuffing": "medium",
    "Masscan": "low",
    "Nmap": "low",
    "Directory Scanning": "low",
    "Web Scanning": "low",
    "Generic Bot Activity": "info",
}

MIRAI_CREDENTIALS: frozenset[tuple[str, str]] = frozenset(
    {
        ("root", "xc3511"),
        ("root", "vizxv"),
        ("root", "admin"),
        ("admin", "admin"),
        ("root", "888888"),
        ("root", "xmhdipc"),
        ("root", "default"),
        ("root", "123456"),
        ("root", "54321"),
        ("root", "12345"),
        ("root", "password"),
        ("root", "1234"),
        ("admin", "1234"),
        ("guest", "guest"),
        ("support", "support"),
        ("user", "tluafed"),
        ("root", "tluafed"),
        ("admin", "password"),
    }
)

MIRAI_BIN_RE = re.compile(r"\bmirai|\.mips\b|\.arm\b|\.sh4\b", re.IGNORECASE)
BUSYBOX_RE = re.compile(r"busybox", re.IGNORECASE)
SHELL_PROBE_RE = re.compile(r"\b(?:enable|shell)\b", re.IGNORECASE)

MALWARE_FETCH_RE = re.compile(
    r"\b(?:wget|curl|tftp|scp|ftpget)\b[^\n]*?(?:https?://|\b\d{1,3}(?:\.\d{1,3}){3}\b)",
    re.IGNORECASE,
)
BARE_URL_RE = re.compile(r"^https?://\S+$")
SNARE_BINARY_RE = re.compile(r"\.(?:bin|sh|mips|arm|exe)\b", re.IGNORECASE)

SQLI_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"union\s+select", re.IGNORECASE),
    re.compile(r"'\s*or\s*'?1'?\s*=\s*1", re.IGNORECASE),
    re.compile(r"sleep\(\d", re.IGNORECASE),
    re.compile(r"benchmark\(", re.IGNORECASE),
    re.compile(r"information_schema", re.IGNORECASE),
    # SQL comment terminator: end of payload, or end of the query segment in
    # access-log style payloads ("<query> 200 \"ua\"").
    re.compile(r"--(?:\s*$|\s+\d{3}\s)", re.IGNORECASE),
)

LFI_RE = re.compile(
    r"(?:\.\./){2,}|/etc/(?:passwd|shadow)|windows[/\\]win\.ini|php://(?:filter|input)",
    re.IGNORECASE,
)
RFI_RE = re.compile(
    r"[?&]\w+=(?:https?://|https?%3a%2f%2f)\S*?\.(?:txt|php)(?:[?\s]|$)",
    re.IGNORECASE,
)

SCANNER_UA_RE = re.compile(
    r"nikto|sqlmap|masscan|nmap|dirbuster|gobuster|wpscan|acunetix|nessus|zgrab|censys|paloalto",
    re.IGNORECASE,
)

SURICATA_MASSCAN_RE = re.compile(r"masscan|zmap", re.IGNORECASE)
SURICATA_NMAP_RE = re.compile(r"nmap", re.IGNORECASE)

BREACH_STRINGS: frozenset[str] = frozenset(
    {"admin", "root", "password", "123456", "1234", "test", "guest", "toor",
     "oracle", "postgres", "pi", "raspberry", "ubnt", "user"}
)

# Payload shapes produced by the normalizers.
SNARE_PAYLOAD_RE = re.compile(r'^(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<status>\d{3})\s+"(?P<ua>[^"]*)"$')
TANNER_DETECTION_RE = re.compile(r"\b(?:rfi/include|rfi|sqli|lfi|xss)\b", re.IGNORECASE)


def _snare_parts(payload: str) -> tuple[str, str, str]:
    """Return (path, status, user_agent) for snare-style payloads, else ('', '', '')."""
    match = SNARE_PAYLOAD_RE.match(payload)
    if match is None:
        return "", "", ""
    return match.group("path"), match.group("status"), match.group("ua")


def _tanner_detection(payload: str) -> str:
    match = TANNER_DETECTION_RE.search(payload)
    return match.group(0).lower() if match else ""


class ClassificationEngine:
    """Stateful classifier assigning attack_type + severity to one event at a time."""

    def __init__(
        self,
        *,
        lru_cap: int = MAX_TRACKED_KEYS,
        dirscan_window: float = 60.0,
        dirscan_min_paths: int = 10,
        request_window: float = 60.0,
        request_burst: int = 20,
        brute_window: float = 300.0,
        brute_threshold: int = 5,
        stuffing_window: float = 3600.0,
        stuffing_min_ips: int = 3,
        portscan_window: float = 60.0,
        portscan_min_ports: int = 50,
    ) -> None:
        self._lru_cap = lru_cap
        self._dirscan_window = dirscan_window
        self._dirscan_min_paths = dirscan_min_paths
        self._request_window = request_window
        self._request_burst = request_burst
        self._brute_window = brute_window
        self._brute_threshold = brute_threshold
        self._stuffing_window = stuffing_window
        self._stuffing_min_ips = stuffing_min_ips
        self._portscan_window = portscan_window
        self._portscan_min_ports = portscan_min_ports
        # key -> deque[(timestamp, value)]
        self._paths_404: OrderedDict[str, deque[tuple[float, str]]] = OrderedDict()
        self._requests: OrderedDict[str, deque[tuple[float, int]]] = OrderedDict()
        self._logins: OrderedDict[str, deque[tuple[float, bool]]] = OrderedDict()
        self._username_ips: OrderedDict[str, deque[tuple[float, str]]] = OrderedDict()
        self._ports: OrderedDict[str, deque[tuple[float, int]]] = OrderedDict()

    def classify(self, event: Event, record: dict[str, Any] | None = None) -> Event:
        """Assign attack_type and severity (first matching rule wins); returns the event."""
        raw = record if isinstance(record, dict) else {}
        ts = event.timestamp.timestamp()
        label = self._label(event, raw, ts)
        event.attack_type = label
        event.severity = SEVERITY[label]
        return event

    def _label(self, event: Event, record: dict[str, Any], ts: float) -> str:
        rules: tuple[tuple[str, Callable[[Event, dict[str, Any], float], bool]], ...] = (
            ("Mirai", self._is_mirai),
            ("Malware Download", self._is_malware_download),
            ("SQL Injection", self._is_sql_injection),
            ("LFI", self._is_lfi),
            ("RFI", self._is_rfi),
            ("Directory Scanning", self._is_directory_scanning),
            ("Web Scanning", self._is_web_scanning),
            ("SSH Brute Force", self._is_ssh_brute_force),
            ("Credential Stuffing", self._is_credential_stuffing),
            ("Masscan", self._is_masscan),
            ("Nmap", self._is_nmap),
        )
        for label, rule in rules:
            if rule(event, record, ts):
                return label
        return "Generic Bot Activity"

    # --- rule predicates -------------------------------------------------

    def _is_mirai(self, event: Event, record: dict[str, Any], ts: float) -> bool:
        if event.honeypot in ("cowrie", "heralding") and event.username is not None:
            if (event.username, event.password or "") in MIRAI_CREDENTIALS:
                return True
        payload = event.payload or ""
        if MIRAI_BIN_RE.search(payload):
            return True
        return bool(BUSYBOX_RE.search(payload) and SHELL_PROBE_RE.search(payload))

    def _is_malware_download(self, event: Event, record: dict[str, Any], ts: float) -> bool:
        payload = event.payload or ""
        if not payload:
            return False
        if event.honeypot == "cowrie":
            if MALWARE_FETCH_RE.search(payload):
                return True
            # cowrie.session.file_download normalizes to a bare URL payload.
            return bool(BARE_URL_RE.match(payload))
        if event.honeypot == "snare":
            return bool(SNARE_BINARY_RE.search(payload))
        return False

    def _is_sql_injection(self, event: Event, record: dict[str, Any], ts: float) -> bool:
        payload = event.payload or ""
        if event.honeypot == "tanner" and _tanner_detection(payload) == "sqli":
            return True
        return any(rx.search(payload) for rx in SQLI_RES)

    def _is_lfi(self, event: Event, record: dict[str, Any], ts: float) -> bool:
        payload = event.payload or ""
        if event.honeypot == "tanner" and _tanner_detection(payload) == "lfi":
            return True
        return bool(LFI_RE.search(payload))

    def _is_rfi(self, event: Event, record: dict[str, Any], ts: float) -> bool:
        payload = event.payload or ""
        if event.honeypot == "tanner" and _tanner_detection(payload) in ("rfi", "rfi/include"):
            return True
        return bool(RFI_RE.search(payload))

    def _is_directory_scanning(self, event: Event, record: dict[str, Any], ts: float) -> bool:
        if event.honeypot not in ("snare", "tanner"):
            return False
        payload = event.payload or ""
        path, status, _ua = _snare_parts(payload)
        if not path:
            return False
        window = self._window(self._paths_404, event.source_ip or "-")
        self._prune(window, ts, self._dirscan_window)
        if status == "404":
            window.append((ts, path))
            distinct = {p for _t, p in window}
            return len(distinct) >= self._dirscan_min_paths
        return False

    def _is_web_scanning(self, event: Event, record: dict[str, Any], ts: float) -> bool:
        if event.honeypot not in ("snare", "tanner"):
            return False
        payload = event.payload or ""
        _path, _status, user_agent = _snare_parts(payload)
        window = self._window(self._requests, event.source_ip or "-")
        self._prune(window, ts, self._request_window)
        window.append((ts, 0))
        if user_agent and SCANNER_UA_RE.search(user_agent):
            return True
        return len(window) >= self._request_burst

    def _is_ssh_brute_force(self, event: Event, record: dict[str, Any], ts: float) -> bool:
        if event.honeypot not in ("cowrie", "heralding") or event.username is None:
            return False
        success = record.get("eventid") == "cowrie.login.success"
        window = self._window(self._logins, event.source_ip or "-")
        self._prune(window, ts, self._brute_window)
        window.append((ts, success))
        failures = sum(1 for _t, ok in window if not ok)
        if failures >= self._brute_threshold:
            return True
        # any successful login after failures in the window
        return success and failures > 0

    def _is_credential_stuffing(self, event: Event, record: dict[str, Any], ts: float) -> bool:
        if event.honeypot != "heralding" or event.username is None:
            return False
        if event.username == (event.password or "") and event.username in BREACH_STRINGS:
            return True
        window = self._window(self._username_ips, event.username)
        self._prune(window, ts, self._stuffing_window)
        window.append((ts, event.source_ip or "-"))
        distinct_ips = {ip for _t, ip in window}
        return len(distinct_ips) >= self._stuffing_min_ips

    def _is_masscan(self, event: Event, record: dict[str, Any], ts: float) -> bool:
        payload = event.payload or ""
        if event.honeypot == "suricata" and SURICATA_MASSCAN_RE.search(payload):
            return True
        raw_port = record.get("dest_port")
        if raw_port is None:
            return False
        try:
            port = int(raw_port)
        except (TypeError, ValueError):
            return False
        window = self._window(self._ports, event.source_ip or "-")
        self._prune(window, ts, self._portscan_window)
        window.append((ts, port))
        return len({p for _t, p in window}) >= self._portscan_min_ports

    def _is_nmap(self, event: Event, record: dict[str, Any], ts: float) -> bool:
        return event.honeypot == "suricata" and bool(SURICATA_NMAP_RE.search(event.payload or ""))

    # --- bounded window bookkeeping --------------------------------------

    def _window(self, store: OrderedDict[str, deque[tuple[float, Any]]], key: str) -> deque[tuple[float, Any]]:
        window = store.get(key)
        if window is None:
            window = deque()
            store[key] = window
            if len(store) > self._lru_cap:
                store.popitem(last=False)
        else:
            store.move_to_end(key)
        return window

    @staticmethod
    def _prune(window: deque[tuple[float, Any]], ts: float, span: float) -> None:
        horizon = ts - span
        while window and window[0][0] < horizon:
            window.popleft()
