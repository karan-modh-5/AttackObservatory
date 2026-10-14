# Dashboard Page Guide — what every page shows and where its data comes from

This explains each page of the Attack Observatory dashboard
(`http://<YOUR_VPS_IP>:8888`), what its numbers and panels represent, and which
honeypot produced the data. Technical details of the stack live in `agent.md`;
this file is the "what am I looking at" guide.

---

## 1. Where the data comes from (the honeypots)

| Honeypot | Protocol / public port | What it captures |
|---|---|---|
| **Cowrie** | SSH (**22**), Telnet (**23**) | Login attempts (username/password tried), accepted sessions, every command typed, malware files downloaded by attackers |
| **Snare + Tanner** | HTTP (**80**) | Every HTTP request to the fake site, scan paths, form submissions, attack payloads (SQLi / LFI / RFI attempts) |
| **Heralding** | FTP (21), SMTP (25), POP3 (110), IMAP (143) | Credential attempts against fake mail/file services |
| **Suricata** | Network IDS — sees **all** traffic | Attack signatures: port scans, exploits, botnet/C2 chatter, Masscan/Nmap fingerprints (ET/open ruleset, attack classtypes only) |

All of it flows through Fluent Bit into one DuckDB table (`events`), where every
event gets an `attack_type` label and a severity (see §9).

---

## 2. The pages

### `/` — Overview
The landing page. **All honeypots combined.**
- Headline tiles: total events, unique attacker IPs, countries, credentials captured (all-time).
- Attack-type breakdown (pie/bars) from the last 365 days.
- 30-day top source countries and top source IPs.
- Uses: `/stats/overview`, `/stats/timeseries`, `/map/points`, `/network/stats`.

### `/live` — Live Feed
**Yes — this page streams live events from ALL honeypots at once**: SSH and
Telnet sessions, HTTP requests, FTP/SMTP/POP3/IMAP credential attempts, and
Suricata IDS alerts, over a WebSocket. It is *not* limited to SSH or HTTP.
- Backfills the last 50 events on load, then prepends new events as they arrive.
- Each row shows: time ago · source IP · honeypot · severity · the
  `attack_type` label (e.g. "generic bot activity", "ssh brute force").
- If you want SSH-only live traffic, use the `/map` page's feed (see below) or
  the `/ssh` page's timeline.

### `/map` — Attack Map
The visual "world map" page. **All honeypots combined** except one panel:
- **Globe**: one dot per attacking origin (size = event count, last 7 days),
  dotted continents, starfield, and attack arcs flying into the sensor marker
  (`LIVE <your-server-ip>`).
- **SUMMARY**: all-time totals — events (all sources), unique attackers,
  countries, credentials.
- **HONEYPOT**: per-honeypot status (active + last event seen).
- **THREAT LEVEL**: 0–100 gauge (volume / intrusion / diversity / exposure
  sub-scores, last 24h).
- **EVENTS / HOUR**: last 24h request volume sparkline.
- **TOP SOURCE IPS**: IPs flagged by the **Suricata network IDS** (last 7 days)
  — not SSH sources.
- **LIVE FEED** (right panel): SSH/Telnet (**cowrie**) events only — the
  reference-style rows with green IP · username · event kind · executed command
  · actor hash. HTTP traffic does not appear in this panel (it's the SSH-style
  feed), but HTTP is on `/live`, `/web`, and the globe itself.

### `/ssh` — SSH Intel
Everything about **SSH + Telnet attacks (Cowrie)**, styled after
ShardLure's intel page:
- **events (ssh)**: all-time SSH/Telnet event count. *(`unique ips` = distinct
  SSH source IPs all-time; `actors` = top tracked attackers in the window —
  these three are deliberately different numbers.)*
- **Threat level** gauge with volume / intrusion / diversity / weaponization
  sub-scores.
- **Attack geography** (countries), **top credentials** tried, **brute-force
  radar** (per-IP attempt rates), **activity heatmap** by event kind
  (connect / failed_password / command / accepted / client_version, 24h–72h).
- **Event kinds / playbooks / intent**: all-time classification of attacker
  behaviour (see §9).
- **Threat actors** table (IP, country, playbook, intent, events, probes, last
  command) and **recent commands executed** (live keystrokes from attackers).
- **Payload capture**: malware files attackers tried to download (sha256, size).
- **Live attack timeline**: cowrie-only WebSocket feed.
- The 1h / 24h / 7d / 30d chips at the top change the time window.

### `/web` — Web Analytics
**HTTP honeypot (Snare + Tanner)** only: most-requested URLs/paths and top
user agents (scanner fingerprints), windowed. Attack payloads from the web
side get their labels here too (SQL Injection, LFI, RFI, Directory Scanning…).

### `/credentials` — Credential Analytics
All captured **username/password pairs** across **every** honeypot that takes
credentials — Cowrie (SSH/Telnet) *and* Heralding (FTP/SMTP/POP3/IMAP):
top usernames, top passwords, distinct combinations, and per-service counts.

### `/network` — Network Analytics
**Suricata IDS** view only: total alerts, top signatures (what triggered),
protocol breakdown, top source IPs (window selectable).

### `/ioc` — IOC Center
Indicators of Compromise for export/threat intel: malicious source IPs and
malware file hashes (sha256) attackers tried to retrieve, with window selector.

### `/login`
JWT sign-in for the dashboard itself (admin account from the server `.env`).

---

## 3. Quick reference — which page answers which question

| Question | Page |
|---|---|
| "What's attacking me right now, all protocols?" | `/live` |
| "Where in the world are attacks coming from?" | `/map` |
| "What are SSH attackers doing on my fake shell?" | `/ssh` |
| "What are HTTP attackers requesting?" | `/web` |
| "Which username/password combos are being tried?" | `/credentials` |
| "What did the network IDS flag?" | `/network` |
| "Give me IPs/hashes to blocklist" | `/ioc` |

---

## 4. "Generic Bot Activity" — SSH or HTTP?

**Neither one specifically — it appears in both, plus every other honeypot.**
It is the classifier's *fallback label*: when an event matches **no** specific
attack rule, it is labelled `Generic Bot Activity` with severity `info`.

Examples:
- **SSH (cowrie)**: a single failed login that isn't part of a detected
  brute-force burst (≥5 failures / 5 min), a bare connection, or an
  unrecognised client probe.
- **HTTP (snare/tanner)**: plain GET requests or small scans below the
  detection thresholds (≥10 distinct 404 paths / minute, or ≥20 requests /
  minute from one IP).
- **Heralding / Suricata**: credential pings or IDS alerts that don't match a
  named pattern.

So when the old feed showed "generic bot activity" on rows from many
protocols, that was correct behaviour — one label meaning "automated noise we
recorded but couldn't attribute to a named attack technique."

---

## 5. The attack labels (what the classifier detects)

Rules run top-to-bottom; **first match wins**. Anything unmatched →
`Generic Bot Activity`.

| Label | Severity | Fires when | Honeypots |
|---|---|---|---|
| **Mirai** | high | login with a known Mirai botnet credential pair (root/xc3511, root/vizxv, admin/admin…) | cowrie, heralding |
| **Malware Download** | high | attacker makes the fake shell fetch a binary (wget/curl URL, sha256 recorded) | cowrie |
| **SQL Injection** | high | HTTP payload contains injection patterns (`union select`, `' or 1=1`…) — flagged by Tanner | tanner (web) |
| **LFI** | high | path traversal (`../`, `/etc/passwd`) — flagged by Tanner | tanner (web) |
| **RFI** | high | remote file inclusion (http(s) URL injected into parameters) — flagged by Tanner | tanner (web) |
| **Directory Scanning** | low | ≥10 distinct 404 paths within 60s from one IP | snare, tanner |
| **Web Scanning** | low | ≥20 HTTP requests within 60s from one IP | snare, tanner |
| **SSH Brute Force** | medium | ≥5 failed SSH logins within 300s from one IP | cowrie |
| **Credential Stuffing** | medium | same username tried from ≥3 different IPs within 1h | cowrie, heralding |
| **Masscan** | low | ET Masscan signature, or ≥50 distinct ports touched within 60s | suricata |
| **Nmap** | low | ET Nmap fingerprint signature | suricata |
| **Generic Bot Activity** | info | fallback — unspecific automated noise (see §4) | **all** |

Severity drives the colour coding across the dashboard
(high=red, medium=amber, low=dim, info=grey).
