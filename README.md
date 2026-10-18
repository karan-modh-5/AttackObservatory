# Attack Observatory

A low-resource, multi-sensor honeypot observatory: **6 honeypots → 1 normalization pipeline → one DuckDB → a unified React dashboard**, designed to run on a **512 MB RAM / 1 vCPU / 10 GB VPS**.

```
Internet ──► Cowrie (22/tcp, 23/tcp)        ──► /var/log/honeypot/cowrie/cowrie.json
        ──► Snare  (80/tcp)                 ──► /var/log/honeypot/snare/snare.log
        ──► Tanner (internal :8090)         ──► /var/log/honeypot/tanner/tanner_report.json
        ──► Heralding (21,25,110,143/tcp)   ──► /var/log/honeypot/heralding/heralding_auth.csv
        ──► Suricata (passive IDS, host ns) ──► /var/log/honeypot/suricata/eve.json
                                                          │
                    Fluent Bit (tails all files)          │
                                                          ▼
                              POST /api/v1/ingest/{source}   (X-API-Key)
                                                          │
                                          FastAPI: normalize → enrich (GeoIP)
                                          → classify → batch insert
                                                          ▼
                                                     DuckDB (single file)
                                                          │
                     REST + WebSocket ◄───────────────────┘
                                                          │
                                     Nginx :8888 (static React SPA, /api → api:8000)
```

---

## The Problem This Project Solves

Traditional honeypot deployments present several operational obstacles for researchers and security teams:

1. **Fragmented, Siloed Threat Data**: Deploying individual honeypots (Cowrie for SSH, Snare for HTTP, Heralding for FTP/mail) produces disparate logs in incompatible formats (JSON lines, CSVs, syslog, Suricata EVE). Correlating whether an attacker scanning web endpoints on port 80 is the same IP brute-forcing SSH on port 22 requires complex, manual correlation.
2. **Resource-Heavy SIEM Stacks**: Enterprise aggregation platforms (Elasticsearch/ELK, Splunk, Graylog, Wazuh) easily demand 4–8 GB of RAM and multi-core CPUs. Hobbyists, researchers, and small organizations cannot run them on budget VPS instances ($5–$6/month).
3. **Lack of In-Stream Attack Classification**: Raw honeypot logs only record events—not attack intent. A series of rapid connections requires sliding-window evaluation to identify whether activity constitutes `Masscan`, `Mirai`, `Credential Stuffing`, `Directory Scanning`, or `SQL Injection`.

**Attack Observatory solves this** by collecting heterogenous honeypot logs via Fluent Bit, normalizing them through a stateless FastAPI engine, enriching with GeoIP/ASN data, classifying them with sliding-window rule heuristics into 12 distinct attack types, and writing them into an embedded columnar DuckDB database. The entire 8-container stack runs smoothly under 512 MB – 1 GB of RAM with a real-time reactive dark-cyber UI.

---

## Honeypot Sensors & Their Roles

| Honeypot | Ports / Protocols | Role & Purpose |
| :--- | :--- | :--- |
| **Cowrie** | `22/tcp` (SSH), `23/tcp` (Telnet) | **Medium-interaction SSH/Telnet honeypot**. Traps brute-force login attempts, records attacker usernames and passwords, logs interactive terminal sessions and commands executed (`uname -a`, `wget`, `chmod`), and captures uploaded/downloaded malware binaries. |
| **Snare** | `80/tcp` (HTTP) | **Web application honeypot**. Emulates a corporate web portal. It captures incoming HTTP requests (GET, POST), URLs, query strings, headers, and user-agents, acting as the sensor facing the Internet. |
| **Tanner** | Internal `:8090` | **Web attack evaluation engine (the "brain" of Snare)**. Snare forwards every incoming HTTP transaction to Tanner. Tanner runs built-in emulators (SQLi, LFI, RFI, XSS, CMD exec) to determine whether the request was an active exploit attempt and issues verdicts (`sqli`, `lfi`, `rfi`). |
| **Heralding** | `21` (FTP), `25` (SMTP), `110` (POP3), `143` (IMAP) | **Authentication credentials harvester**. Catches bots and threat actors attempting credential stuffing across common legacy internet protocols without providing an actual open service backend. |
| **Suricata** | Host network (Passive IDS) | **High-performance Network Threat Detection Engine**. Sniffs raw packets passing through the host interface to detect port scanning (`Nmap`, `Masscan`), TCP SYN floods, abnormal flags, and network probes targeting ports where no honeypot is listening. |

---

## Dashboard Pages & Data Guide

The frontend dashboard (accessible at `http://<your-vps>:8888/`) provides 8 specialized analytical pages:

### 1. `/` — Overview
- **Metrics**: Total events (24h), unique attacker IPs, active honeypots, and critical-severity alerts.
- **Top Attack Vectors**: Breakdown of events grouped by classification (`SSH Brute Force`, `Web Scanning`, etc.).
- **Top Attacker Countries**: Geo-distributed origin of attacks based on IP location lookups.
- **Recent High-Severity Events**: Real-time table of critical alerts (e.g., successful fake logins, malware uploads).

### 2. `/live` — Live Event Feed
- **WebSocket Streaming Console**: Streams events in sub-second real time directly from the ingest pipeline.
- **Row Anatomy**: Displays relative timestamp, green attacker IP, yellow username/credentials (if any), white attack classification tag, and green payload snippet (e.g. bash commands executed or HTTP URI paths).
- *Troubleshooting Note*: If the Live Feed freezes or shows data from hours ago, it indicates the database disk buffer was full and the pipeline paused ingestion (see Storage Troubleshooting below).

### 3. `/ssh` — SSH & Telnet Analytics (Cowrie)
- **Top Credentials**: Most frequently attempted username + password pairs (e.g., `root:root`, `admin:123456`).
- **Attacked Usernames**: Distribution of targeted user accounts.
- **Session Durations**: How long attackers stayed connected inside the simulated Cowrie terminal shell.
- **Executed Commands**: Raw terminal commands run by attackers during Cowrie shell sessions.

### 4. `/web` — Web Attack Analytics (Snare + Tanner)
- **Scanner Events**: Count of reconnaissance requests identified as automated directory busting or vulnerability scanners.
- **Top URLs / Paths**: The most targeted paths on the simulated web server (e.g. `/wp-login.php`, `/.env`, `/phpmyadmin`).
- **Top User-Agents**: Headers identifying attacker tools (`sqlmap`, `nikto`, `curl`, `python-requests`, standard browsers).
- **Exploit Payloads**: **Displays payloads specifically identified as active web exploits (`SQL Injection`, `LFI`, `RFI`)**.
  - *Why doesn't typing `' OR 1=1` into the login form show up as SQL Injection?*
    1. **Log pipeline routing**: Tanner produces verdicts in `tanner_report.json` via its internal evaluation engine. Once ingested and classified, Tanner detections appear with their path and payload (e.g., `sqli /index.php?id=...`).
    2. **GET query parameters vs. POST bodies**: Tanner's default SQLi emulator is optimized to evaluate URL query parameters (e.g. `GET /index.php?id=1%20UNION%20SELECT...` or `?id=' OR 1=1--`). Standard HTML form submissions send POST request bodies which Snare records as HTTP events, but Tanner's emulator only flags as SQLi when matching its specific parser rules.

### 5. `/credentials` — Credential Intelligence
- Aggregates all credentials harvested across all honeypots: Cowrie (SSH/Telnet), Heralding (FTP, SMTP, POP3, IMAP), and Snare login submissions.
- Searchable by username, password, protocol, and originating IP.

### 6. `/network` — Network & Port Scan Analytics (Suricata)
- Analyzes network-layer threats captured by Suricata IDS.
- Displays detected port scans (classified as `Nmap` or `Masscan`), targeted destination ports, TCP flag distributions, and signature alerts.

### 7. `/map` — Global Attack Map
- Interactive 3D globe and 2D choropleth map plotting real-time attacker origins.
- Shows attack arcs converging into your honeypot sensor node with geolocation coordinates provided by the local GeoIP engine.

### 8. `/ioc` — Threat Intelligence & IOC Export
- Extracts high-confidence Indicators of Compromise (IP addresses, hashes, malware download URLs).
- Provides one-click exports in **STIX 2.1 JSON**, **CSV**, and plain **TXT blocklist** format for firewall integration.

---

## Storage & Maintenance Troubleshooting

On small VPS disks (e.g. 10 GB), Docker build layers, container logs, and containerd content stores can accumulate and hit 100% disk usage. When the disk is 100% full:
- Ingestion stops (DuckDB cannot allocate disk blocks).
- Fluent Bit buffers fill and hold back shipping.
- The `/live` feed stops showing current events and appears "stuck" in the past.

### One-Line Diagnostic Command
Run this on your VPS to immediately see what is consuming disk space:
```bash
df -h / && docker system df
```

### Safe One-Line Cleanup Command
Run this command on your VPS to reclaim 2–4 GB of disk space without deleting honeypot data:
```bash
docker builder prune -af && docker image prune -f
```

### Full Storage Recovery Command (If Disk Hits 100% & Pipeline Halts)
If the disk is completely full and services fail to write, run:
```bash
# 1. Clean build cache and dangling layers
docker builder prune -af
docker image prune -af
# 2. Clean containerd temporary ingest files
rm -rf /var/lib/containerd/io.containerd.content.v1.content/ingest/*
# 3. Check reclaimed space
df -h /
```

---

## Port matrix (host)

| port | service   | note                          |
|------|-----------|-------------------------------|
| 80   | snare     | fake corporate login portal (the bait) |
| 8888 | web/nginx | dashboard + REST + WebSocket  |
| 22022 | sshd    | your real SSH (moved off 22 — see DEPLOYMENT §5) |
| 21   | heralding | FTP                           |
| 22   | cowrie    | SSH (move real sshd first — see DEPLOYMENT §5) |
| 23   | cowrie    | telnet                        |
| 25   | heralding | SMTP                          |
| 110  | heralding | POP3                          |
| 143  | heralding | IMAP                          |

Everything else (api, fluent-bit, tanner) is internal-only; suricata listens on the host network in passive (IDS) mode.

## Quickstart

```bash
# One-shot production install: generates .env secrets, builds the frontend
# inside the web image, starts all 8 services, then prints your login.
bash install.sh

# Manual / local dev equivalent:
cp .env.example .env
sed -i "s/^OBS_SECRET_KEY=.*/OBS_SECRET_KEY=$(openssl rand -hex 32)/" .env
sed -i "s/^OBS_ADMIN_PASSWORD=.*/OBS_ADMIN_PASSWORD=$(openssl rand -hex 32)/" .env
sed -i "s/^OBS_INGEST_API_KEY=.*/OBS_INGEST_API_KEY=$(openssl rand -hex 32)/" .env
docker compose up -d --build
# dashboard: http://localhost:8888/  (login: admin / the OBS_ADMIN_PASSWORD above)
```

The API refuses to start on the `CHANGE_ME_*` placeholders, so a plain
`cp .env.example .env` without setting real secrets fails loudly instead of
serving a known password. The frontend bundle is built inside the web image's
multi-stage build, so a fresh clone needs no pre-existing `frontend/dist/`.

Full production walkthrough: **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**.
Data model, API surface, and classification rules: **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.
Page-by-page dashboard reference: **[PAGES.md](PAGES.md)**.
