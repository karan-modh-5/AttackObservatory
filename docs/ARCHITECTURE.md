# Attack Observatory — Architecture Contract

Single source of truth for the pipeline, data schema, API surface, environment
variables, ports and file paths. Every component MUST conform to this document.

```
Internet ──► Cowrie (22/tcp, 23/tcp)        ──► /var/log/honeypot/cowrie/cowrie.json
        ──► Snare  (80/tcp)                 ──► /var/log/honeypot/snare/snare.log
        ──► Tanner (internal :8090)         ──► /var/log/honeypot/tanner/tanner.log
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

## 1. Normalized event schema

Internal record (pydantic `models.Event`) and DuckDB table columns. Fields the
product spec requires first; `lat`/`lon` are internal extras used by the map.

| column     | DuckDB type  | JSON type      | notes                                     |
|------------|--------------|----------------|-------------------------------------------|
| id         | BIGINT       | int            | sequence `events_id_seq`, server assigned |
| timestamp  | TIMESTAMPTZ  | ISO-8601 str   | UTC, event time (not receive time)        |
| source_ip  | VARCHAR      | str \| null    |                                           |
| country    | VARCHAR      | str \| null    | ISO-3166 alpha-2, from GeoLite2-City      |
| city       | VARCHAR      | str \| null    |                                           |
| asn        | VARCHAR      | str \| null    | e.g. `AS14061 DigitalOcean, LLC`          |
| lat        | DOUBLE       | float \| null  | GeoLite2-City location                    |
| lon        | DOUBLE       | float \| null  | GeoLite2-City location                    |
| honeypot   | VARCHAR      | str            | `cowrie|snare|tanner|heralding|suricata`  |
| service    | VARCHAR      | str            | `ssh|telnet|http|https|ftp|smtp|imap|pop3|scan` |
| attack_type| VARCHAR      | str            | exactly one label from §2                 |
| username   | VARCHAR      | str \| null    |                                           |
| password   | VARCHAR      | str \| null    |                                           |
| payload    | VARCHAR      | str \| null    | commands, URLs, paths, signatures; ≤ 8 KiB |
| severity   | VARCHAR      | str            | `info|low|medium|high|critical`           |
| session_id | VARCHAR      | str \| null    | honeypot session / suricata flow_id       |

DDL (backend must execute exactly this on startup):

```sql
CREATE SEQUENCE IF NOT EXISTS events_id_seq;
CREATE TABLE IF NOT EXISTS events (
    id          BIGINT DEFAULT nextval('events_id_seq'),
    timestamp   TIMESTAMPTZ NOT NULL,
    source_ip   VARCHAR,
    country     VARCHAR,
    city        VARCHAR,
    asn         VARCHAR,
    lat         DOUBLE,
    lon         DOUBLE,
    honeypot    VARCHAR NOT NULL,
    service     VARCHAR NOT NULL,
    attack_type VARCHAR NOT NULL,
    username    VARCHAR,
    password    VARCHAR,
    payload     VARCHAR,
    severity    VARCHAR NOT NULL,
    session_id  VARCHAR,
    event_kind  VARCHAR,            -- cowrie: connect|client_version|failed_password|accepted|command|file_download|file_upload
    sha256      VARCHAR,            -- cowrie file_download shasum
    size_bytes  BIGINT,             -- cowrie file_download filesize
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_events_ts        ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_kind      ON events (event_kind);
CREATE INDEX IF NOT EXISTS idx_events_sha       ON events (sha256);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events (source_ip);
CREATE INDEX IF NOT EXISTS idx_events_type      ON events (attack_type);
CREATE INDEX IF NOT EXISTS idx_events_honeypot  ON events (honeypot);
```

Pragmas on every connection: `memory_limit`, `threads=1`,
`timezone='UTC'`. Writer connection is the ONLY writable connection; readers use
`read_only=True`. Writes are batched (queue consumer: flush at ≥500 events or
every 1.0 s) behind an asyncio lock; after each flush the batch is published to
WebSocket subscribers.

## 2. Attack classification (labels are exact strings)

`SSH Brute Force`, `Credential Stuffing`, `Masscan`, `Nmap`, `Mirai`,
`Directory Scanning`, `Web Scanning`, `SQL Injection`, `LFI`, `RFI`,
`Malware Download`, `Generic Bot Activity`

Rules (evaluated top to bottom; first match wins; engine is pure-Python +
a bounded in-memory per-IP sliding window for burst detection):

| label                | detection |
|----------------------|-----------|
| Mirai                | cowrie/heralding credentials in the Mirai default set (e.g. `root/xc3511`, `admin/1234`, `support/support`, `user/tluafed`, bin names `mirai.*|.mips|.arm|.sh4`) or payload containing `busybox` + `enable`/`shell` probes |
| Malware Download     | cowrie command invokes `wget`/`curl`/`tftp`/`scp`/`ftpget` with a URL/IP payload; cowrie `file_download` event; snare payload fetching a binary (`.bin|.sh|.mips|.arm|.exe`) |
| SQL Injection        | tanner `sqli` detection, or payload regexes: `union\s+select`, `'\s*or\s*'?1'?\s*=\s*1`, `sleep\(\d`, `benchmark\(`, `information_schema`, `--\s*$` in query |
| LFI                  | payload path traversal `(\.\./){2,}` or `/etc/passwd`, `/etc/shadow`, `windows/win.ini`, `php://filter|php://input` |
| RFI                  | query param value containing `https?://` plus `=` remote inclusion patterns (`=http` with `.txt`, `.php` remote target) |
| Directory Scanning   | snare/tanner: ≥10 distinct 404 paths from one IP inside window (default 60 s) |
| Web Scanning         | snare/tanner UA matches `nikto|sqlmap|masscan|nmap|dirbuster|gobuster|wpscan|acunetix|nessus|zgrab|censys|paloalto` or ≥20 requests/60 s from one IP |
| SSH Brute Force      | cowrie/heralding login attempts: ≥5 failures/300 s from one IP, or any successful login after failures |
| Credential Stuffing  | heralding: ≥3 distinct source IPs using the same username/1 h, or ≥1 attempt where username==password==common breach string |
| Masscan              | suricata signature mentions `masscan`/`zmap`, or ≥50 distinct dst ports/60 s from one IP |
| Nmap                 | suricata signature mentions `nmap` |
| Generic Bot Activity | fallback for any parsed event |

Severity map: Mirai, Malware Download → `high`; SQL Injection, LFI, RFI →
`high`; SSH Brute Force, Credential Stuffing → `medium`; Masscan, Nmap,
Directory Scanning, Web Scanning → `low`; Generic Bot Activity → `info`.

## 3. Normalizers per source

Fluent Bit posts batches of records to `/api/v1/ingest/{source}` where
`source ∈ {cowrie, snare, tanner, heralding, suricata}`. Each record is either a
parsed JSON object (json-parser sources) or `{"log": "<raw line>"}` (tail-only
sources). Normalizers MUST tolerate malformed lines (skip + counter, never
raise). `timestamp` fallback = receive time.

- **cowrie** (JSON lines, `cowrie.json`): events `cowrie.session.connect`,
  `cowrie.login.failed`, `cowrie.login.success`, `cowrie.command.input`,
  `cowrie.session.file_download`, `cowrie.session.file_upload`,
  `cowrie.client.version`, `cowrie.session.closed`. `service` = `ssh` or
  `telnet` (from `cowrie.telnet.*` prefix). login events fill username/password;
  command.input fills payload (command string); file_download fills payload
  (url) plus `sha256`/`size_bytes`; file_upload fills payload (filename or
  `tty upload`); client.version fills payload (joined version string);
  session.connect → `Generic Bot Activity`/`info`; session.closed keeps
  `event_kind` NULL (not a probe). Each handled event sets `event_kind`
  (`connect`, `failed_password`, `accepted`, `command`, `file_download`,
  `file_upload`, `client_version`). A bounded in-memory map (50 000 entries,
  oldest half cleared when full) records session→username from login events so
  command.input / file_download / file_upload inherit the actor's username.
- **heralding** (raw CSV lines from `heralding_auth.csv`, columns
  `time_retrieved,src_ip,src_port,dst_ip,dst_port,protocol,username,password`;
  parse with `csv.reader`, skip header, tolerate quoted commas).
  `service` = protocol lowercase.
- **snare** (raw stdout lines): try JSON; else regex
  `<ip> ... "<METHOD> <path>"` + trailing `"<user-agent>"`. service `http`.
- **tanner** (raw stdout lines, JSON-ish): tanner detection ids
  (`sqli`, `lfi`, `rfi`, `rfi/include`, `xss`) drive classification; service `http`.
- **suricata** (JSON lines from `eve.json`): only `event_type == "alert"`;
  `service` = `scan`; payload = `alert.signature`; session_id = `flow_id`.

## 4. REST API (prefix `/api/v1`)

Auth: `Authorization: Bearer <jwt>` on everything except
`POST /auth/login`, `GET /health`, `GET /health/ready`, `POST /ingest/{source}`
(X-API-Key header, constant-time compare). JWT HS256, exp from env.

- `POST /auth/login` `{username, password}` → `{access_token, token_type:"bearer"}`
- `GET  /auth/me` → `{username}`
- `GET  /events?limit=50&offset=0&honeypot=&service=&attack_type=&severity=&ip=&since=&until=`
  → `{total, items: Event[]}` (limit ≤ 500; since/until ISO-8601)
- `GET  /stats/overview` → `{total_attacks, unique_attackers, countries, credentials_captured, commands_executed, last_24h}`
- `GET  /stats/timeseries?days=7&interval=hour|day` → `{interval, points:[{bucket,total}], by_type:[{attack_type,count}]}`
- `GET  /ssh/stats?days=30` → `{sessions, brute_force_events, top_usernames:[{name,count}], top_passwords:[{name,count}], top_commands:[{name,count}], malware_downloads:[{name,count}], top_sources:[{name,count}], event_kinds:[{name,count}]}`
- `GET  /ssh/heatmap?hours=72` (6–168) → `{hours:[ISO hour], kinds:[kind], matrix:[[count per hour] per kind]}` (cowrie events, zero-filled buckets, kinds sorted by total desc)
- `GET  /ssh/actors?days=30` → `{actors:[{ip, country, city, playbook, intent, events, probes, last_cmd, last_seen}], playbooks:[{name,count}], intents:[{name,count}], event_kinds:[{name,count}], sources:[{name,count}], geography:[{name,count}]}` (actors = per-IP window aggregates, top 50 by events; playbooks: `opportunistic|crypto_target|service_account_enum|default_credential_spray|fast_dictionary|handshake_scan|scanner_tool`; intents: `deploy|probe|unknown`; playbooks/intents are all-time aggregates)
- `GET  /ssh/payloads?limit=100` → `{stats:{tracked_urls, saved, fetching_now, bytes_on_disk}, items:[{time, url, sha256, size_bytes, source_ip, origin}]}` (cowrie file_download events)
- `GET  /web/stats?days=30` → `{scanner_events, top_urls:[{name,count}], top_user_agents:[{name,count}], exploit_payloads:[{name,count}], attack_types:[{attack_type,count}]}`
- `GET  /credentials/stats?days=30` → `{unique_pairs, by_service:[{name,count}], top_usernames:[{name,count}], top_passwords:[{name,count}], reuse_pairs:[{username,password,count}]}`
- `GET  /network/stats?days=30` → `{total_alerts, signatures:[{name,count}], protocols:[{name,count}], top_sources:[{name,country,count}]}`
- `GET  /map/points?days=7` → `{points:[{lat,lon,weight,country}], top_countries:[{name,count}]}` (points capped 500, rounded to 0.01°)
- `GET  /ioc?days=7` → `{ips:[{value,country,asn,hits,last_seen}], urls:[{value,hits}], domains:[{value,hits}], hashes:[{value,hits}]}` (each capped 1000)
- `GET  /ioc/export?format=csv|json&types=ip,url,domain,hash&days=7` → attachment `ioc_YYYYMMDD.csv|json`
- `GET  /health` → `{status:"ok"}`
- `GET  /health/ready` → `{status, database, geoip, queue_depth}`
- `WS   /ws/live?token=<jwt>` → pushes each normalized `Event` as JSON frame;
  accepts `{"type":"ping"}` replies `{"type":"pong"}`

All list facets (`name|value`) capped at 20 rows unless noted.

## 5. Ingest endpoint

`POST /api/v1/ingest/{source}` with `X-API-Key: $OBS_INGEST_API_KEY`, body =
JSON array of records, max 5000. Response `202 {"accepted": n, "rejected": m}`.
Accepted records are normalized → enriched → classified → queued; the queue
consumer batches into DuckDB and fans out to WebSocket.

## 6. Environment variables (single `.env`, consumed by compose)

| var | default | used by |
|-----|---------|---------|
| `OBS_SECRET_KEY` | — (required) | api: JWT signing |
| `OBS_ADMIN_USER` | `admin` | api |
| `OBS_ADMIN_PASSWORD` | — (required) | api |
| `OBS_INGEST_API_KEY` | — (required) | api + fluent-bit |
| `OBS_TOKEN_EXPIRE_MINUTES` | `1440` | api |
| `OBS_DB_PATH` | `/data/observatory.duckdb` | api |
| `OBS_DB_MEMORY_LIMIT` | `128MB` | api |
| `OBS_RETENTION_DAYS` | `90` | api |
| `OBS_QUEUE_MAXSIZE` | `20000` | api |
| `OBS_MAXMIND_LICENSE_KEY` | empty | api: GeoLite2 download; empty ⇒ enrichment disabled gracefully |
| `OBS_GEOIP_DIR` | `/data/geoip` | api |
| `OBS_LOG_LEVEL` | `INFO` | api |
| `OBS_CORS_ORIGINS` | `http://localhost:5173` | api |
| `SNARE_CLONE_SITE` | `https://example.com` | snare entrypoint |
| `SNARE_PAGE_NAME` | `example.com` | snare entrypoint |
| `COWRIE_HOSTNAME` | `svc-01` | cowrie.cfg |
| `TZ` | `UTC` | all |

## 7. Deployment topology (docker compose, project = observatory)

| service | image | ports (host) | notes |
|---------|-------|--------------|-------|
| `web`   | built `frontend/Dockerfile` (multi-stage: node build → `nginx:alpine`) | `8888:80` | serves SPA, proxies `/api/` + `/api/v1/ws/live` to `api:8000` |
| `api`   | built `backend/Dockerfile` (python:3.12-slim) | none (internal) | volumes `duckdb-data:/data`, `geoip` under /data, `backups:/backups` |
| `fluent-bit` | `fluent/fluent-bit:3.2` | none | mounts `cowrie-logs`, `suricata-logs`, `heralding-logs`, `hp-logs` **read-only**, `fluentbit-db` rw |
| `cowrie`| `cowrie/cowrie:latest` | base `2222:2222`, `2323:2223`; `docker-compose.override.yml` (shipped) replaces them with `22:2222`, `23:2223` after real sshd moves to 22022 | cfg at `/cowrie/cowrie-git/etc/cowrie.cfg` (image layout), json output to `cowrie-logs` volume (uid 999) |
| `snare` | built `snare/Dockerfile` (source install; the ghcr.io image is not publicly pullable) | `80:8080` | serves the bundled fake login portal (`snare/portal/`, installed as page `$SNARE_PAGE_NAME` when the pages volume is fresh) or clones `$SNARE_CLONE_SITE`; access log forwarded to volume |
| `tanner`| built `tanner/Dockerfile` (source install; ghcr.io image not publicly pullable; bundles loopback-only redis — tanner requires it and the stack has no separate redis service) | internal 8090 | tees log to volume |
| `heralding` | built `heralding/Dockerfile` (pip install) | `21:21`, `25:25`, `110:110`, `143:143` | yaml config, csv auth log on volume |
| `suricata` | `jasonish/suricata:latest` | host network | `af-packet` on `eth0`, `network_mode: host`, runs `suricata-update` then suricata; local fallback rules shipped |

Volumes: `duckdb-data`, `cowrie-logs` (at the cowrie image's log dir
`/cowrie/cowrie-git/var/log/cowrie` — an empty named volume mounted there
inherits the image directory's uid-999 ownership, so the non-root cowrie user
can write), `suricata-logs` (`/var/log/suricata`), `heralding-logs`
(`/var/log/heralding`), `hp-logs` (`/var/log/honeypot`, holds the `snare/` and
`tanner/` tee output), `fluentbit-db` (`/flb-db`), `snare-pages`, `backups`.
Separate volumes per honeypot are deliberate: each gets the permissions of the
image directory it replaces. fluent-bit mounts `cowrie-logs`, `suricata-logs`
and `heralding-logs` read-only at `/var/log/honeypot/{cowrie,suricata,heralding}`
and `hp-logs` read-only at `/var/log/honeypot`, so the contract paths below hold.

All services `restart: unless-stopped` with `mem_limit` caps (suricata 256m,
api 256m, cowrie 128m, snare 96m, tanner 96m, heralding 64m, fluent-bit 48m,
web 32m).

Log files visible to fluent-bit (contract paths — must stay exactly):
`/var/log/honeypot/cowrie/cowrie.json`, `/var/log/honeypot/snare/snare.log`,
`/var/log/honeypot/tanner/tanner.log`,
`/var/log/honeypot/heralding/heralding_auth.csv`,
`/var/log/honeypot/suricata/eve.json`.

## 8. Background jobs (APScheduler, in-process)

- `retention`: hourly — `DELETE FROM events WHERE timestamp < now() - interval '$OBS_RETENTION_DAYS days'` + `CHECKPOINT`
- `geoip`: on boot if DBs missing and license key set; then weekly — download
  GeoLite2-City + GeoLite2-ASN tar.gz from MaxMind into `$OBS_GEOIP_DIR`
- `event-kind-backfill`: on boot after schema init + weekly — idempotent SQL
  `UPDATE events SET event_kind = CASE ... END WHERE honeypot='cowrie' AND
  event_kind IS NULL` (approximate for historical rows; logged rowcount)
- `backup`: daily 03:00 — `CHECKPOINT` then gzip copy of the DB file into `/backups`
- host cron equivalent + restore procedure live in `scripts/backup.sh`,
  `scripts/restore.sh`

## 9. Code standards

Python 3.12, strict typing (`from __future__ import annotations`, pydantic v2
models for all payloads/responses), structured JSON logging (request-id
middleware), slowapi rate limiting (strict on login, default on reads).
Frontend: TypeScript strict, no `any`, functional components + hooks only.
No TODO/FIXME/placeholder comments anywhere. No pseudocode.
