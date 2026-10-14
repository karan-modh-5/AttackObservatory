# agent.md — Attack Observatory: context for a fresh agent/engineer

Read this before touching anything. Ground truth lives in `README.md`,
`docs/ARCHITECTURE.md`, `docs/DEPLOYMENT.md`, `docker-compose.yml` and the
code itself — this file is the map, those are the details.

## 1. What the project is

The **Internet Attack Observatory**: a low-resource honeypot stack that lures
real internet attackers, normalizes their activity into one event stream, and
visualizes it in a dark React console (ShardLure-style).

- 9 attack-facing surfaces: SSH, Telnet, HTTP, HTTPS, FTP, SMTP, IMAP, POP3,
  plus network-scan detection via a passive IDS.
- 12 exact attack classifications: `SSH Brute Force`, `Credential Stuffing`,
  `Masscan`, `Nmap`, `Mirai`, `Directory Scanning`, `Web Scanning`,
  `SQL Injection`, `LFI`, `RFI`, `Malware Download`, `Generic Bot Activity`.
- **Hard constraints**: 512 MB RAM, 1 vCPU, 10 GB disk on the production VPS.
  No ELK, no Java, no Kafka, no Kubernetes, no message broker. Every service
  has a `mem_limit` cap; DuckDB memory limit is 128 MB; suricata runs 32 MB
  flow/stream memcaps, single detect thread. A 2 GB swapfile absorbs bursts.

## 2. Architecture & data flow

```
Internet ──► Cowrie (22/23) ──► /var/log/honeypot/cowrie/cowrie.json
        ──► Snare  (80)    ──► /var/log/honeypot/snare/snare.log
        ──► Tanner (internal :8090)
        ──► Heralding (21/25/110/143) ──► heralding_auth.csv
        ──► Suricata (passive IDS, host net) ──► eve.json
                          │
              Fluent Bit tails all files
                          ▼
        POST /api/v1/ingest/{source}   (X-API-Key header)
                          │
   FastAPI: normalize (app/normalize/*) → enrich (GeoIP) →
   classify (app/classify.py) → batched insert into DuckDB
                          ▼
        DuckDB single file (single-writer asyncio queue)
                          ▼
        REST + WebSocket ──► Nginx ──► React SPA dashboard
```

Ingest batching: flush at ≥500 queued events or 1.0 s after the first pending
event (`FLUSH_SIZE`/`FLUSH_INTERVAL_SECONDS` in `backend/app/ingest.py`).
After each flush the batch is fanned out to WebSocket subscribers. When the
bounded queue (default maxsize 20000) is full, events are dropped and counted
— graceful degradation, never a crash.

## 3. Repo layout

- `backend/` — FastAPI app (`backend/app/`): `main.py` (app factory),
  `ingest.py` (queue + batching), `db.py` (DuckDB manager), `classify.py`
  (rules engine), `actors.py` (actor playbook/intent), `geoip.py`,
  `security.py` (bcrypt + JWT), `jobs.py` (APScheduler), `models.py`
  (Pydantic), `routers/` (one file per endpoint group), `normalize/`
  (per-honeypot parsers), `ioc.py`, `backup.py`. Tests in `backend/tests/`.
- `frontend/` — React + Vite + Tailwind. Pages in `src/pages/`, canvas globe
  in `src/components/GlobeCanvas.tsx`, typed API client in `src/api/`.
- `cowrie/`, `snare/`, `tanner/`, `heralding/`, `suricata/`, `fluent-bit/` —
  per-service configs/Dockerfiles. `infra/nginx/observatory.conf` — nginx.
- `scripts/` — `generate-land-dots.mjs`, `backup.sh`, `restore.sh`.
- `docs/` — `ARCHITECTURE.md` (binding port/path/env contract),
  `DEPLOYMENT.md` (production walkthrough).
- `.env.example` — every env var documented; real values live in `.env`
  (gitignored) and on the VPS. NEVER commit or paste secrets.
- **Local-only reference dirs (not part of the deployed stack)**:
  `shardlure/` (UI-parity screenshots + notes), `shardlure_map_page/`,
  `_ref/` (target-design reference images), `TODO.md`, `agent.md`.

## 4. Runtime topology on the VPS

VPS: `ssh -o BatchMode=yes -p 22022 root@<YOUR_VPS_IP>`, project root
`/opt/observatory`, Ubuntu 24.04, docker compose. Dashboard:
`http://<YOUR_VPS_IP>:8888`.

| container    | role                              | host ports        |
|--------------|-----------------------------------|-------------------|
| `web`        | nginx: React SPA + `/api` proxy   | 8888 → 80         |
| `api`        | FastAPI, DuckDB writer            | internal :8000    |
| `fluent-bit` | log shipper → api ingest          | internal          |
| `cowrie`     | SSH/Telnet honeypot               | **22** and **23** |
| `snare`      | web honeypot (fake login portal)  | 80 → 8080         |
| `tanner`     | snare's backend; redis loopback-only inside its container | internal :8090 |
| `heralding`  | FTP/SMTP/POP3/IMAP                | 21, 25, 110, 143  |
| `suricata`   | passive IDS, `network_mode: host`, af-packet on eth0 | n/a (host ns) |

Named volumes: `duckdb-data` (→ `/data` in api), `backups`, `cowrie-logs`,
`hp-logs`, `heralding-logs`, `suricata-logs`, `fluentbit-db`, `snare-pages`.

`docker-compose.override.yml` (prod cutover) uses the `!override` tag
(compose v2.24+; VPS ships 2.40) to map cowrie to host 22/23 — replacing the
base file's 2222/2323 test mappings. Real sshd listens on **22022**.

Nginx (`infra/nginx/observatory.conf`): static SPA at `/`, `/api/` proxied to
`api:8000` with the original URI unchanged, and a dedicated
`location /api/v1/ws/live` with long read/send timeouts for hour-long
WebSocket connections.

## 5. Database schema highlights

Single table `events` (DDL in `backend/app/db.py`): `id` (sequence),
`timestamp TIMESTAMPTZ`, `source_ip`, `country`, `city`, `asn`, `lat`, `lon`,
`honeypot`, `service`, `attack_type`, `username`, `password`, `payload`,
`severity`, `session_id`, `created_at`, plus migration-added columns
`event_kind` (e.g. `malware_download` — downloaded artifact metadata),
`sha256`, `size_bytes` (added idempotently via
`ALTER TABLE ... ADD COLUMN IF NOT EXISTS` for pre-existing DBs). Indexes on
`timestamp`, `event_kind`, `sha256`, `source_ip`, `attack_type`, `honeypot`.

- **`DuckDBManager` owns the ONLY writable connection.** Writes go through
  `execute_write()` / the ingest flush loop under `write_lock`. Reads use
  short-lived **read-only** connections (`db.read()` / `fetch_all()`).
- NEVER open a second write connection to the DuckDB file from anywhere
  (script, notebook, second process) while the api container runs — DuckDB
  is single-writer; a second writer locks/corrupts access.
- PRAGMAs per connection: `memory_limit=128MB`, `threads=1`, UTC.
- Background jobs (`backend/app/jobs.py`, APScheduler): hourly retention
  (`OBS_RETENTION_DAYS`, default 90), weekly GeoIP refresh + event-kind
  backfill, nightly 03:00 UTC gzip backup via `app/backup.py`.
  `scripts/restore.sh` validates and atomically swaps the DB file.

## 6. Backend API surface (all under `/api/v1`)

**Public:** `POST /auth/login` (→ JWT HS256, `OBS_TOKEN_EXPIRE_MINUTES`
default 1440), `GET /auth/me`, `GET /health`, `GET /health/ready` (returns
`status`, `database`, `geoip`, `queue_depth`, `uptime_seconds`),
`POST /ingest/{source}` (auth: `X-API-Key` = `OBS_INGEST_API_KEY`; sources:
cowrie/snare/tanner/heralding/suricata).

**Protected (Bearer JWT, `require_admin` dependency):**
- SSH: `GET /ssh/stats`, `/ssh/actors` (actor intelligence), `/ssh/heatmap`
  (activity heatmap), `/ssh/payloads`
- Stats: `GET /stats/overview`, `/stats/timeseries`
- `GET /events` (filterable event list), `GET /map/points` (GeoIP map data)
- Web: `GET /web/stats` · Credentials: `GET /credentials/stats`
- Network (suricata): `GET /network/stats`
- IOC: `GET /ioc`, `GET /ioc/export`
- Live: `WS /ws/live?token=<jwt>`

Classification is a **pure-Python rules engine** (`backend/app/classify.py`):
stateful, per-IP sliding windows driven by event timestamps (dirscan 60 s,
web requests 60 s, SSH brute 300 s, credential stuffing 3600 s, portscan
60 s), OrderedDict LRU capped ~10k keys — so replayed logs don't poison
windows. First matching rule wins. Actor intelligence lives in
`backend/app/actors.py`: pure classification of per-IP aggregates into a
`(playbook, intent)` pair — e.g. `opportunistic`, `crypto_target` — computed
from counts and command features over the same SQL window.

GeoIP: zero-config default uses keyless **DB-IP lite** mmdb files
(country/city/ASN), auto-downloaded into `OBS_GEOIP_DIR` (`/data/geoip`) and
refreshed weekly, past events backfilled. Setting `OBS_MAXMIND_LICENSE_KEY`
switches to GeoLite2.

## 7. Frontend map — the dependency-free canvas globe

`frontend/src/components/GlobeCanvas.tsx` renders the attack map with **no
3D/map libraries** — raw Canvas 2D:

- Dotted-Earth halftone land cloud from `frontend/src/lib/land-dots.json`
  (`{ "step": 1.7, "points": [lat, lon, ...] }`), precomputed cos/sin per dot.
- Seeded deterministic starfield with twinkle phase behind the globe disc.
- Great-circle **slerp** attack arcs (`slerpPath`) drawn as comet trails from
  each attacker origin into the LIVE sensor chip (marker at ~lat 12.97) with
  live pulses and a labeled chip (`sensorLabel`).

Regenerate land dots: `node scripts/generate-land-dots.mjs
[path/to/ne_110m_land.geojson]` (Natural Earth 110m, public domain; default
input path is `land110.geojson` at repo root). JSON import requires
`resolveJsonModule: true` — already set in `frontend/tsconfig.app.json`;
keep it if you touch tsconfig.

Routes (`frontend/src/App.tsx`): `/login`, then behind auth `/` (Overview),
`/live`, `/map`, `/ssh`, `/web`, `/credentials`, `/network`, `/ioc`.

## 8. Deploy workflow

1. Edit locally. Test what you can locally.
2. `scp -P 22022 <changed files> root@<YOUR_VPS_IP>:/opt/observatory/<path>`
3. On the VPS: `docker compose build <svc> && docker compose up -d <svc>`
   - `api` (pure Python): rebuild+restart is near-instant.
   - `web` (Vite build inside Docker): **~1–10 minutes** on the 1 vCPU box.
     Only rebuild web when frontend source actually changed.
4. **Disk is the recurring emergency** (10 GB total). The frontend build
   stage cache alone is ~700 MB. After rebuilds, when `df -h /` climbs:
   `docker builder prune -af`, `docker image prune -af`,
   `journalctl --vacuum-size=50M`. The retention job caps the DuckDB file;
   suricata `eve.json` grows ~10 MB/day under normal scan pressure.

## 9. Verification commands

```bash
# Backend test suite (inside the container):
ssh -p 22022 root@<YOUR_VPS_IP> 'cd /opt/observatory && docker compose run --rm --no-deps -v /opt/observatory/backend/tests:/app/tests:ro api sh -c "cd /app && python -m pytest -q"'
# The api image does NOT contain tests/ — mount them read-only as above and use
# `compose run --rm` (ephemeral layer). NEVER `exec` pytest into the live api
# container: test temp DuckDB files permanently grow its writable overlay
# (filled the disk once; needed `docker rm -f` of the container to reclaim).
# Local equivalent: cd backend && python -m pytest -q   (needs pytest + requirements)

# Health / readiness (no auth):
curl -s http://<YOUR_VPS_IP>:8888/api/v1/health/ready
# → check status, queue_depth, uptime_seconds

# Authenticated endpoint check:
TOKEN=$(curl -s -X POST http://<YOUR_VPS_IP>:8888/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"<OBS_ADMIN_USER>","password":"<OBS_ADMIN_PASSWORD>"}' | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://<YOUR_VPS_IP>:8888/api/v1/stats/overview

# Frontend deploy check: hard-refresh the browser (Ctrl+Shift+R) and confirm
# the new bundle hash is served under /assets/ (view page source).
```

Test files: `backend/tests/test_api.py`, `test_classify.py`, `test_normalize.py`.

## 10. Known gotchas

- **DuckDB single-writer**: never open a second write connection (container
  sidecar, CLI, script) while the api runs. Use read-only connections for
  inspection, or stop the stack first.
- **JWT secret stability**: `OBS_SECRET_KEY` must not change across restarts,
  or every issued token invalidates and all dashboard sessions log out. It
  lives in `.env` on the VPS — don't regenerate casually.
- **suricata-update leaks ~44 MB tmp dirs per run** (observed 351 MB after 4
  days on this 10 GB VPS). `suricata/entrypoint.sh` ends the update block with
  `rm -rf /tmp/tmp*suricata-update` — **do not remove that line**.
- **cowrie owns public port 22; real sshd is on 22022.** If SSH "fails",
  you're hitting the honeypot or using port 22. Always
  `ssh -p 22022 root@<YOUR_VPS_IP>`. Never test-log into port 22 expecting a
  real shell.
- Base compose maps cowrie 2222/2323 for pre-cutover testing; the override
  file's `!override` tag is what puts it on 22/23 in production. Requires
  compose v2.24+.
- Suricata runs `network_mode: host` (af-packet); its eve.json lands on the
  `suricata-logs` volume → fluent-bit → api. Don't publish it via `ports:`.
- Disk at ~90% is normal-ish; **alert above 95%**. Prune recipe in §8.
- cowrie's `cowrie.cfg` does not interpolate env vars — if you change
  `COWRIE_HOSTNAME` in `.env`, change it in `cowrie/cowrie.cfg` too.

## 11. Current state summary (as of 2026-10-13)

- All 8 compose services (`web api fluent-bit cowrie snare tanner heralding suricata`)
  deployed and healthy on the VPS; dashboard live at `http://<YOUR_VPS_IP>:8888`.
- Backend test suite green (`compose run --rm` pytest as above; 47 passed).
- Tests run with OBS_GEOIP_ENABLED=false (conftest) — never download the 131MB
  DB-IP databases; a full suite once filled the 10GB disk that way.
- `/network/stats` is windowed (default 7 days). The old 30-day signature
  GROUP BY took 30s+ on this box and stalled the whole /map page.
- DISK GUARD: the 10GB disk filled twice (build cache + log rotations). A daily
  cron (`/etc/cron.d/obs-disk-gc`, script `scripts/obs-disk-gc.sh`, installed
  at `/usr/local/bin/obs-disk-gc.sh` on the VPS) prunes build cache, truncates
  container logs >50MB, deletes rotated honeypot logs >3 days, and force-prunes
  unused images above 90% usage. `/etc/docker/daemon.json` caps container logs
  at 10m×3 — applies to containers created after it was added.
- UI pages shipped: Overview (`/`), Live feed (`/live`), Attack map (`/map`),
  SSH (`/ssh`), Web (`/web`), Credentials (`/credentials`),
  Network (`/network`), IOC center (`/ioc`), Login (`/login`).
- ShardLure-parity work completed on `/ssh` and `/map`: SSH page has actor
  intelligence (playbook/intent), payloads and activity heatmap; map page has
  the canvas globe with land-dot cloud, starfield and slerp comet arcs
  (reference screenshots in `shardlure/`, `shardlure_map_page/`, `_ref/`).
- Remaining repo-side housekeeping is tracked in `TODO.md` (VPS↔repo sync,
  git init/commit, final verification) — check it before assuming state.
