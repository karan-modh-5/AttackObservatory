# Attack Observatory

A low-resource honeypot observatory: **6 honeypots → 1 normalization pipeline →
one DuckDB → a React dashboard**, designed to run on a **512 MB RAM / 1 vCPU /
10 GB VPS**.

```
Internet ──► Cowrie (22/tcp, 23/tcp)        ──► /var/log/honeypot/cowrie/cowrie.json
        ──► Snare  (8080/tcp)               ──► /var/log/honeypot/snare/snare.log
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
                                     Nginx :80 (static React SPA, /api → api:8000)
```

## What's inside

- **9 attack-facing services**: ssh, telnet, http, https, ftp, smtp, imap,
  pop3 and network scan detection (suricata).
- **12 attack classifications** (exact labels): `SSH Brute Force`,
  `Credential Stuffing`, `Masscan`, `Nmap`, `Mirai`, `Directory Scanning`,
  `Web Scanning`, `SQL Injection`, `LFI`, `RFI`, `Malware Download`,
  `Generic Bot Activity`.
- **8 dashboard pages**: Overview, Live event stream (WebSocket), SSH, Web,
  Credentials, Network (suricata), Attack map (GeoLite2), IOC export.
- Pure-Python classification engine with per-IP sliding windows — no ELK, no
  Java, no Kafka, no Kubernetes.

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
| 8080 | snare     | legacy mapping (no longer published) |

Everything else (api, fluent-bit, tanner) is internal-only; suricata listens on
the host network in passive (IDS) mode.

## Quickstart

```bash
cp .env.example .env      # then set the three CHANGE_ME_* secrets
docker compose up -d --build
# dashboard: http://localhost/  (login: OBS_ADMIN_USER / OBS_ADMIN_PASSWORD)
```

Full production walkthrough (swapfile, sshd relocation off port 22, ufw rules,
verification checklist, backup cron + restore drill): **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**.
Data model, API surface, classification rules and the binding port/path
contract: **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

## Low-resource design notes

- Log shipping is **fluent-bit → HTTP ingest** into a batched DuckDB writer
  (flush at ≥500 events or 1 s), not a broker.
- Every service has a `mem_limit` cap; suricata runs with 32 MB flow/stream
  memcaps and a single detect thread; tanner's required redis is bundled
  loopback-only inside the tanner container (no extra service).
- GeoIP works with zero configuration: the api auto-downloads the keyless
  DB-IP lite databases and backfills past events; a MaxMind license key
  (`OBS_MAXMIND_LICENSE_KEY`) switches to the higher-accuracy GeoLite2 source.
- Backups are gzipped DuckDB copies (nightly, in-container and host cron);
  `scripts/restore.sh` validates and atomically swaps the DB file.
