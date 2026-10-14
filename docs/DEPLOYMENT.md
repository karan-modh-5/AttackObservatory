# Attack Observatory — Deployment Guide

Production deployment for the target VPS: **Ubuntu 24.04, 1 vCPU, 512 MB RAM,
10 GB disk**. The full stack (web, api, fluent-bit, cowrie, snare, tanner,
heralding, suricata) runs from `docker-compose.yml` in the repository root.

Read `docs/ARCHITECTURE.md` first — it is the binding contract for ports,
paths and environment variables.

---

## 0. DNS and firewall planning

- Point an A/AAAA record (e.g. `observatory.example.com`) at the VPS IP. Only
  port **80** is used by the dashboard; everything else is honeypot bait.
- Plan the final open-port list (step 5 shows the order that keeps you locked
  out):

  | port | purpose                        |
  |------|--------------------------------|
  | 80   | snare fake login portal        |
  | 8888 | nginx dashboard + API          |
  | 22022| **your real SSH** (moved)      |
  | 21   | heralding FTP                  |
  | 22   | cowrie SSH (after step 5)      |
  | 23   | cowrie telnet                  |
  | 25   | heralding SMTP                 |
  | 110  | heralding POP3                 |
  | 143  | heralding IMAP                 |

- **Never** allow ports 2222/2323 externally unless you skipped step 5 (the
  base compose maps `2222:2222` and `2323:2223` so you can test before moving
  real sshd).

## 1. Create a 2 GB swapfile

The stack's `mem_limit` caps sum above 512 MB on purpose (caps are ceilings,
not reservations); swap absorbs bursts.

```bash
fallocate -l 2G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab
sysctl vm.swappiness=10
echo 'vm.swappiness=10' > /etc/sysctl.d/99-observatory.conf
free -h   # verify Swap: 2.0Gi
```

## 2. Install Docker Engine + Compose v2

```bash
apt update && apt -y upgrade
apt install -y docker.io docker-compose-v2
systemctl enable --now docker
docker compose version    # expect v2.x
```

(Alternative: `curl -fsSL https://get.docker.com | sh`, which also installs the
compose plugin.)

## 3. Get the repository onto the box

```bash
mkdir -p /opt/observatory
# via git:
git clone <your-repo-url> /opt/observatory
# or upload an archive from your machine and unpack it into /opt/observatory
cd /opt/observatory
ls   # expect docker-compose.yml, backend/, frontend/, fluent-bit/, ... docs/
```

## 4. Configure `.env`

```bash
cp .env.example .env
sed -i "s/^OBS_SECRET_KEY=.*/OBS_SECRET_KEY=$(openssl rand -hex 32)/" .env
sed -i "s/^OBS_ADMIN_PASSWORD=.*/OBS_ADMIN_PASSWORD=$(openssl rand -hex 32)/" .env
sed -i "s/^OBS_INGEST_API_KEY=.*/OBS_INGEST_API_KEY=$(openssl rand -hex 32)/" .env
chmod 600 .env
grep CHANGE_ME .env   # must output nothing
```

Notes:

- Save the `OBS_ADMIN_PASSWORD` value — it is the dashboard login.
- **GeoIP (works out of the box):** without any key the api auto-downloads the
  keyless DB-IP free lite databases (country/city/ASN, refreshed weekly,
  attribution: DB-IP.com) and backfills existing events. For higher accuracy
  you can optionally create a free MaxMind account at
  <https://www.maxmind.com/en/geolite2/signup>, generate a license key
  (Account → GeoIP2 / GeoLite2 → Manage License Keys), then set
  `OBS_MAXMIND_LICENSE_KEY=<key>` in `.env`. With a key, the api downloads
  GeoLite2-City/ASN on first boot and weekly afterwards; without one, the
  keyless DB-IP lite source is used instead.
- Optionally point `SNARE_CLONE_SITE` at a site you want to imitate;
  `SNARE_PAGE_NAME` must equal its root host (`https://example.com/` →
  `example.com`).

## 5. Move real sshd off port 22 BEFORE exposing cowrie on 22

Do this before the first `docker compose up` if you plan to map cowrie onto
22/23. Keep your **current SSH session open the whole time**.

```bash
# 5.1 Configure sshd to additionally listen on 22022 (keep 22 for now)
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
printf '\nPort 22\nPort 22022\n' >> /etc/ssh/sshd_config
sshd -t
# Ubuntu 24.04 gotcha: ssh is socket-activated and ssh.socket ignores Port.
# Switch to classic service mode or the new port never opens:
systemctl disable --now ssh.socket && systemctl enable ssh.service
systemctl restart ssh
ss -ltnp | grep -E ':(22|22022)\s'   # BOTH must listen before proceeding

# 5.2 Open the new port in the firewall FIRST
ufw allow 22022/tcp
ufw allow 8888/tcp
ufw allow 80/tcp
ufw allow 21/tcp && ufw allow 23/tcp && ufw allow 25/tcp
ufw allow 110/tcp && ufw allow 143/tcp

# 5.3 PROVE the new port works from OUTSIDE before touching port 22:
#     from your workstation:  ssh -p 22022 root@<vps-ip> 'echo ok'
#     Only after that succeeds, close your old session.

# 5.4 Drop port 22 from sshd (edit the appended block to a single 'Port 22022')
sed -i 's/^Port 22$/#Port 22/' /etc/ssh/sshd_config
sshd -t && systemctl restart ssh
ss -ltnp | grep -E ':(22|22022)\s'   # sshd only on 22022 now
```

Then publish cowrie on 22/23 with a compose override — create
`/opt/observatory/docker-compose.override.yml`:

```yaml
services:
  cowrie:
    ports: !override
      - "22:2222"
      - "23:2223"
```

`!override` replaces the base port list (plain `ports:` would merge and keep
2222/2323 published too). With the override, the externally visible ports are
exactly the table in step 0.

## 6. Build and start

```bash
cd /opt/observatory
docker compose --env-file .env config -q   # sanity-check .env + compose file
docker compose up -d --build
docker compose ps
```

First-run notes:

- **First build needs egress**: the `snare`, `tanner` and `heralding` images
  install from upstream sources at build time (git clone + pip), so run the
  build on a box with internet access. Subsequent rebuilds use the docker build
  cache.
- **suricata-update**: on the first boot suricata tries to download the ET
  open ruleset (120 s budget). Offline or blocked → it logs a warning and runs
  with the shipped `suricata/rules/local.rules` baseline. Check with
  `docker compose logs suricata | grep -E 'suricata-update|fallback'`.
- **snare** clones `SNARE_CLONE_SITE` once into the `snare-pages` volume; later
  restarts reuse the clone. If cloning fails 3 times the container exits with a
  clear message — fix the site/egress and `docker compose up -d snare` again.
- **geoip** downloads happen inside the api container on boot (needs egress);
  progress: `docker compose logs api | grep -i geoip`.

## 7. Verification checklist

```bash
# 7.1 API health through nginx
curl -s http://127.0.0.1/api/v1/health                 # {"status":"ok"}
curl -s http://127.0.0.1/api/v1/health/ready           # status/database/geoip/queue_depth

# 7.2 Login (dashboard + JWT sanity)
curl -s -X POST http://127.0.0.1/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"<OBS_ADMIN_PASSWORD>\"}"

# 7.3 WebSocket (expect HTTP/1.1 101 or an upgrade-capable handshake)
curl -s -i --http1.1 -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Version: 13' \
  "http://127.0.0.1/api/v1/ws/live?token=<JWT>" | head -n 1

# 7.4 Honeypot port banners (host side; after the step-5 cutover)
nc -w2 localhost 22 </dev/null | head -1      # SSH-2.0-OpenSSH_8.9p1... (cowrie)
nc -w2 localhost 23 </dev/null             # telnet negotiation bytes
printf 'USER anon\r\nPASS anon\r\nQUIT\r\n' | nc -w3 localhost 21   # 220 banner + 331/530
nc -w3 localhost 25 </dev/null | head -1     # 220 Microsoft ESMTP...
nc -w3 localhost 110 </dev/null | head -1    # +OK POP3 server ready
nc -w3 localhost 143 </dev/null | head -1    # * OK IMAP4rev1 Server Ready
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:80/   # 200 (snare login portal)

# 7.5 End-to-end pipeline: run one of the above credential attempts, then
curl -s http://127.0.0.1/api/v1/events?limit=5
#    and confirm the event shows up (allow ~10s for fluent-bit flush).
# 7.6 Dashboard: browse to http://<vps>/, log in, check Overview + Live pages.
```

## 8. Backups: cron + restore drill

```bash
chmod +x scripts/backup.sh scripts/restore.sh

# nightly 03:00 backup (matches the in-container daily job; belt and braces)
( crontab -l 2>/dev/null; echo '0 3 * * * cd /opt/observatory && ./scripts/backup.sh >> /var/log/observatory_backup.log 2>&1' ) | crontab -

# list what the api produced so far
docker run --rm -v observatory_backups:/b alpine ls -lh /b

# restore drill (do this once before you need it)
./scripts/restore.sh <file-from-listing>
curl -s http://127.0.0.1/api/v1/health   # api back up with restored data
```

`restore.sh` stops api, validates the archive with duckdb (CHECKPOINT guard),
atomically replaces the DB file and restarts api — no prompts, safe to run from
automation.

## 9. Resource tuning

`docker compose config` shows the caps; typical steady-state RSS on an idle
deployment is roughly half of each cap. Caps (contract §7):

| service    | mem_limit | typical RSS | knob if under pressure                          |
|------------|-----------|-------------|-------------------------------------------------|
| suricata   | 256m      | ~120–180 MB | shrink `stream/flow` memcaps in suricata.yaml   |
| api        | 256m      | ~90–140 MB  | lower `OBS_DB_MEMORY_LIMIT`, `OBS_QUEUE_MAXSIZE`|
| cowrie     | 128m      | ~50–80 MB   | disable telnet in cowrie.cfg                    |
| snare      | 96m       | ~40–70 MB   | —                                               |
| tanner     | 96m       | ~40–60 MB   | —                                               |
| heralding  | 64m       | ~25–40 MB   | disable unused capabilities in config.yaml      |
| fluent-bit | 48m       | ~20–30 MB   | raise Flush interval                            |
| web        | 32m       | ~5–10 MB    | —                                               |

Rules of thumb on 512 MB + 2 GB swap:

- Keep `OBS_RETENTION_DAYS` at 90 or lower (DuckDB size ↔ disk and scan speed).
- If the box swaps heavily, first lower suricata's `flow.memcap` /
  `stream.reassembly.memcap` (32mb → 16mb), then api memory limit.
- `docker stats --no-stream` is your friend; check `dmesg | grep -i oom` after
  any service restart storm.

## 10. Troubleshooting

| symptom | cause / fix |
|---------|-------------|
| `address already in use` on 80/21/22/8888 | something else owns the port: `ss -ltnp 'sport = :<port>'`. For 22 see step 5 — real sshd must be on 22022 before cowrie maps 22. |
| cowrie container exits, logs show permission errors on cowrie.json | the `cowrie-logs` volume was created before correct ownership was initialized; `docker compose down -v` (wipes data!) or `docker compose exec` chown not possible as user cowrie — simplest: `docker volume rm observatory_cowrie-logs && docker compose up -d cowrie`. |
| map/country columns empty, `geoip: disabled` in /health/ready | no `OBS_MAXMIND_LICENSE_KEY` — set it in `.env` and `docker compose up -d api` (recreates; download happens on boot). |
| suricata runs but only baseline alerts, log shows update failure | expected offline; once egress works: `docker compose exec suricata suricata-update && docker compose restart suricata`. |
| SMTP (25/tcp) unreachable from outside but banner works locally | provider-level inbound SMTP filter (common on budget VPS networks). FTP/POP3/IMAP honeypots still capture credentials; check with your provider. |
| disk filling up | `docker builder prune -af` after rebuilds (the frontend build stage cache alone is ~700 MB), `docker image prune -af`, `journalctl --vacuum-size=50M`. The retention job caps the DuckDB file; suricata `eve.json` grows ~10 MB/day under normal scan pressure. |
| suricata errors `eth0: No such device` | your NIC is not `eth0` — change `interface:` in `suricata/suricata.yaml` (`ip -o addr`), then `docker compose restart suricata`. |
| fluent-bit re-ingests old lines after api restart | offsets live in the `fluentbit-db` volume; only reset it (`docker volume rm observatory_fluentbit-db`) if you want a full re-tail from file head — expect duplicate events. |
| events missing for one source | check the file exists on its volume: `docker compose exec fluent-bit ls -l /var/log/honeypot/{cowrie/cowrie.json,snare/snare.log,tanner/tanner.log,heralding/heralding_auth.csv,suricata/eve.json}`; then `docker compose logs api \| grep ingest` for 401 (key mismatch between `.env` and fluent-bit env — recreate both). |
| snare exits with clone failure | site unclonable/egress blocked — set a simpler `SNARE_CLONE_SITE` (static HTML works best), `docker compose up -d snare`. |
| dashboard 502 | api restarting (see `docker compose logs api`); nginx retries DNS per request, it recovers by itself. |
