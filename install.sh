#!/usr/bin/env bash
# =============================================================================
# Attack Observatory — one-shot installer for a fresh Ubuntu 24.04 VPS.
#
# Target capacity: 1 vCPU, 512MB-1GB RAM, 10GB+ SSD (works exactly as deployed;
# see docs/DEPLOYMENT.md for the manual equivalent of every step).
#
# What it does:
#   1. Creates swap (the box cannot survive traffic bursts without it)
#   2. Installs Docker Engine + compose plugin
#   3. Generates .env with fresh random secrets (never committed to git)
#   4. Builds the React frontend inside a throwaway node container
#      (npm never installs on the host filesystem)
#   5. Builds + starts the full stack: web, api, fluent-bit, cowrie, snare,
#      tanner, heralding, suricata
#   6. Waits for health and prints your dashboard URL + admin credentials
#
# Usage (as root, from the repository root):
#   bash install.sh                    # normal install
#   bash install.sh --rebuild-frontend # force a fresh frontend build
#
# SSH-on-port-22 note: cowrie (the SSH honeypot) is mapped to host port 22 by
# docker-compose.override.yml. If your sshd still listens on 22, the installer
# moves that override aside so the stack starts safely, and prints the steps to
# cut over later (honeypot on 22 = the real bait).
# =============================================================================
set -euo pipefail

REBUILD_FRONTEND=0
[ "${1:-}" = "--rebuild-frontend" ] && REBUILD_FRONTEND=1

cd "$(dirname "$0")"
[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root (sudo bash install.sh)"; exit 1; }
[ -f docker-compose.yml ] || { echo "ERROR: run from the repository root"; exit 1; }

step() { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }

# ---------------------------------------------------------------------------
step "1/8 Swap (required: the stack OOMs without it on <=1GB RAM)"
mem_mb=$(free -m | awk '/^Mem:/{print $2}')
swap_mb=$(free -m | awk '/^Swap:/{print $2}')
if [ "$swap_mb" -lt 512 ]; then
    warn "swap is ${swap_mb}MB — creating a 2GB swapfile"
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile
    grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    sysctl -q vm.swappiness=20
else
    echo "swap already ${swap_mb}MB — ok"
fi
sysctl -q vm.swappiness=20
# Stop Ubuntu's periodic upgrade prober: it D-states under memory pressure and
# was observed pinning the box at load 3+ on the reference deployment.
systemctl disable --now update-notifier-download.timer 2>/dev/null || true

# ---------------------------------------------------------------------------
step "2/8 Docker Engine + compose plugin"
if ! command -v docker >/dev/null 2>&1; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io docker-compose-v2 >/dev/null
fi
systemctl enable --now docker >/dev/null 2>&1 || true
docker compose version

# ---------------------------------------------------------------------------
step "3/8 .env with fresh secrets"
if [ -f .env ]; then
    echo ".env already exists — keeping it (secrets unchanged)"
else
    cp .env.example .env
    sed -i "s|^OBS_SECRET_KEY=.*|OBS_SECRET_KEY=$(openssl rand -hex 32)|"  .env
    sed -i "s|^OBS_ADMIN_PASSWORD=.*|OBS_ADMIN_PASSWORD=$(openssl rand -hex 16)|" .env
    sed -i "s|^OBS_INGEST_API_KEY=.*|OBS_INGEST_API_KEY=$(openssl rand -hex 32)|"  .env
    echo "generated .env with random secrets (file is gitignored — back it up)"
fi

# ---------------------------------------------------------------------------
step "4/8 Port 22 check (SSH honeypot cutover)"
if ss -ltn 'sport = :22' | grep -q ':22'; then
    if grep -q ':22:2222' docker-compose.override.yml 2>/dev/null; then
        mv docker-compose.override.yml docker-compose.override.yml.disabled
        warn "your sshd owns port 22 — cowrie will serve 2222/2323 instead for now"
        warn "to put the honeypot on 22 later (the real bait):"
        warn "  1) add 'Port 22022' to /etc/ssh/sshd_config, ufw allow 22022, restart ssh"
        warn "  2) remove Port 22 from sshd_config, restart ssh"
        warn "  3) mv docker-compose.override.yml.disabled docker-compose.override.yml && docker compose up -d cowrie"
    fi
else
    echo "port 22 free — cowrie will own it via docker-compose.override.yml"
fi

# ---------------------------------------------------------------------------
step "5/8 Frontend build (inside a throwaway node container)"
if [ ! -f frontend/dist/index.html ] || [ "$REBUILD_FRONTEND" -eq 1 ]; then
    docker run --rm \
        -e NODE_OPTIONS=--max-old-space-size=1024 \
        -v "$PWD/frontend":/app \
        -w /app \
        node:22-alpine \
        sh -c "npm ci --no-audit --no-fund && npm run build"
    echo "frontend/dist built"
else
    echo "frontend/dist exists — skipping (use --rebuild-frontend to force)"
fi

# ---------------------------------------------------------------------------
step "6/8 Build + start the stack (8 services)"
docker compose build
docker compose up -d

# ---------------------------------------------------------------------------
step "7/8 Waiting for the api to become healthy"
probe="http://127.0.0.1:8888/api/v1/health/ready"
for i in $(seq 1 40); do
    body=$(curl -s --max-time 5 "$probe" || true)
    echo "$body" | grep -q '"status":"ok"' && { echo "healthy after $i checks"; break; }
    [ "$i" -eq 40 ] && { echo "ERROR: api did not become healthy — check: docker compose logs api"; exit 1; }
    sleep 10
done

# ---------------------------------------------------------------------------
step "8/8 Firewall reminder (run only the ports you want public)"
cat <<'EOF'
  ufw allow 8888/tcp    # dashboard + api
  ufw allow 80/tcp      # web honeypot
  ufw allow 22/tcp      # SSH honeypot (after the sshd cutover)
  ufw allow 23/tcp      # Telnet honeypot
  ufw allow 21/tcp 25/tcp 110/tcp 143/tcp   # FTP/SMTP/POP3/IMAP honeypots
EOF

admin_pw=$(grep '^OBS_ADMIN_PASSWORD=' .env | cut -d= -f2)
ip=$(curl -s --max-time 5 https://ifconfig.me || hostname -I | awk '{print $1}')
cat <<EOF

============================================================
 Attack Observatory is up.

 Dashboard : http://${ip}:8888
 Login     : admin
 Password  : ${admin_pw}   (also in .env — keep it, it is not in git)

 Honeypots : SSH 22 · Telnet 23 · HTTP 80 · FTP 21 · SMTP 25
             POP3 110 · IMAP 143 · network IDS (host mode)
 Logs      : docker compose logs -f <service>
 Stop      : docker compose down        (data volumes survive)
============================================================
EOF
