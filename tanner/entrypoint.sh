#!/bin/sh
# Tanner entrypoint: start the in-container redis session store, then run tanner
# with stdout teed into the shared hp-logs volume
# (/var/log/honeypot/tanner/tanner.log -> fluent-bit).
set -eu

mkdir -p /var/log/honeypot/tanner /var/lib/tanner

# Tanner writes its debug log, error log AND the per-request detection report
# (tanner_report.json — the sqli/lfi/rfi/xss verdicts fluent-bit ships to the
# api) into /tmp/tanner/, which is ephemeral: every restart wiped the evidence.
# Bind the directory onto the shared hp-logs volume instead.
rm -rf /tmp/tanner
ln -s /var/log/honeypot/tanner /tmp/tanner
mkdir -p /tmp/tanner/emulators

redis-server --bind 127.0.0.1 --port 6379 \
    --daemonize yes --save "" --appendonly no \
    --dir /var/lib/tanner --logfile /var/lib/tanner/redis-server.log

ready=0
i=1
while [ "$i" -le 30 ]; do
    if redis-cli -h 127.0.0.1 -p 6379 ping 2>/dev/null | grep -q PONG; then
        ready=1
        break
    fi
    i=$((i + 1))
    sleep 1
done
if [ "$ready" -ne 1 ]; then
    echo "[tanner] FATAL: in-container redis did not become ready" >&2
    cat /var/lib/tanner/redis-server.log >&2 || true
    exit 1
fi
echo "[tanner] redis ready on 127.0.0.1:6379"

# Download the GeoLite2-City.mmdb at runtime (the image strips the 600 MB
# baked-in copy to fit disk limits); tanner uses it only for geo on session
# pages, not for detection.
if [ ! -s /opt/tanner/db/GeoLite2-City.mmdb ]; then
    echo "[tanner] downloading GeoLite2-City.mmdb ..."
    wget -q -O /opt/tanner/db/GeoLite2-City.mmdb \
        "https://github.com/P3ter04/ip.neuron.gitlab.io/raw/master/geoip/GeoLite2-City.mmdb" \
        2>/dev/null || echo "[tanner] WARN: GeoLite2 download failed (geo features disabled)"
fi

export PYTHONUNBUFFERED=1

exec /opt/tanner/tanner-env/bin/tanner --config /opt/tanner/tanner/data/config.yaml \
    2>&1 | tee -a /var/log/honeypot/tanner/tanner.log