#!/bin/sh
# Tanner entrypoint: start the in-container redis session store, then run tanner
# with stdout teed into the shared hp-logs volume
# (/var/log/honeypot/tanner/tanner.log -> fluent-bit).
set -eu

mkdir -p /var/log/honeypot/tanner /tmp/tanner/emulators /var/lib/tanner

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

export PYTHONUNBUFFERED=1

exec /opt/tanner/tanner-env/bin/tanner --config /opt/tanner/tanner/data/config.yaml \
    2>&1 | tee -a /var/log/honeypot/tanner/tanner.log
