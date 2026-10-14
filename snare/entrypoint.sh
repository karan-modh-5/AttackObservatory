#!/bin/sh
# Snare entrypoint.
# 1. Clone $SNARE_CLONE_SITE on first start (3 attempts, 30s apart; hard exit on
#    total failure so the failure is visible in `docker compose logs snare`).
# 2. Strip response-framing headers the cloner replayed into meta.json
#    (aiohttp adds its own Transfer-Encoding; a cloned `chunked` or a stale
#    Content-Length makes every client mis-parse the body).
# 3. Serve the cloned page on 8080, forwarding detections to tanner:8090.
# 4. Tee stdout into the shared hp-logs volume: /var/log/honeypot/snare/snare.log
set -u

PAGES_ROOT=/opt/snare/pages
PAGE_DIR="$PAGES_ROOT/$SNARE_PAGE_NAME"
LOG_DIR=/var/log/honeypot/snare

mkdir -p "$LOG_DIR"

if [ ! -f "$PAGE_DIR/meta.json" ] && [ ! -f "$PAGE_DIR/index.html" ]; then
    if [ -f /opt/portal/meta.json ]; then
        echo "[snare] installing bundled login portal as page '$SNARE_PAGE_NAME'"
        mkdir -p "$PAGES_ROOT"
        cp -r /opt/portal "$PAGE_DIR"
    else
        echo "[snare] page '$SNARE_PAGE_NAME' not found under $PAGES_ROOT - cloning $SNARE_CLONE_SITE"
        attempt=1
        ok=0
        while [ "$attempt" -le 3 ]; do
            echo "[snare] clone attempt $attempt/3"
            # clone saves to <path>/snare/pages/<root-host>; --path /opt puts pages
            # in /opt/snare/pages, which is exactly where snare --page-dir looks.
            if clone --path /opt --target "$SNARE_CLONE_SITE"; then
                ok=1
                break
            fi
            attempt=$((attempt + 1))
            [ "$attempt" -le 3 ] && sleep 30
        done
        if [ "$ok" -ne 1 ]; then
            echo "[snare] FATAL: could not clone $SNARE_CLONE_SITE after 3 attempts." >&2
            echo "[snare] Set SNARE_CLONE_SITE to a reachable site (check egress/DNS) and restart." >&2
            exit 1
        fi
    fi
fi

if [ ! -d "$PAGE_DIR" ]; then
    echo "[snare] FATAL: pages exist but not as '$SNARE_PAGE_NAME'." >&2
    echo "[snare] SNARE_PAGE_NAME must equal the root host of SNARE_CLONE_SITE (e.g. https://example.com/ -> example.com)." >&2
    echo "[snare] Available page dirs:" >&2
    ls -1 "$PAGES_ROOT" >&2 || true
    exit 1
fi

# Snare replays the cloned site's response headers from meta.json. Framing
# headers must not be replayed: aiohttp applies its own Transfer-Encoding and
# the stored Content-Length no longer matches the served (dork-processed) body.
python3 - "$PAGE_DIR/meta.json" <<'EOF'
import json
import sys

path = sys.argv[1]
try:
    with open(path) as fh:
        meta = json.load(fh)
except (FileNotFoundError, json.JSONDecodeError):
    raise SystemExit(0)

changed = False
for entry in meta.values():
    headers = entry.get("headers")
    if not headers:
        continue
    kept = [
        h for h in headers
        if not any(k.lower() in ("transfer-encoding", "content-length") for k in h)
    ]
    if len(kept) != len(headers):
        entry["headers"] = kept
        changed = True

if changed:
    with open(path, "w") as fh:
        json.dump(meta, fh)
    print("[snare] stripped framing headers from meta.json")
EOF

# PYTHONUNBUFFERED keeps the tee'd log live instead of block-buffered.
export PYTHONUNBUFFERED=1

# snare writes per-request lines to its own file (/opt/snare/snare.log), not to
# stdout. Forward the aiohttp access lines into the fluent-bit-watched file in
# the hp-logs volume; non-matching snare lines stay out of the ingest stream.
snare --host-ip 0.0.0.0 --port 8080 --tanner tanner \
    --page-dir "$SNARE_PAGE_NAME" --no-dorks true --auto-update false \
    2>&1 | tee -a "$LOG_DIR/snare.log" &
SNARE_PID=$!

# BusyBox grep lacks --line-buffered; a read loop is line-flushed by POSIX
# semantics and filters without GNU flags.
tail -F -n 0 /opt/snare/snare.log 2>/dev/null | while IFS= read -r line; do
    case "$line" in
        *aiohttp.access:log:*) printf '%s\n' "$line" >> "$LOG_DIR/snare.log" ;;
    esac
done &
TAIL_PID=$!

# Container lifetime follows the honeypot, not the log forwarder.
wait "$SNARE_PID"
