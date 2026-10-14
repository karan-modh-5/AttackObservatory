#!/usr/bin/env bash
# Host-side restore for Attack Observatory.
#
# Usage:   ./scripts/restore.sh <backup-file>
# Example: ./scripts/restore.sh backups/observatory_20260109T030000.duckdb.gz
#
# What it does (no interactive prompts):
#   1. validates the gzip archive locally,
#   2. stops the api service (the DuckDB writer lock holder),
#   3. copies the archive into the api container,
#   4. gunzips to a staging file, validates it by opening with duckdb and
#      running CHECKPOINT, then atomically os.replace()s it over the live DB,
#   5. restarts the api service (also on failure, so the old DB stays serving).
#
# Run as a user in the `docker` group (or root).

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <backup-file>   (a gzip archive produced by scripts/backup.sh)" >&2
    exit 1
fi

BACKUP="$1"
if [ ! -f "$BACKUP" ]; then
    echo "ERROR: backup file not found: $BACKUP" >&2
    exit 1
fi
if ! gzip -t "$BACKUP" 2>/dev/null; then
    echo "ERROR: not a valid gzip archive: $BACKUP" >&2
    exit 1
fi

cd "$(dirname "$0")/.."

if ! docker compose ps --all --services api 2>/dev/null | grep -qx api; then
    echo "ERROR: api container does not exist - run 'docker compose up -d' once first" >&2
    exit 1
fi

echo "[restore] stopping api (releases the DuckDB writer lock)"
trap 'docker compose start api >/dev/null 2>&1 || true' EXIT
docker compose stop api

echo "[restore] copying archive into the api container"
docker compose cp "$BACKUP" api:/tmp/restore_backup.gz

echo "[restore] validating archive and swapping database atomically"
if docker compose run --rm --no-deps -T api python - <<'PY'
import gzip
import os
import shutil

import duckdb

src = "/tmp/restore_backup.gz"
db_path = os.environ.get("OBS_DB_PATH", "/data/observatory.duckdb")
staged = db_path + ".restore-staging"

with gzip.open(src, "rb") as f, open(staged, "wb") as out:
    shutil.copyfileobj(f, out, length=1024 * 1024)

con = duckdb.connect(staged)
con.execute("CHECKPOINT")
tables = con.execute("SELECT count(*) FROM duckdb_tables()").fetchone()[0]
events = con.execute(
    "SELECT count(*) FROM duckdb_tables() WHERE table_name = 'events'"
).fetchone()[0]
con.close()

if not events:
    raise SystemExit("staged database has no events table - refusing restore")

os.replace(staged, db_path)
print(f"restore complete: {db_path} ({tables} tables, events table present)")
PY
then
    echo "[restore] success - starting api"
    docker compose start api
    docker compose exec -T api rm -f /tmp/restore_backup.gz || true
    echo "[restore] done - verify with: curl -s http://127.0.0.1/api/v1/health"
else
    echo "ERROR: restore failed - api was restarted with the previous database intact" >&2
    docker compose start api
    exit 1
fi
