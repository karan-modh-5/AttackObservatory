#!/usr/bin/env bash
# Host-side backup driver for Attack Observatory.
#
# Runs the api container's backup routine (DuckDB CHECKPOINT + gzip copy into
# the `backups` volume, contract §8). Safe to run from cron while the stack is
# up; it never stops any service.
#
# Install (root cron):
#   0 3 * * * cd /opt/observatory && ./scripts/backup.sh >> /var/log/observatory_backup.log 2>&1
#
# Restore with: ./scripts/restore.sh <backup-file>

set -euo pipefail

cd "$(dirname "$0")/.."

if ! docker compose ps --status running --services api 2>/dev/null | grep -qx api; then
    echo "ERROR: api service is not running - start the stack first: docker compose up -d" >&2
    exit 1
fi

echo "[backup] $(date -u '+%Y-%m-%dT%H:%M:%SZ') starting in-container backup"
docker compose exec -T api python -m app.backup
echo "[backup] done - archives are in the 'backups' volume (host: docker volume inspect observatory_backups)"
