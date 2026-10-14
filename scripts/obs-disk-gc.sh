#!/bin/sh
# Attack Observatory disk guard: runs daily via cron.
# - prunes build cache + dangling/unused images + stopped containers
# - truncates container stdout logs over 50MB
# - deletes rotated honeypot logs older than 3 days (raw logs are already
#   parsed into DuckDB; deleting them loses nothing the dashboard shows)
# - vacuums journal to 10MB
# If usage is still above 90%, force-prunes ALL unused images (rebuildable).
PCT=$(df / | awk 'NR==2 {gsub("%","",$5); print $5}')
docker builder prune -af >/dev/null 2>&1
docker container prune -f >/dev/null 2>&1
find /var/lib/docker/containers -name '*-json.log' -size +50M -exec truncate -s 0 {} \; 2>/dev/null
find /var/lib/docker/volumes/observatory_cowrie-logs/_data -name 'cowrie.json.2026-*' -mtime +3 -delete 2>/dev/null
find /var/lib/docker/volumes/observatory_suricata-logs/_data -name 'eve.json.*' -mtime +3 -delete 2>/dev/null
journalctl --vacuum-size=10M >/dev/null 2>&1
if [ "$PCT" -ge 90 ]; then
    docker image prune -a -f >/dev/null 2>&1
fi
echo "$(date -u) disk=${PCT}%" >> /var/log/obs-gc.log
