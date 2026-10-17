# Attack Observatory — tanner image (source install + in-container redis).
# Two deviations from the contract's `ghcr.io/mushorg/tanner:master`, both
# forced by reality and documented in docs/ARCHITECTURE.md §7:
#   1. that image is not publicly pullable (registry denies anonymous access),
#      so tanner is installed from the upstream repository at build time on the
#      same alpine 3.15 base upstream's own Dockerfile uses (Python 3.10 — the
#      newest that supports the pinned aioredis/MarkupSafe versions);
#   2. tanner requires redis for session state and the contract fixes the stack
#      at 8 services, so redis-server is bundled and bound to loopback only.
FROM alpine:3.15

RUN apk add --no-cache git build-base libffi-dev libressl-dev linux-headers python3 python3-dev py3-pip redis \
    && git clone --depth=1 https://github.com/mushorg/tanner /opt/tanner \
    && python3 -m venv /opt/tanner/tanner-env \
    && /opt/tanner/tanner-env/bin/pip install --no-cache-dir wheel \
    && /opt/tanner/tanner-env/bin/pip install --no-cache-dir -r /opt/tanner/requirements.txt \
    && cd /opt/tanner \
    && /opt/tanner/tanner-env/bin/python setup.py install \
    && mkdir -p /opt/tanner/data /tmp/tanner/emulators /var/lib/tanner /var/log/honeypot/tanner \
    && rm -f /opt/tanner/db/GeoLite2-City.mmdb

# TannerConfig reads /opt/tanner/data/config.yaml at import time and the CLI
# takes --config /opt/tanner/tanner/data/config.yaml; keep both copies identical.
COPY config.yaml /opt/tanner/data/config.yaml
COPY config.yaml /opt/tanner/tanner/data/config.yaml

COPY entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]