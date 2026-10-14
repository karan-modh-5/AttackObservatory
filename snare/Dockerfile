# Attack Observatory — snare image (source install).
# The contract's ghcr.io/mushorg/snare:master image is not publicly pullable
# (registry denies anonymous access), so snare is installed from the upstream
# repository at build time. Debian slim (not alpine): every dependency ships a
# prebuilt manylinux wheel for py3.9, so no gcc/musl compile — the 1 vCPU/10GB
# VPS cannot afford alpine's aiohttp source build (disk + ~10 min CPU).
FROM python:3.9-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth=1 https://github.com/mushorg/snare /opt/snare-src \
    && pip install --no-cache-dir -r /opt/snare-src/requirements.txt \
    && cd /opt/snare-src \
    && python setup.py install \
    && mkdir -p /opt/snare/pages /var/log/honeypot/snare \
    && rm -rf /opt/snare-src

COPY entrypoint.sh /opt/entrypoint.sh

# Bundled fake corporate login portal: installed as the served page when the
# pages volume is fresh (clone remains the fallback for custom SNARE_CLONE_SITE
# deployments). meta.json maps paths -> content files per snare's format.
COPY portal/ /opt/portal/

# Pages are cloned into /opt/snare/pages (snare-pages volume); stdout is teed to
# /var/log/honeypot/snare/snare.log (hp-logs volume) by the entrypoint.
ENTRYPOINT ["/bin/sh", "/opt/entrypoint.sh"]
