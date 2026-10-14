FROM python:3.8-slim
# heralding 1.0.7 uses asyncio.Task.all_tasks() (removed in Python 3.9), so the
# newest base it actually runs on is Python 3.8. Project code (§9) stays 3.12;
# this pin is third-party-imposed, not a project standard.

# psycopg2 (a heralding dependency) builds from source and needs libpq headers.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Heralding ships only as an sdist whose setup.py bootstraps setuptools through
# a 2014-era ez_setup download that fails on modern Python — even `pip download`
# cannot read its metadata. Fetch the sdist directly, strip the bootstrap, and
# pip-install the patched source.
RUN python -c "import json,pathlib,tarfile,urllib.request as u; d=json.load(u.urlopen('https://pypi.org/pypi/heralding/json')); url=next(x['url'] for x in d['urls'] if x['filename'].endswith('.tar.gz')); pathlib.Path('/tmp/h.tar.gz').write_bytes(u.urlopen(url).read()); tarfile.open('/tmp/h.tar.gz').extractall('/tmp/hs',filter='data'); p=next(pathlib.Path('/tmp/hs').rglob('setup.py')); t=p.read_text(); p.write_text(t.replace('from ez_setup import use_setuptools','').replace('use_setuptools()  # NOQA','')); print('patched',p)"

RUN pip install --no-cache-dir /tmp/hs/Heralding-1.0.7 \
    && rm -rf /tmp/hs /tmp/h.tar.gz

COPY config.yaml /etc/heralding/config.yaml

# The auth CSV lives here (heralding-logs volume mounts over it in compose).
RUN mkdir -p /var/log/heralding

# Operational log goes to container-local /tmp; the auth CSV (the artifact
# fluent-bit ships to the api) lives on the heralding-logs volume.
CMD ["heralding", "--config", "/etc/heralding/config.yaml", "-l", "/tmp/heralding.log"]
