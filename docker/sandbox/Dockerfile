# ProvenanceX disposable analysis sandbox.
#
# Build:  docker build -t provenancex-sandbox:0.1.0 docker/sandbox
#
# The image holds no secrets and no application code other than the supervisor. The
# runtime restrictions (no network, read-only filesystem, cap-drop ALL and so on) are
# applied by backend/app/scanners/sandbox/hardening.py at `docker run` time.
FROM python:3.12.8-slim-bookworm@sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/tmp

# strace records behavior. setuptools is what a setup.py target imports.
RUN apt-get update \
    && apt-get install -y --no-install-recommends strace=6.1-0.1 \
    && rm -rf /var/lib/apt/lists/* \
    && printf '%s\n' \
       "setuptools==75.8.0 --hash=sha256:e3982f444617239225d675215d51f6ba05f845d4eec313da4418fdbb56fb27e3" \
       > /tmp/req.txt \
    && pip install --require-hashes --no-deps -r /tmp/req.txt \
    && rm /tmp/req.txt

COPY supervisor.py /opt/px/supervisor.py
RUN chmod 0555 /opt/px /opt/px/supervisor.py

# I1: strip setuid/setgid bits (su, mount, passwd, ...); nothing here ever needs them.
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + \
    && ! find / -xdev -perm /6000 -type f | grep -q .

# The real uid comes from `docker run --user` and is never 0.
USER 65534:65534
WORKDIR /tmp
ENTRYPOINT ["python", "-B", "/opt/px/supervisor.py"]
