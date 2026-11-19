# ProvenanceX egress proxy: the only way out of the internal fetch network (Milestone B).
# Standard library only: no third-party packages at all.
#
# Build (from the repo root):
#   docker build -f docker/egress-proxy/Dockerfile -t provenancex-egress-proxy:0.1.0 backend
# Compose builds it as the `egress-proxy` service. It runs read-only, non-root, with every
# capability dropped, on the fetch network (internal) and its own egress network only; it is
# never attached to the network that holds Postgres, the API or the chain.
FROM python:3.12.8-slim-bookworm@sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Only the proxy package (and the empty top-level package marker).
COPY app/__init__.py /opt/px/app/__init__.py
COPY app/egress_proxy /opt/px/app/egress_proxy
RUN chmod -R a-w,a+rX /opt/px \
    && cd /opt/px && python -B -c "import app.egress_proxy.server, app.egress_proxy.__main__"

USER 65534:65534
WORKDIR /opt/px
EXPOSE 3128
ENTRYPOINT ["python", "-B", "-m", "app.egress_proxy"]
