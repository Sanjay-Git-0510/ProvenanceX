"""The scan-runner service: claims queued scans and runs them through the sandboxed pipeline.

It is the only process that talks to Docker. It has no HTTP port. The API only queues scans.
"""
