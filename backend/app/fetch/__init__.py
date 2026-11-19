"""Runner side of the isolated fetcher (Milestone B, audit finding H1).

The scan-runner orchestrates downloads but never performs or parses them: it creates a
hardened, per-scan fetcher container on the internal fetch network, verifies it with
`docker inspect`, feeds it a request and validates its small framed manifest.
"""
