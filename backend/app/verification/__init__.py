"""Asynchronous verification jobs (Milestone C1, audit finding M5).

jobs.py      the queue: enqueue (API), claim, heartbeat, fenced finish and stale recovery (runner)
executor.py  runs one claimed job in the scan-runner: rehash container, chain read, comparison
"""
