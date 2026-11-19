"""The fetcher worker: runs inside the isolated fetcher container (docker/fetcher).

It downloads a GitHub repository or Hugging Face model into the scan's kernel-capped staging
volume through the egress proxy, and prints a small framed manifest. It has no Docker socket,
no database or chain credentials and no API keys (docs/security/fetcher.md).
"""
