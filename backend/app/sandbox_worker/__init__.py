"""Code that runs inside the disposable analyzer container.

Everything that reads untrusted artifact content (archive extraction, tree hashing, manifest
detection, Syft, AI-BOM, pickle/safetensors parsing, static analysis) is driven from here. The
host side (the scan-runner) only launches the container, validates the JSON it prints and
stores the result. Nothing in this package touches the database or the network.
"""
