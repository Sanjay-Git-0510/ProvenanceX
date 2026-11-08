# ML dataset seeds

Text templates for the synthetic dataset generator (`app/ml/dataset`). They are written to a
temporary directory as `.py` files and only **parsed** by the static scanners. They are never
imported or run. The `.txt` suffix keeps them away from pytest collection and ruff.

- `benign_module.py.txt`: ordinary application code.
- `benign_tooling.py.txt`: legitimate developer tooling that uses `subprocess`. It exists so
  that using such an API does not perfectly predict a suspicious label.
- `inert_suspicious.py.txt`: harmless patterns that static rules flag. It holds no payload, and
  its only address is `192.0.2.1` (TEST-NET-1, reserved and not routable).
- `inert_setup_hook.py.txt`: a `setup.py` install hook whose body does nothing harmful.

This directory holds no malware, real samples, secrets or tokens.
