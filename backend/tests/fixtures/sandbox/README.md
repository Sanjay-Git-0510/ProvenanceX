# Sandbox trace fixtures (SYNTHETIC)

Every `*.trace.json` file here is **synthetic**. They were written by hand for the telemetry parser
tests. They are not output from a real sandbox run, and they do not describe any real package or
model. Each one carries `"synthetic": true`. No result derived from them may be presented as real.

IP addresses are arbitrary public-range values used only as text. Nothing connects to them.

- `benign_run.trace.json`: a quiet run with a local write and a failed loopback connect
- `network_beacon.trace.json`: failed connects to public addresses, plus an unfinished/resumed call
- `credential_probe.trace.json`: opens sensitive paths and starts a shell
- `resource_spike.trace.json`: a timed-out run with memory and pids at the limit
