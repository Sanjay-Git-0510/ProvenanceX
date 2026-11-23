# Sandbox-only scanning

_Status: master-prompt Phase 1, Milestones A and A.1 (2026-11-18/19), B and C (2026-11-19, C
awaiting review). Downloads run in an isolated fetcher container behind an egress proxy, every
artifact tree lives in a kernel-capped tmpfs staging volume ([fetcher.md](fetcher.md)), `/verify`
re-hashes in a runner-side `rehash` container, Syft runs alone in an `sbom` container and every
analyzer result is cross-checked ([verification.md](verification.md)). See "Not yet sandboxed"._

## The rule

Every step that reads untrusted artifact content runs in a disposable **analyzer container**:

| Step | Where it runs |
|---|---|
| GitHub clone, Hugging Face download | fetcher container, behind the egress proxy ([fetcher.md](fetcher.md)) |
| ZIP extraction (traversal, absolute-path, symlink, bomb, size and file-count checks) | analyzer, `extract` mode, into the kernel-capped staging volume |
| Copy of the analyzed tree into the persistent workspace (for `/verify`) | analyzer, `persist` mode |
| `/verify` re-hash of the kept evidence | analyzer, `rehash` mode (scan workspace read-only), started by the runner |
| Tree SHA-256 (`provenancex-tree-v1`), file list | analyzer, `analyze` mode |
| Manifest and project-package detection | analyzer |
| Syft SBOM generation | analyzer, `sbom` mode, alone (Syft 1.57.0, checksum-pinned in the image) |
| AI-BOM: inventory, pickle opcode scan, safetensors header, configs, model card, custom code | analyzer |
| Static analysis | analyzer |
| Config digest and declared versions (risk inputs) | analyzer |

The API and the scan runner only orchestrate. They hash raw upload bytes, validate the
analyzer's JSON, cross-check it (`app/analysis/consistency.py`), and store it. There is **no disabled mode and no host fallback**. If the analyzer
cannot run, the scan is marked `failed` with `sandbox_unavailable`, nothing is processed, and the
reason is shown in the API and the UI.

## Architecture

```
Frontend -> API (queues only; no Docker, no socket)
              |  Postgres: scan QUEUED
              v
          scan-runner (claims with FOR UPDATE SKIP LOCKED; the only holder of the Docker socket)
              |  docker create -> docker inspect (verify) -> docker start
              v
          analyzer container (per scan, per mode; --rm'd in `finally`)
              |  one JSON document on stdout
              v
          scan-runner: size cap -> strict JSON -> Pydantic schema -> typed decode
                       -> contradiction checks (M4) -> Postgres
```

## Isolation controls, and how each is checked

| Control | Requested (`docker create`) | Checked from outside (`docker inspect`) | Checked from inside (self-check) |
|---|---|---|---|
| No network | `--network=none` | `NetworkMode == none` | only `lo` exists |
| Read-only root | `--read-only` | `ReadonlyRootfs` | `statvfs("/")` is `ST_RDONLY` |
| Non-root | `--user=<workspace owner>` (never 0) | `Config.User` | uid/gid/euid != 0 |
| No capabilities | `--cap-drop=ALL` | `CapDrop` has ALL, no `CapAdd` | CapEff/CapPrm/CapBnd/CapAmb = 0 |
| No privilege gain | `--security-opt=no-new-privileges` | `SecurityOpt` | `NoNewPrivs: 1` |
| No Docker socket | refused anywhere in argv | no mount mentions `docker.sock` | socket paths absent |
| Memory, no swap | `--memory=N --memory-swap=N` | `Memory == MemorySwap == N` | (OOM kill is reported) |
| CPU, pids | `--cpus`, `--pids-limit` | `NanoCpus`, `PidsLimit` | |
| Temp storage | `/tmp` tmpfs `noexec,nosuid,nodev,size=` | `Tmpfs` | |
| Mounts | staging volume read-only for `analyze`/`sbom`/`persist`/`hold`; `extract` writes only staging; `persist` writes only `src`; `rehash` mounts only the scan workspace, read-only; bind sources exactly under `WORKSPACE_ROOT` (L4) | exact mount set, modes, subpaths, `volume-nocopy` | |
| Hardening details (L3) | defaults kept | runtime `runc`, OOM killer on, `/dev/shm` ≤ 64 MiB, masked/read-only paths, `core=0` ulimit only, private cgroupns, no unconfined seccomp/AppArmor/SELinux, no sysctls/devices/ports/DNS, entrypoint | `Seccomp: 2` (`seccomp_filtered`), no secret-like env |
| No IPC/PID/UTS/userns sharing, no devices | `--ipc=none` and nothing else allowed | `IpcMode`, `PidMode`, `UTSMode`, `UsernsMode`, `Devices`, `Binds` | |
| No secrets | no `--env`, request on stdin | `Config.Env` has no secret-like names | |
| No logs kept | `--log-driver=none` | `LogConfig.Type` | |
| Image | `--pull=never`, pinned base digest | image id recorded on the scan | |
| Time | host deadline (timeout + grace), then `docker kill` | | |

`app/analysis/hardening.py` builds the command, re-parses it against an allowlist, and verifies
the created container before it starts. Any mismatch fails the scan with `sandbox_refused`, and
the container never starts. The worker refuses to read the artifact if its own self-check fails.
The runner also refuses any result whose self-check is not fully passing.

Analyzer output is untrusted. Since Milestone B (audit M3) it is a framed stream: a JSON envelope
capped by `ANALYZER_MAX_OUTPUT_MB` (12) and, separately, the raw SBOM (capped by `MAX_SBOM_MB`),
which is spooled to a file and parsed in a memory-limited child process. Oversized frames are
refused from their header. The envelope passes a structural JSON budget before decoding, and the
runner rejects NaN, Infinity, deep nesting and unknown fields. The self-check report must have
exactly the expected keys, each the boolean `true` (audit L2). It validates the result against
`app/sandbox_worker/protocol.py`, then type-checks the AI-BOM and static documents
(`app/analysis/codec.py`) before anything is stored.

## Setup

### Docker Compose (recommended)

```bash
make up            # builds the analyzer image, detects the socket group, starts everything
# or by hand:
docker compose --profile analyzer-image build analyzer-image
export DOCKER_SOCKET_GID=$(stat -c %g /var/run/docker.sock)
docker compose up --build -d
```

- `api` has no socket and no Docker CLI, and sets `SCAN_DISPATCH=runner`.
- `scan-runner` is the only service with `/var/run/docker.sock`. It runs as the non-root `app`
  user with the socket's group, a read-only root, `cap_drop: ALL`, `no-new-privileges`, and no
  ports. The socket is root-equivalent on the host, so keep this service minimal.
- The workspace is the named volume `ANALYZER_WORKSPACE_VOLUME` (default
  `provenancex_workspace`). Analyzer containers mount each scan's own subdirectory with
  `volume-subpath` (Docker Engine API 1.45 or newer).
- A wrong `DOCKER_SOCKET_GID` fails closed: scans fail with "no permission on the Docker socket".

### Runner on the host

```bash
make analyzer-image
cd backend && ANALYZER_WORKSPACE_MOUNT=bind .venv/bin/python -m app.runner   # or: make runner
```

`WORKSPACE_ROOT` must be a host path that the runner's user owns. Analyzer containers run as that
owner's uid (never 0).

### Settings

`ANALYZER_*`, `SCAN_DISPATCH` and `RUNNER_*` are documented in `.env.example`. Two values exist
only for the test suite, and settings validation rejects both unless `APP_ENV=test`:
`ANALYZER_PROVIDER=inprocess_test` and `SCAN_DISPATCH=inline_test`. The in-process executor also
refuses to run outside a pytest test, and the worker entry points refuse to run outside the
container (`app/security/sandbox_guard.py`).

## Runner crashes: claims, heartbeats and orphaned containers

Two findings of the Milestone A security audit are fixed here (Milestone A.1).

**M1: an analyzer container outlived a SIGKILLed runner.** The `finally` that removes the
container never runs when the runner is killed. Now:

- Every analyzer container is labelled `io.provenancex.role=analyzer`,
  `io.provenancex.instance=<ANALYZER_INSTANCE>` (default: the workspace volume name),
  `io.provenancex.scan-id`, `io.provenancex.claim` (the runner's claim token) and
  `io.provenancex.mode`. The labels are part of the `docker create` allowlist and are checked again
  with `docker inspect`, like every other restriction.
- The worker enforces its own limits, passed as `--deadline` (the run's time limit) and
  `--cpu-seconds` (`ceil(ANALYZER_CPUS x limit) + ANALYZER_CPU_GRACE_SECONDS`). PID 1 forks. The
  child works under `RLIMIT_CPU`. At the deadline, the parent kills the child and exits 124, which
  stops the container. This needs nothing from the host. The CPU limit exits 152.
- `app/analysis/reconcile.py` lists only containers that carry this deployment's instance label,
  and removes a container unless its scan is RUNNING under the same claim token with a fresh
  heartbeat. It removes by full container id, and `rm -f` of a container that is already gone is
  harmless. So passes can repeat, and several runners can run them at once. Other Compose
  projects and unlabelled containers are never touched.
- The runner runs recovery at startup and every `RUNNER_RECONCILE_SECONDS` while idle. Recovery
  fails the scans its own identity held before a restart and the stale scans. It then removes
  orphaned containers and the workspaces of the recovered scans. Compose restarts the runner
  (`restart: unless-stopped`). `stop_grace_period` (31m) covers `RUNNER_MAX_SCAN_SECONDS` (30m),
  so a normal stop lets the current scan finish.

**M2: the original runner could overwrite a scan after stale recovery.** Now
(`app/pipeline/ownership.py`):

- A claim gets a fresh `claim_token`, plus `claimed_by` and `heartbeat_at` (migration 0008). A
  heartbeat thread renews `heartbeat_at` every `RUNNER_HEARTBEAT_SECONDS`. A scan is stale after
  `RUNNER_STALE_SECONDS` (at least 3 heartbeats) of silence, or once it is older than
  `RUNNER_MAX_SCAN_SECONDS`. A long scan that keeps heartbeating is never stale before the
  ceiling.
- The runner's session is fenced. Every commit first re-reads the scan row with `SELECT ... FOR
  UPDATE` and is refused (`ClaimLost`) unless the token is still the runner's own. Stale recovery
  replaces the token in its own locked transaction (`FOR UPDATE SKIP LOCKED`). So a write lands
  either before recovery or not at all. The fence covers stage updates, provenance, the risk
  decision, sandbox run records and the blockchain reservation. The reservation is committed
  before anything is sent to the chain, so an old claim can never anchor.
- `mark_completed` and `record_failure` are also conditional UPDATEs (`WHERE claim_token = :t AND
  status = 'running'`), so a terminal state is written once. A runner that loses its claim stops
  its analyzer run, writes nothing more and removes only its own workspace.

## What a scan records

`GET /api/v1/scans/{id}` returns `sandbox.runs[]`, an allowlisted view with no host paths and no
uids. Each run carries: mode, provider, status, `runtime_verified`, the verified limits, the
self-check results, exit code, OOM and timeout flags, and duration. Failed runs are recorded too.

## Tests

| Suite | What it proves | Command |
|---|---|---|
| `tests/security/test_no_host_fallback.py` | A missing analyzer, missing Docker, a missing image or invalid output fails the scan. Spies on every content function prove nothing ran on the host. The API never imports content code. | default suite |
| `tests/unit/test_docker_analyzer.py` | A fake Docker CLI drives each branch: runtime-config drift (10 cases) is refused before start, plus timeout, OOM, oversized or invalid output, failed self-check. Cleanup always runs. | default suite |
| `tests/unit/test_analyzer_hardening.py`, `test_analyzer_output.py`, `test_sandbox_guard.py`, `test_analysis_codec.py`, `test_runner_queue.py` | Allowlist, output validation, guards, lossless decoding, queue claims | default suite |
| `tests/security/test_compose_isolation.py` | Only `scan-runner` mounts the socket. The API image has no Docker CLI. The analyzer image is pinned and non-root. | default suite |
| `tests/unit/test_scan_ownership.py`, `tests/unit/test_analyzer_lifetime.py` | Fencing, conditional transitions, heartbeat, stale and restart recovery, old claims cannot anchor; labels, deadline and CPU-limit allowlist, worker self-limits (real signals), orphan decisions, idempotent and instance-scoped cleanup | default suite |
| `tests/integration/test_scan_ownership_pg.py` | On real PostgreSQL in a throwaway schema: concurrent runners claim each scan once, concurrent recoverers recover once, recovery skips a scan whose owner is committing, an owner's commit waits for recovery and is refused, runner A finishing after runner B's recovery changes nothing, heartbeat on a long scan, anchoring by an old claim | `pytest tests/integration/test_scan_ownership_pg.py` (needs `DATABASE_URL`) |
| `tests/integration/test_runner_kill_live.py` | SIGKILL of a runner mid-analysis on real Docker: the container outlives it, stops at its own deadline, restart recovery removes it and the workspace, other deployments' and unlabelled containers survive, a repeat pass is harmless | `PROVENANCEX_SANDBOX_TESTS=1 pytest tests/integration/test_runner_kill_live.py` |
| `tests/integration/test_analyzer_live.py` | The real image: isolation self-check, traversal, absolute paths, symlinks, bombs, full software and model scans, no leftover containers | `PROVENANCEX_SANDBOX_TESTS=1 pytest tests/integration/test_analyzer_live.py` |
| Milestone B suites | Fetcher, egress proxy, staging, watchdog, L2/L3/M3: see the table in [fetcher.md](fetcher.md#tests) | see fetcher.md |
| Milestone C suites | Verify jobs, rehash, evidence consistency, supply chain: see [verification.md](verification.md#tests) | see verification.md |

## Not yet sandboxed (tracked)

- ~~Downloads~~: done in Milestone B. They run in the fetcher container behind the egress proxy,
  and the runner has no git and no download path ([fetcher.md](fetcher.md)).
- ~~`POST /scans/{id}/verify`~~: done in Milestone C1. The API only queues a job; the runner
  re-hashes in a read-only `rehash` container ([verification.md](verification.md)).
  `test_host_side_code_never_calls_content_functions` now has no exceptions.
- **Behavioral (dynamic) analysis** (`SANDBOX_PROVIDER`) is a separate, optional evidence layer. It
  supports only bind mounts, so it stays `disabled` in the default Compose stack. Turning it off
  does not disable the analyzer. **Opt-in:** `make sandbox-up` adds `docker-compose.sandbox.yml`,
  which gives the api and scan-runner a host workspace directory mounted at the same absolute path
  (owned by uid 999, outside the repo) and sets `SANDBOX_PROVIDER=docker` and
  `ANALYZER_WORKSPACE_MOUNT=bind`. The sandbox hardening is unchanged. Trade-off: untrusted
  artifacts then live in a host directory instead of a Docker-managed volume.
- **ML dataset generation** (`ml/scripts`) still parses the committed benign fixtures directly. It
  never touches scanned artifacts.
