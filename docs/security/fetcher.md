# Isolated downloads, egress proxy and kernel-capped storage (Milestone B)

_Status: implemented 2026-11-19, uncommitted, awaiting owner review. Milestone C is not started._

This document covers audit finding **H1** (Git and Hugging Face downloads ran inside the
scan-runner, which holds the Docker socket and the deployment's secrets), the follow-up
findings **L1** (bypassable extraction limit), **L2** (self-check validation), **L3**
(incomplete `docker inspect` verification) and **M3** (analyzer-output memory amplification),
and the hung-download recovery gap. It extends [sandbox.md](sandbox.md).

## Architecture

```
API (queues only) ── Postgres ── scan-runner (Docker socket; no git, no download client)
                                    │ docker volume create  px-stg-<scan>  (tmpfs, size=STAGING_MB)
                                    │ docker create/inspect/start
                                    ▼
      ┌──────── holder container (analyzer image, `hold` mode): keeps the tmpfs mounted ────────┐
      │                                                                                         │
      │  fetcher container (per scan)       network: <project>_fetch  (Docker `internal`)      │
      │    git / Hugging Face client  ──CONNECT──►  egress-proxy  ──►  <project>_egress ──► internet
      │    writes ONLY /out/src = px-stg-<scan> (kernel-capped)                                 │
      │                                                                                         │
      │  analyzer `analyze` (network none): reads px-stg-<scan> read-only, returns framed result │
      │  analyzer `persist` (network none): copies px-stg-<scan> → workspace/<scan>/src         │
      └─────────────────────────────────────────────────────────────────────────────────────────┘
                                    ▼
          scan-runner: validates the small manifests, never opens the downloaded files
```

Sequence for a GitHub or Hugging Face scan (`app/pipeline/software.py`, `model.py`,
`sandboxed.py`):

1. The runner re-validates the URL (syntax and DNS) and creates the scan's staging volume, after
   admission against the RAM budget (`STAGING_TOTAL_MB`).
2. It starts the **holder**. Docker unmounts a tmpfs volume, and its data is lost, as soon as no
   container uses it (verified on this machine), so a holder keeps it mounted for the whole scan.
   The holder reads nothing and stops by itself at `RUNNER_MAX_SCAN_SECONDS`.
3. The **fetcher** downloads through the egress proxy into the staging volume and prints a framed
   manifest: commit SHA, Hub listing, verified per-file hashes, file count and bytes.
4. The analyzer **analyzes** the staging volume read-only (tree digest, Syft, AI-BOM, static).
5. The analyzer **persists** the tree into the persistent workspace (for `POST /verify`), and the
   runner requires the persisted digest to equal the analyzed digest
   (`download_integrity_error` otherwise).
6. Holder and staging volume are removed in a `finally`, whatever happened.

Uploads use the same staging flow: `extract` writes the ZIP's contents into the staging volume
instead of the workspace.

## The fetcher (`docker/fetcher`, `app/fetch_worker`, `app/fetch`)

| Control | How it is enforced | How it is verified |
|---|---|---|
| No Docker socket | never in argv (allowlist refuses any `docker.sock` token) | `docker inspect` (whole document), self-check `no_docker_socket` |
| No secrets | no `--env` flag is allowed at all; the request (proxy URL, limits) travels on stdin; the image holds no secrets | inspect `Config.Env` (no secret-like or `*_PROXY` names), self-check `no_secret_env` |
| Non-root | `--user=<workspace owner uid>` (never 0) | inspect `Config.User`, self-check `non_root` |
| Read-only root, noexec `/tmp` | `--read-only`, `--tmpfs /tmp:rw,noexec,nosuid,nodev,size=` | inspect `ReadonlyRootfs`, `Tmpfs`; self-check `rootfs_read_only` |
| Capabilities, privileges | `--cap-drop=ALL`, `--security-opt=no-new-privileges` | inspect; self-check `capabilities_dropped`, `no_new_privileges`, `seccomp_filtered` |
| Network | `--network=<FETCHER_NETWORK>` only; `none`, `host`, `bridge`, `container:` refused | inspect `NetworkMode` and `NetworkSettings.Networks`; `docker network inspect` must show `Internal: true`; self-check `single_interface`, `direct_egress_blocked`, `external_dns_blocked` |
| Storage | the only mount is the scan's own staging volume (`volume-nocopy`) | inspect `Mounts` (exactly one, this scan's volume) |
| Resources | `--memory` = `--memory-swap`, `--cpus`, `--pids-limit`, `--ulimit core=0`, in-container deadline and `RLIMIT_CPU` | inspect; L3 checks below |
| Time | in-container deadline (`fetch_timeout_seconds` = source budget + `FETCHER_SETUP_SECONDS`), host deadline + `FETCHER_HOST_GRACE_SECONDS`, runner watchdog | unit and live tests |
| Concurrency | at most `FETCHER_MAX_CONCURRENT` fetcher containers per deployment (PostgreSQL advisory lock around count + create) | unit test |

The worker runs its self-check **before** reading the request's URL or opening any connection.
The fetcher's self-check proves from inside the kernel that a direct TCP connection to a public
address fails and that external DNS does not resolve. The runner accepts the result only if the
report has exactly the `FETCHER_CHECKS` keys, each the boolean `true` (L2).

Inside the fetcher, git runs as before (depth 1, no submodules, hooks off, symlinks as files,
no redirects, no credential helper), with `http.proxy` set to the egress proxy. After the commit
is confirmed, `.git` is deleted: the tree digest excludes it, and git metadata never reaches the
analyzer. The Hugging Face client is the same capped, hash-verifying client. Each redirect hop
must be on the code's exact Hugging Face host list **and** on `EGRESS_ALLOWED_HOSTS`. The
former `*.hf.co` wildcard was removed.

The runner never downloads. `git_fetch.clone_repository`, `HuggingFaceProvider.fetch`,
`MockHfProvider.fetch` and `fetch_worker.run.run_fetch` call `require_fetch_context()`, which
passes only inside the fetcher container (`PX_FETCH_WORKER=1` plus `/.dockerenv`) or inside a
pytest-only test context. `git` was removed from the API and runner image. A static test fails if
any module under `api`, `pipeline`, `runner`, `analysis`, `fetch`, `blockchain` or `risk` calls
or imports download code (except the pytest-only in-process fetcher).

## The egress proxy (`docker/egress-proxy`, `app/egress_proxy`)

A small asyncio CONNECT proxy using only the Python standard library. It is the only member of
the `fetch` network besides fetchers, and it is attached to its own `egress` network, never to the
default network that holds Postgres, the API and the chain.

Per connection:

1. Read the request head (8 KiB max, 10 s). Only `CONNECT host:port` is accepted. Plain-HTTP
   proxying returns 405, so the proxy serves HTTPS tunnels only.
2. The host must exactly match `EGRESS_ALLOWED_HOSTS` (case-insensitive). There are no
   wildcards. IP literals, trailing dots, userinfo and single-label names (`postgres`, `api`,
   `localhost`) are refused, and the port must be 443. Refusals happen before any DNS lookup.
3. The name is resolved **once**. If **any** address is not public, the tunnel is refused.
   Refused ranges: RFC 1918, ULA, loopback, link-local (169.254.169.254 and `fd00:ec2::254`
   metadata), CGNAT, multicast, reserved, benchmarking and documentation ranges, and the IPv6
   transition forms that can embed an internal IPv4 address (IPv4-mapped, NAT64, 6to4, Teredo).
4. The proxy connects to an address it validated. It never re-resolves, and the client never
   supplies an IP, so DNS rebinding cannot swap the destination.
5. It relays bytes with an idle timeout (`EGRESS_IDLE_TIMEOUT_SECONDS`), a total tunnel duration
   (`EGRESS_MAX_TUNNEL_SECONDS`), a download cap per tunnel (`EGRESS_MAX_TUNNEL_MB`) and an
   upload cap. Concurrency is capped (`EGRESS_MAX_CONNECTIONS`, then 503).
6. Nothing from the client's request head is forwarded, so no headers or credentials leak
   upstream. Each tunnel logs one JSON line (host, port, address, outcome, reason, bytes,
   seconds).

**Redirects.** TLS is end to end, so the proxy cannot see HTTP redirects. Each redirect hop is a
new CONNECT and goes through the same checks. The fetcher also validates each hop itself
(https, no credentials or port, exact host lists, at most 5 hops).

### Allowlist

The default allowlist, also in `.env.example` and `docker-compose.yml`:

| Host | Why | Observed |
|---|---|---|
| `github.com` | git smart-HTTP (`info/refs`, `git-upload-pack`); git does not follow redirects | 2026-11-19 |
| `huggingface.co` | Hub API (`/api/models/...`), `/resolve/` and the `307` to `/api/resolve-cache/...` for small files | 2026-11-19 |
| `us.aws.cdn.hf.co` | LFS/Xet content: `302` target for `pytorch_model.bin`, `model.safetensors` | 2026-11-19 (from this machine) |
| `cas-bridge.xethub.hf.co` | Xet bridge host in the previous code's allowlist; not observed here | kept for compatibility |

Other regions may be redirected to other CDN hosts, for example `eu.aws.cdn.hf.co`. The code's
Hugging Face list accepts a few known HF hosts, but the proxy refuses any host not in
`EGRESS_ALLOWED_HOSTS`. Add a host there only after checking where real downloads go. A
redirect to an unlisted host makes that file fail with a clear reason, and the scan reports it.

## Storage limits (L1)

- **Kernel-enforced cap.** Each scan's tree lives in `px-stg-<scan>`, a Docker `local` volume of
  type `tmpfs` with `size=STAGING_MB`, owned by the workspace user with mode 0700 and mounted
  `nosuid,nodev,noexec`. Writes past the size fail with `ENOSPC`, whatever the writer is: git,
  the HF client, ZIP extraction, or a compromised process in those containers. `ENOSPC` is
  reported as `storage_limit_exceeded`. The runner verifies every volume with
  `docker volume inspect` (driver, type, exact options, labels) and refuses one that differs.
- **RAM budget.** tmpfs is memory. A new volume is admitted only while this deployment's staging
  volumes, plus the new one, stay within `STAGING_TOTAL_MB`. Admission happens under a
  PostgreSQL advisory lock; otherwise the scan waits up to `STAGING_WAIT_SECONDS` and then fails
  with `staging_budget_exceeded`. A volume with an unreadable size label counts as full.
  `FETCHER_MEMORY_MB` and `ANALYZER_MEMORY_MB` must exceed `STAGING_MB`, because tmpfs pages are
  charged to the writer's memory cgroup.
- **Persistent workspace.** The `persist` copy is bounded twice: its source is the capped tmpfs,
  and the copy itself enforces `MAX_ARTIFACT_SIZE_MB` and `MAX_ARTIFACT_FILES`, and refuses
  symlinks and special files. Before each copy, the `src` trees of the oldest finished scans are
  pruned until the total fits `WORKSPACE_MAX_TOTAL_MB` (`app/pipeline/retention.py`). Their small
  evidence files are kept; `/verify` then reports `UNKNOWN` for the artifact hash, which is the
  documented result for missing off-chain content.
- **Archive limits** (traversal, absolute paths, symlinks, ratio and file count) still run inside
  the analyzer, as before.

## Lifecycle and recovery

- **Labels.** Containers and volumes carry `io.provenancex.role`
  (`analyzer`/`fetcher`/`staging`), `instance`, `scan-id` and `claim`. Containers also carry
  `mode`. Each is verified at create time and again with inspect.
- **Self-stopping.** Fetcher, analyzer and holder enforce their own deadline and CPU time
  (`app/sandbox_worker/supervise.py`), so they stop even when the runner that started them is
  gone.
- **Reconciliation** (`app/analysis/reconcile.py`, at startup and every
  `RUNNER_RECONCILE_SECONDS`). It removes analyzer and fetcher containers that do not belong to
  a live claim, then the staging volumes (Docker refuses to remove one that is still mounted; the
  next pass retries), then workspace directories with no scan row that are older than an hour. It
  removes by full id, is scoped to this deployment's instance label, and is idempotent and safe
  to run concurrently.
- **Claims and fencing** (Milestone A.1) are unchanged. The fetcher's container is labelled with
  the claim token, a lost claim stops the attached run (`ClaimLost`), and an old runner can
  never publish a fetch result because every write is fenced on the token.
- **Watchdog** (`app/runner/watchdog.py`). The heartbeat keeps renewing while the process lives,
  so a wedged scan thread was never recovered when only one runner existed. Each sandbox step now
  registers its deadline. A step still running `RUNNER_WATCHDOG_GRACE_SECONDS` after its
  deadline, or a scan past `RUNNER_MAX_SCAN_SECONDS`, triggers the watchdog thread:
  1. it marks the claim lost (the heartbeat stops, fenced writes are refused);
  2. it fails the scan as `runner_watchdog_timeout` with a conditional UPDATE on its own token
     and replaces the token;
  3. it removes only the containers labelled with this scan id **and** claim token, plus the
     staging volume and workspace;
  4. if the scan thread has not unwound within `RUNNER_WATCHDOG_EXIT_SECONDS`, it exits the
     process (code 75) so Compose restarts the runner.
  A runner runs one scan at a time, so no unrelated scan is affected.
- **Docker restart.** Every sandbox container stops, and tmpfs contents are lost. On restart,
  startup recovery and stale-claim recovery fail the interrupted scan (`runner_interrupted`), and
  reconciliation removes the leftover containers and volumes. See "Docker restart test" below.

## L2, L3, M3

- **L2** (`app/sandbox_worker/selfcheck.py`). `is_isolated(report, expected)` requires
  **exactly** the expected keys (`ANALYZER_CHECKS` or `FETCHER_CHECKS`), each the boolean
  `True`. The result schemas use `StrictBool`, so `"true"` or `1` are refused rather than
  coerced. New checks: `seccomp_filtered` (`Seccomp: 2` in `/proc/self/status`) and
  `no_secret_env`.
- **L3** (`app/analysis/runtime_checks.py`, applied to analyzer and fetcher containers).
  Required: runtime `runc`; `OomKillDisable` false; `/dev/shm` ≤ 64 MiB; Docker's default
  masked and read-only `/proc` and `/sys` paths present; ulimits exactly `core=0`; private
  cgroup namespace; no `seccomp=unconfined`, AppArmor `unconfined`, SELinux `label=disable` or
  `systempaths=unconfined`, and no custom security profiles. Also refused: sysctls, init
  injection, published or exposed ports, extra hosts, links, device requests, device cgroup
  rules, custom cgroup parent, negative OOM score, isolation, group-add, custom DNS, TTY and the
  wrong entrypoint. A property Docker always reports fails closed when it is missing. The
  expected values were taken from this daemon (Docker 29.9.3, cgroup v2, builtin seccomp
  profile).
- **M3**:
  - Workers print a framed stream (`app/analysis/framing.py`): a JSON envelope
    (≤ `ANALYZER_MAX_OUTPUT_MB`, default 12; fetcher ≤ `FETCHER_MAX_OUTPUT_MB`, 8) and, for
    software analysis, the raw SBOM as its own frame (≤ `MAX_SBOM_MB`).
  - The decoder refuses an oversized frame from its 9-byte header, before reading the body. It
    also refuses truncated, duplicated, reordered, unknown and trailing data.
  - The SBOM is streamed to a file and checked against its declared size and SHA-256.
  - The envelope passes a structural budget (objects, elements, depth) before `json.loads`, which
    bounds how many Python objects it can expand into.
  - The SBOM is parsed in a child process with `RLIMIT_AS` (`SBOM_PARSE_MEMORY_MB`), so a hostile
    SBOM can only exhaust the child.
  - The Compose runner has a memory limit (`RUNNER_MEMORY_LIMIT`, 1536m).
  - Real sizes: SBOMs of the fixture projects and `octocat/Hello-World` are a few hundred bytes to
    a few KB. A 20,000-path envelope is under 2 MB.

## Configuration

All values live in `.env.example`, the Compose `scan-runner` environment and
`app/core/config.py`, with validation. `STAGING_MB` must be ≥ `MAX_ARTIFACT_SIZE_MB`, the memory
limits must exceed `STAGING_MB`, and `RUNNER_MAX_SCAN_SECONDS` must cover fetch, analyze and
persist plus grace. The test-only `FETCHER_PROVIDER=inprocess_test` is refused unless
`APP_ENV=test`, and the in-process fetcher refuses to run outside a pytest test.

Bring-up: `make up` builds both sandbox images (`make sandbox-images`) and starts the stack, which
creates the `fetch` (internal) and `egress` networks and the proxy. A host-run runner
(`make runner`) still needs `docker compose up -d egress-proxy`, which provides the fetch
network.

## Tests

The live suites run only with the stated variables; skipped tests are not counted as passed.

| Suite | Kind | What it shows |
|---|---|---|
| `tests/unit/test_output_framing.py` | mocked | framing refusals, header-only refusal of oversized frames, JSON budget, bounded memory (tracemalloc) |
| `tests/unit/test_selfcheck_and_inspect.py` | mocked (fake Docker CLI) | L2 exact keys and strict booleans; each L3 weakening refused before start; unverifiable properties fail closed |
| `tests/unit/test_staging_and_fetcher.py` | mocked (fake Docker CLI) | staging volume options, verification and budget; fetcher allowlist (each restriction required, wrong networks and mounts, extra flags); DockerFetcher drift, timeouts, concurrency, isolation and output refusals |
| `tests/unit/test_egress_proxy.py` | in-process, offline | allowlist, SSRF address ranges, rebinding (one resolution, pinned address), caps, timeouts, 405/403/408/503, no header forwarding |
| `tests/unit/test_runner_watchdog.py` | SQLite + fake Docker | hung step detected with a fresh heartbeat; only this scan and claim cleaned up; replaced claims untouched; exit when wedged |
| `tests/unit/test_storage_limits.py` | SQLite / child process | workspace pruning order and budget; persist digest mismatch fails the scan; SBOM child: malformed, oversized, memory bomb contained |
| `tests/security/test_no_host_fallback.py`, `test_compose_isolation.py` | static + mocked | download entry points refuse on the host; runner and pipeline never call or import download code; no git in the runner image; proxy networks, images and limits |
| `tests/integration/test_fetcher_live.py` | **real Docker** (+ `network` subset) | fetch network has no route and no DNS; proxy cannot reach other networks; real fetcher self-check all true; unapproved destination fails safely; `ENOSPC` past the tmpfs cap; extraction past the cap with the app limit raised; hung download; SIGKILLed runner recovered by concurrent reconcilers; watchdog cleanup on real containers; real GitHub and HF downloads checked against independent hashes; download larger than staging refused |
| `tests/integration/test_egress_proxy_live.py` | **real proxy container** (+ `network` subset) | policy refusals; GitHub TLS through the tunnel; the real HF redirect chain hop by hop; a GitHub redirect to an unlisted host refused; public DNS names pointing at loopback, RFC 1918 or metadata refused; byte cap |
| `tests/integration/test_analyzer_live.py`, `test_runner_kill_live.py` | **real Docker** | updated for staging: extract, analyze and persist through the holder; SIGKILLed runner recovery also removes holder and staging volume |
| `scripts/milestone_b/verify_e2e.py` | **real Compose stack + internet** | pinned GitHub and HF scans through the real runner, fetcher, proxy, analyzer, Postgres and Hardhat: hashes vs independent references, evidence endpoints, risk decision, anchor, `VERIFIED`, no leftovers |

### Docker restart test (needs a manual Windows-side restart)

```bash
scripts/milestone_b/up.sh                    # separate project "pxmb", own ports/volumes/networks
scripts/milestone_b/docker_restart_pre.sh    # leaves a real HF scan in flight, runner paused
# restart Docker Desktop from Windows
scripts/milestone_b/docker_restart_post.sh   # recovery checks + fresh end-to-end scans
scripts/milestone_b/down.sh                  # removes project "pxmb" only
```

## Known limitations

- **The scan-runner still holds the Docker socket**, which is root-equivalent on the host. It no
  longer downloads or parses artifacts, but a compromise of the runner itself (for example,
  through its dependencies or the OSV/NVD responses it still fetches) remains critical.
- **Docker Desktop bind mounts.** When the runner runs on the host (`ANALYZER_WORKSPACE_MOUNT=bind`),
  Docker Desktop rewrites a WSL bind source to
  `/run/desktop/mnt/host/wsl/docker-desktop-bind-mounts/<distro>/<sha256>` whenever the container
  also mounts a named volume. The inspect check accepts exactly that form, for a bind with the
  requested target and access mode, but cannot map it back to the original path. Compose uses
  volume mode, has no binds, and keeps the exact check.
- **tmpfs RAM.** Staging is RAM: `STAGING_TOTAL_MB` must fit the Docker VM, which has about 8 GB
  on this machine. Docker Desktop's VM memory limit is the final backstop.
- **Allowlist drift.** Hugging Face CDN host names can change or differ by region. A changed
  host fails safely (that file is not downloaded and the reason is recorded) until it is added.
- **DNS rebinding** is prevented by single resolution and address pinning. That is tested with
  an injected resolver; the live tests use real public DNS records that point inside, but cannot
  make a real resolver change its answer mid-test.
- **The proxy cannot inspect TLS**, so it cannot enforce HTTP-level rules (paths, redirects,
  response sizes per file). Those stay in the fetcher, behind the network-level guarantees.
- **The `/verify` re-hash** still reads the kept tree in the API process (documented exception,
  Milestone C).
- **Fetched identity comes from an untrusted container.** The commit SHA, the Hub listing and its
  hashes are reported by the fetcher, which parsed network data. Isolation keeps a compromised
  fetcher away from the host, the database and secrets, but it could misreport what it fetched.
  The runner re-checks a pinned commit SHA, the reported repository and the persisted-tree
  digest. The analyzer independently hashes every staged file, and verifies LFS files against
  the reported listing.
- **Fetchers share the internal network.** Concurrent fetchers can see each other at the IP
  level. They expose no services, and disabling inter-container traffic on the bridge would also
  cut them off from the proxy. `FETCHER_MAX_CONCURRENT` (default 2) bounds this.

## Deferred findings

**M4, M5, M6** and the rest of Milestone C are deferred, as instructed. The audit report is not in
the repository, so their content is not restated here.
