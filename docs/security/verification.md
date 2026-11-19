# Verification, evidence integrity and supply chain (Milestone C)

_Status: implemented 2026-11-19 (C1–C5), uncommitted, awaiting owner review._

This document covers the last three audit findings, **M5** (the `/verify` re-hash ran in the API),
**M4** (a compromised analyzer could forge clean evidence) and **M6** (the image holding the
Docker socket had the weakest supply chain), plus the folded low-severity findings **L4**, **L5**,
**L9**, **L11** and **I1**. It extends [sandbox.md](sandbox.md) and [fetcher.md](fetcher.md).

## M5: asynchronous verification jobs

`POST /api/v1/scans/{id}/verify` no longer hashes anything. The API reads no artifact files and
no chain for a verification; it only writes a row.

```
POST /scans/{id}/verify   (API: database only)
  ├─ unknown scan                          -> 404 scan_not_found
  ├─ scan that can never be anchored       -> 200, finished job, NOT ANCHORED
  ├─ an active job for this scan exists    -> 202, that job (partial unique index: one per scan)
  ├─ VERIFY_MAX_PENDING jobs already queued -> 429 verify_queue_full (exact: advisory lock)
  └─ otherwise                             -> 202, new queued job
GET  /scans/{id}/verifications/{job_id}    -> the job; `result` once finished
GET  /scans/{id}/verifications             -> history, newest first (limit, offset)

scan-runner (each loop pass: one verification job, then one scan)
  ├─ claim: FOR UPDATE SKIP LOCKED, fresh claim token, heartbeat
  ├─ rehash analyzer container: network none, the scan's workspace mounted read-only at
  │    /evidence, non-root, cap-drop ALL, all limits, self-check, deadline
  │    (VERIFY_REHASH_TIMEOUT_SECONDS). It only hashes bytes (O_NOFOLLOW, fstat, inode match)
  │    and returns three strictly validated digests (DigestOut: ok | missing | invalid | unavailable)
  ├─ the unchanged comparison (app/blockchain/verification.py) against the stored anchor,
  │    the live tables and the chain
  └─ conditional UPDATE ... WHERE claim_token = :mine AND status = 'running'
```

States are unchanged: **VERIFIED, MISMATCH, NOT ANCHORED, UNKNOWN**. Job statuses are `queued`,
`running`, `completed` and `failed`. A job that cannot finish never reads as VERIFIED:

| Situation | Answer |
|---|---|
| Rehash container unavailable, failed, timed out, invalid output | UNKNOWN `rehash_failed` |
| Rehash reports the anchored digest but different file counts | UNKNOWN `rehash_inconsistent` |
| Kept tree deleted or unreadable | UNKNOWN `offchain_evidence_unavailable` |
| A byte changed in the tree, the SBOM/AI-BOM or the provenance file | MISMATCH `evidence_mismatch` |
| A kept file swapped for a symlink or special file | MISMATCH (the field is `invalid`) |
| Job past `VERIFY_MAX_SECONDS`, or its step past its deadline (`VerifyGuard`) | job `failed`, UNKNOWN `verify_timeout` |
| Heartbeat stopped, or the runner was killed | job `failed`, UNKNOWN `verify_interrupted` |
| Unexpected error | job `failed`, UNKNOWN `verify_failed` |
| A runner whose job was recovered tries to store its answer | refused (fenced UPDATE) |

Rehash containers carry the job's claim token as their label. The reconciler keeps one only while
its job is running under that token and heartbeating, and removes it otherwise.
`verification_runs` (migration `0009`) keeps every job: request, start and finish times, the
answer, and the rehash run record (image id, verified runtime limits, exit code, duration).

Settings: `VERIFY_REHASH_TIMEOUT_SECONDS` (300), `VERIFY_MAX_SECONDS` (600),
`VERIFY_MAX_PENDING` (50). The web UI posts once, then polls the job (`Queued`, `Verifying`).

## M4: evidence integrity

A parser exploit in the analyzer could rewrite its output. Three layers limit what such output can
claim:

1. **Separation.** Syft runs alone in its own `sbom` container (read-only staging, the same
   hardening, `ANALYZER_SBOM_TIMEOUT_SECONDS`). The analyze container can no longer return an
   SBOM (schema). The tree digest is computed independently in the analyze, sbom and persist
   containers, and all three must be identical.
2. **Strict types** (`app/analysis/codec.py`, `app/sandbox_worker/protocol.py`). Static features
   have exactly the known keys with bounded non-negative counts. The AI-BOM summary has exactly
   its keys and bounded values. Config fields are short scalars or short lists of scalars. Model
   card metadata and file analyses are bounded plain JSON. Completeness is between 0 and 1.
3. **Contradiction checks** (`app/analysis/consistency.py`, after every analyze):
   - the file list is well formed (relative, no `..`), unique, and exactly `tree.file_count` long;
   - manifest, static-finding, not-analyzed and AI-BOM paths lie inside the file list; AI-BOM
     files marked as not downloaded lie outside it;
   - static counts never exceed the tree; `script_presence` agrees with `script_count`; findings
     have a known kind and never exceed that kind's count;
   - the AI-BOM summary agrees with its own file list;
   - real Syft component locations lie inside the tree (checked by the SBOM stage).

Any contradiction fails the scan (or the SBOM stage) with `analyzer_output_invalid`. Missing or
failed sections stay failed: nothing is treated as benign or as confirmed malicious.

**Limit.** These checks catch output that contradicts itself or the independently computed tree.
A compromised analyzer that hides a finding *consistently* (removing both the finding and its
count) is not detectable this way; isolation keeps such a compromise away from the host, the
database and the secrets.

## M6 and I1: supply chain

| Rule | Where | Checked by |
|---|---|---|
| Every base image pinned by digest (Python 3.12.8 slim, Node 22 slim, Postgres 16) | all Dockerfiles, `docker-compose.yml`, CI services | `tests/security/test_supply_chain.py` |
| Python packages only from hash-locked files, `pip install --require-hashes --no-deps` | `backend/requirements*.lock` (generated by `make lock` in the pinned base) | same |
| Direct dependencies exact (`==`), equal to the locked versions | `backend/requirements.txt`, `requirements-ml.txt` | same |
| Docker CLI from Docker's signed apt repository, key fingerprint pinned, `.deb` SHA-256 pinned | `backend/Dockerfile`, stage `docker-cli` | same; CI `images` job runs it |
| No curl, gnupg, compiler or Syft in the API and runner images | multi-stage `backend/Dockerfile` | same; CI `images` job inspects the images |
| setuid/setgid bits stripped, and the build fails if any remain (I1) | every Dockerfile | same; CI `images` job counts them |

`make lock` regenerates the lock files. It keeps existing pins unless an input changes;
`LOCK_CONSTRAINTS=<file>` seeds or holds pins (the first lock was seeded from the tested venv, so
no version changed).

**Runner constraint.** The runner image cannot be smaller than the ML stack: it runs the risk
stage (Random Forest, Isolation Forest, XGBoost with its NCCL wheel, SHAP over the saved models).
It shares the API's hash-locked runtime and adds only the verified Docker CLI. The API image has
no Docker CLI and no socket.

## L4, L5, L9, L11

- **L4.** A bind mount source must be exactly `<WORKSPACE_ROOT>/<scan>[/src|/input]`
  (`assert_create_hardened(..., workspace_root=)`). Without the root, any bind mount is refused.
- **L5.** Worker error `details` must be plain JSON of at most 4 KiB and depth 6 (workers clamp
  their own; anything larger invalidates the result). Untrusted stderr is logged only as an
  escaped excerpt (`app/core/bounded.py`), so it cannot forge log lines or carry terminal escapes.
- **L9.** The workspace volume and the fetch and egress networks default to
  `<compose project>_workspace|fetch|egress`, so two Compose projects never share them. The
  default project (`provenancex`) keeps its existing names.
- **L11.** CI builds every image (`images` job) and runs the real-Docker, real-PostgreSQL and
  real-Hardhat suites (`live` job, no skips allowed). See "Tests".

## Tests

| Suite | Kind | What it proves |
|---|---|---|
| `tests/unit/test_verify_jobs.py` | mocked (SQLite, stub analyzer) | queue, dedup, 429, NOT ANCHORED at once, fencing, stale/timeout/restart recovery, every failure is UNKNOWN, guard, reconcile |
| `tests/unit/test_rehash_mode.py` | mocked + fake Docker CLI | hashing refuses symlinks, FIFOs and swapped inodes; rehash statuses; strict schema; `rehash` allowlist |
| `tests/unit/test_evidence_consistency.py` | mocked | every contradiction rule, strict typing, forged sbom run fails the scan, L4, L5 |
| `tests/security/test_supply_chain.py` | static | M6, I1, L9 rules above |
| `tests/integration/test_verify_jobs_pg.py` | **real PostgreSQL** | 20 parallel POSTs make one job, runners never share a job, an old runner cannot overwrite, exact pending cap |
| `tests/integration/test_verify_live.py` | **real Docker** (+ **Hardhat** for one case) | verified rehash container, one changed byte in each file, symlink swap, deleted tree, file cap, timeout, SIGKILL of the runner mid-rehash; Hardhat VERIFIED, then MISMATCH, then UNKNOWN with the chain unreachable |
| `tests/integration/test_evidence_live.py` | **real Docker** | Syft alone in a verified `sbom` container; a forged analyzer image (built in the test) is rejected twice |
| `scripts/milestone_b/verify_e2e.py` | **real Compose stack + internet** | verification answered by a verified rehash container in the real runner |
| CI `images`, `live` jobs | **real Docker/PostgreSQL/Hardhat on GitHub** | run only on push or pull request |
