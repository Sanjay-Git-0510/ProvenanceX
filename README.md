# ProvenanceX

ProvenanceX is a defensive security platform for software and AI/ML supply chains. It
takes a software repo or package, or an AI model artifact, and does the following:

1. Collects multi-layer evidence: SBOM, vulnerabilities, provenance, static analysis, sandbox behavior and graph.
2. Produces an explainable **0–1 risk score** and an **ALLOW / REVIEW / BLOCK** decision.
3. Anchors compact evidence on a local blockchain.

> **Status: Phase 7, blockchain evidence.** Software (GitHub URL or ZIP) and AI/ML artifacts (Hugging Face URL or
> model-directory ZIP) are fetched safely, hashed with SHA-256, and analyzed for SBOM or AI-BOM, dependency or lineage graph,
> known vulnerabilities, provenance and static signals. On the host, an optional Docker sandbox adds behavior evidence (off by default).
> ML, risk scoring and ALLOW/REVIEW/BLOCK decisions work. Completed scans can be anchored on a local chain and verified. The dashboard
> has working Dashboard, New Scan, Scan Details, Findings and Risk Analysis pages. The Dependency Graph, Model Lineage,
> Blockchain Evidence, CI/CD and Settings pages are still placeholders. See [docs/implementation-plan.md](docs/implementation-plan.md).

- Architecture: [docs/architecture.md](docs/architecture.md)
- Binding project contract: [CLAUDE.md](CLAUDE.md)

## Prerequisites

The development machine is Windows with WSL2 Ubuntu. Keep the repo on the Linux filesystem, for example `~/provenancex`, and not under `/mnt/c`.

| Tool | Version | Notes |
|---|---|---|
| Docker Desktop | recent | Turn on **Settings → Resources → WSL Integration** for your distro so `docker` works inside WSL |
| Python | 3.12 recommended | Containers use 3.12. Local 3.14 works for Phase 0. |
| Node.js | 22 LTS or newer | For the frontend |
| Git | any | |
| Syft | 1.57.0 (pinned) | SBOM generation. Already in the API Docker image. For local runs, install it on `PATH` ([releases](https://github.com/anchore/syft/releases)). If it is missing, the SBOM stage reports `unavailable`. It never falls back to mock data silently. Set `SBOM_PROVIDER=mock` to choose the labeled mock explicitly. |

## Quickstart (Docker)

```bash
cp .env.example .env          # then edit POSTGRES_PASSWORD and DATABASE_URL
docker compose up --build -d
curl http://localhost:8000/api/v1/health/ready
# {"status":"ready","db":"ok","version":"0.1.0"}
open http://localhost:5173    # UI shell; the header badge shows API and DB status
```

The API container runs `alembic upgrade head` on startup.

## Local development (without Docker)

```bash
# Backend
cd backend
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/uvicorn app.main:app --reload      # needs DATABASE_URL pointing at a running Postgres

# Frontend
cd frontend
npm install
npm run dev                                   # proxies /api to localhost:8000
```

The frontend is dark only. Its design tokens are in `frontend/src/styles/tokens.css`, and a test checks
WCAG AA contrast for each colour on its actual background. Onest and IBM Plex Mono (Latin 400 and 500)
are self-hosted through npm packages, so the app loads nothing from an external CDN. After changing
frontend dependencies, rebuild the Compose image with `docker compose build frontend`.

Opening an older completed scan in Scan Details or Risk Analysis calls `GET /risk`, which computes and stores
its decision on first read. The Dashboard does not trigger this: it calls `/risk` only for ALLOW rows, which
already have a stored decision.

## Tests and lint

```bash
make lint            # ruff (backend) + eslint (frontend)
make test            # pytest + vitest
cd frontend && npm run build
```

Backend integration tests (`-m integration`) need a reachable PostgreSQL at `DATABASE_URL`.
Without one they are **skipped with an explicit reason**. The real-Syft tests
(`tests/integration/test_syft_real.py`) are skipped when Syft is not on `PATH`. In CI, Postgres
and a pinned Syft are both available, and any skip fails the build.

Live-internet tests (marker `network`: GitHub clone, OSV, NVD, Hugging Face) run only with
`PROVENANCEX_NETWORK_TESTS=1`. Tests that run the real sandbox (marker `sandbox`) run only with
`PROVENANCEX_SANDBOX_TESTS=1` and need the sandbox image. CI deselects both with
`-m "not network and not sandbox"`.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/health` | Liveness: `{status, version}` |
| GET | `/api/v1/health/ready` | Readiness (DB check). Returns 503 with `{"error": {...}}` when the DB is down. |
| POST | `/api/v1/scans/software` | Start a software scan (multipart form, see below). Returns **202** `{scan_id, artifact_id, status}`. |
| POST | `/api/v1/scans/model` | Start an AI/ML scan (multipart form, see below). Returns **202** `{scan_id, artifact_id, status}`. |
| GET | `/api/v1/scans` | Scans, newest first. Query: `limit` (default 20, max 100), `offset`, `status` (`queued`, `running`, `completed`, `failed`). Each sanitized item has `scan_id`, `status`, `created_at`, `finished_at`, `artifact` (`name`, `artifact_type`, `source`), `decision`, `risk_score` and `confidence`. The last three are null when no decision is stored, never 0. Reads stored results only |
| GET | `/api/v1/scans/{scan_id}` | Scan status, normalized artifact record, ingest evidence, per-stage evidence status (`stages`), `bom_sha256`, `provenance`, component and finding counts, and a structured error if the scan failed |
| GET | `/api/v1/scans/{scan_id}/findings` | Findings, highest CVSS first. Filters: `category`, `severity`, `source`, `limit`, `offset`. Each item has a separate `cvss` object, `source` and `is_mock`. |
| GET | `/api/v1/scans/{scan_id}/graph` | Dependency or model-lineage graph (`graph_kind`), nodes and edges, graph features, `limitations`, and `is_mock` |
| GET | `/api/v1/scans/{scan_id}/evidence` | Bounded, sanitized evidence summary: stage statuses and reasons, feature vector with null reasons, finding and component summaries with sources, provenance record, hashes, model version, mock flags and the synthetic-training label. Pages with `findings_limit`/`findings_offset` and `components_limit`/`components_offset` (at most 200 per page). Contains no file contents, raw SBOMs or traces |
| POST | `/api/v1/scans/{scan_id}/anchor` | Anchor a completed scan on the local chain, once. Returns a structured error and sends nothing if it is refused |
| GET | `/api/v1/scans/{scan_id}/blockchain` | The stored anchor record. Makes no verification claim |
| POST | `/api/v1/scans/{scan_id}/verify` | Recompute the evidence and compare it with the anchor and the chain. Returns `VERIFIED`, `MISMATCH`, `NOT ANCHORED` or `UNKNOWN` with a reason and the values for each field |

Every error uses the envelope `{"error": {"code", "message", "details"}}`.

### Starting a software scan

Send exactly one of `source_url` or `file`:

```bash
# GitHub repository (https://github.com/<owner>/<repo> only), optional branch/tag/full commit SHA
curl -F source_url=https://github.com/psf/requests -F revision=v2.32.3 \
     http://localhost:8000/api/v1/scans/software

# ZIP upload (optional display name)
curl -F file=@project.zip -F name=my-project http://localhost:8000/api/v1/scans/software

curl http://localhost:8000/api/v1/scans/<scan_id>
```

The scan runs in the background. Its status moves `queued → running → completed | failed`.
`artifact.sha256` is a deterministic **content digest** (`provenancex-tree-v1`; see
`backend/app/core/hashing.py`), so the same files produce the same hash whether they came from a ZIP or a git clone.
For uploads, `ingest.archive_sha256` is the hash of the raw ZIP bytes.

Evidence stages (Phase 2) run after ingestion: `sbom` (Syft → CycloneDX → components),
`graph` (NetworkX), and `vulnerabilities` (OSV, plus NVD to fill in missing CVSS). Each stage
records `status` (`completed | partial | unavailable | error | skipped`), `provider`, and `source`
under `stages`. A scan can be `completed` while a stage is `unavailable`, for example when Syft is
missing or OSV cannot be reached. An empty findings list then does **not** mean "no vulnerabilities".
CVSS scores are advisory severity. They are not the ProvenanceX risk score (Phase 6), and a known
vulnerability is not evidence of malice.

### Starting an AI/ML scan

Send exactly one of `source_url` or `file`. `artifact_type` is `model` (default), `lora` or `dataset`:

```bash
# Public Hugging Face repository, optionally pinned to a branch, tag or full commit SHA
curl -F source_url=https://huggingface.co/hf-internal-testing/tiny-random-gpt2 \
     -F artifact_type=model http://localhost:8000/api/v1/scans/model

# Dataset repositories use the /datasets/ path
curl -F source_url=https://huggingface.co/datasets/<owner>/<name> \
     http://localhost:8000/api/v1/scans/model

# ZIP of a model directory
curl -F file=@lora.zip -F artifact_type=lora http://localhost:8000/api/v1/scans/model

curl http://localhost:8000/api/v1/scans/<scan_id>                       # stages, provenance
curl http://localhost:8000/api/v1/scans/<scan_id>/graph                 # lineage graph
curl "http://localhost:8000/api/v1/scans/<scan_id>/findings?category=static"
```

A model scan runs the stages `aibom`, `graph` (`graph_kind: lineage`), `vulnerabilities` and
`provenance`. Pickle files are inspected with `pickletools` opcode parsing only, and custom code
is listed but never imported. `static` findings (such as a pickle that imports `os.system`) are
suspicious signals and carry no CVSS. They are separate from `vulnerability` findings.

What a model scan does not do:
- Only public, non-gated repositories can be scanned. No Hugging Face token is used.
- LFS files over `HF_MAX_FILE_MB` are listed but not downloaded. Their hash is the one the Hub reports, marked unverified.
- Signature and attestation files are detected by name only, so `signed` stays `null`.
- OSV lookups cover only exactly pinned (`name==version`) runtime requirements.
- GGUF and ONNX files are identified but their internals are not parsed.

In provenance fields, `null` means "could not be determined", never "no".

Input safety:
- URLs: https only, `github.com` or `huggingface.co` allowlist, and the host must resolve to a public IP. Hugging Face download redirects may only go to a fixed list of Hugging Face hosts.
- ZIPs: rejected for path traversal, absolute paths, symlinks, special files, encryption, duplicate entries, decompression bombs, or size and file-count limits.
- git: shallow clone, hooks, submodules, redirects and LFS disabled, with a timeout and size cap.

## Optional Docker sandbox

The sandbox is **off by default** (`SANDBOX_PROVIDER=disabled`). When it is enabled, it runs real
untrusted code inside a disposable container, so read the limitations below first.

```bash
# Build the image (pinned base image and strace, no secrets)
docker build -t provenancex-sandbox:0.1.0 docker/sandbox
# or: docker compose --profile sandbox-image build sandbox-image

# Run the API on the host, with Docker available
cd backend
SANDBOX_PROVIDER=docker .venv/bin/uvicorn app.main:app --port 8000

# Live boundary tests
PROVENANCEX_SANDBOX_TESTS=1 .venv/bin/pytest -m sandbox
```

What runs: a software scan runs a root `setup.py`. A model scan loads pickle files with stdlib
`pickle` and imports `auto_map` modules. npm lifecycle scripts are not run.

The `sandbox` stage records behavior features and `behavioral` findings. The raw trace stays
off-chain in the scan workspace. `SANDBOX_PROVIDER=mock` returns a synthetic bundle labeled
`source="mock"`. It is never used as a fallback. If the sandbox fails, the scan still completes,
the stage says why, and behavior features stay `null`.

Limitations:
- **Do not run real malware through this sandbox on the host.** It is for controlled fixtures and
  development. Analyzing real malware needs a disposable VM with no route to anything you care about.
- **The sandbox needs the API running on the host with Docker.** Inside Compose the API has no
  Docker access by design, so with `SANDBOX_PROVIDER=docker` the stage reports `unavailable`.
- **Observed code can interfere with its own trace.** It can kill the tracer, rewrite `/trace` and
  write to the bundle through `/proc/1/fd`, so quiet telemetry is not proof of safety.
- **A kernel or container escape is outside this boundary.** Containers share the host (WSL2)
  kernel, and the sandbox runs as the workspace owner's uid (never 0). If that user is in the `docker`
  or `sudo` groups, an escape can lead to root in WSL and to Windows files.
- **The host API has Docker access, which is root-equivalent, while it parses untrusted input.** See
  [docs/architecture.md](docs/architecture.md) for this and the cleanup-failure and image-by-tag limits.

## Local chain

`docker compose up` also starts a local Hardhat chain, bound to `127.0.0.1:8545`. It is for local
development only and runs in memory, so restarting it erases every anchor.

`BLOCKCHAIN_PROVIDER` is `disabled` by default. `web3` accepts only a local RPC host and chain id
31337. `mock` is an in-memory ledger whose results are labeled `source="mock"`. A mock is never used
as a fallback. Scans containing mock evidence are refused on the real chain.

```bash
# Contract tests, in the pinned Node 22 image
docker compose build hardhat
docker compose run --rm --no-deps hardhat npx hardhat test --no-compile

# Check that the backend's ABI matches the compiled contract
docker run --rm -v "$PWD/backend/app/blockchain/abi.json:/tmp/abi.json:ro" \
  provenancex-hardhat:0.1.0 node scripts/check-abi.js /tmp/abi.json

# Deploy (needs a local Hardhat test key in your git-ignored .env)
docker compose --profile chain-deploy run --rm hardhat-deploy

# Live chain tests, from backend/, with the chain running and the contract deployed. Also set
# DATABASE_URL, BLOCKCHAIN_RPC_URL, BLOCKCHAIN_CONTRACT_ADDRESS and BLOCKCHAIN_PRIVATE_KEY.
PROVENANCEX_CHAIN_TESTS=1 pytest -m chain
```

### Anchoring and verifying a scan

Set `BLOCKCHAIN_PROVIDER=web3`, `BLOCKCHAIN_CONTRACT_ADDRESS` and `BLOCKCHAIN_PRIVATE_KEY` in your
git-ignored `.env`, then restart the API.

```bash
curl -X POST http://localhost:8000/api/v1/scans/<scan_id>/anchor   # a scan can be anchored once
curl http://localhost:8000/api/v1/scans/<scan_id>/blockchain       # stored data, no verification claim
curl -X POST http://localhost:8000/api/v1/scans/<scan_id>/verify   # recompute and compare
```

Set `BLOCKCHAIN_ANCHOR_ON_SCAN=true` to anchor each completed scan automatically. It is off by default.

| State | Meaning |
|---|---|
| `VERIFIED` | Every hash was recomputed and every value matches the anchor and the chain |
| `MISMATCH` | Something differs (see `reason` and each field's `status`) |
| `NOT ANCHORED` | No anchor exists for this scan |
| `UNKNOWN` | It could not be checked: chain unavailable or reset, or off-chain files missing |

`VERIFIED` means the record has not changed since it was anchored. It does not show that the scanner
was correct or that the artifact is safe.

Scanned files are kept in the `provenancex_workspace` Docker volume so that hashes can be recomputed.
It holds **untrusted artifacts** until you run `docker compose down -v`. Anchored scans whose files are
gone, including any made before this volume existed, report `UNKNOWN`.

The full steps and the on-chain encoding are in [contracts/README.md](contracts/README.md). Use only
Hardhat's public test keys, and never a real key.

## Safety

ProvenanceX treats every scanned artifact as untrusted and never executes it on the host.
See the trust boundaries in [docs/architecture.md](docs/architecture.md#3-trust-boundaries).
Do not commit secrets. Only `.env.example` is tracked.
