# ProvenanceX

ProvenanceX is a defensive security platform for software and AI/ML supply chains. It
takes a software repo or package, or an AI model artifact, and does the following:

1. Collects multi-layer evidence: SBOM, vulnerabilities, provenance, static analysis, sandbox behavior and graph.
2. Produces an explainable **0–1 risk score** and an **ALLOW / REVIEW / BLOCK** decision.
3. Anchors compact evidence on a local blockchain.

> **Status: Phase 3, AI/model ingestion.** Software (GitHub URL or ZIP) and AI/ML artifacts (Hugging Face URL or
> model-directory ZIP) are fetched safely, hashed with SHA-256, and analyzed for SBOM or AI-BOM, dependency or lineage graph,
> known vulnerabilities and provenance. Model files are only parsed, never loaded.
> Static code analysis, the sandbox, ML, risk scoring and blockchain anchoring do not exist yet. See [docs/implementation-plan.md](docs/implementation-plan.md).

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
`PROVENANCEX_NETWORK_TESTS=1`. CI deselects them with `-m "not network"`.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/health` | Liveness: `{status, version}` |
| GET | `/api/v1/health/ready` | Readiness (DB check). Returns 503 with `{"error": {...}}` when the DB is down. |
| POST | `/api/v1/scans/software` | Start a software scan (multipart form, see below). Returns **202** `{scan_id, artifact_id, status}`. |
| POST | `/api/v1/scans/model` | Start an AI/ML scan (multipart form, see below). Returns **202** `{scan_id, artifact_id, status}`. |
| GET | `/api/v1/scans/{scan_id}` | Scan status, normalized artifact record, ingest evidence, per-stage evidence status (`stages`), `bom_sha256`, `provenance`, component and finding counts, and a structured error if the scan failed |
| GET | `/api/v1/scans/{scan_id}/findings` | Findings, highest CVSS first. Filters: `category`, `severity`, `source`, `limit`, `offset`. Each item has a separate `cvss` object, `source` and `is_mock`. |
| GET | `/api/v1/scans/{scan_id}/graph` | Dependency or model-lineage graph (`graph_kind`), nodes and edges, graph features, `limitations`, and `is_mock` |

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

## Safety

ProvenanceX treats every scanned artifact as untrusted and never executes it on the host.
See the trust boundaries in [docs/architecture.md](docs/architecture.md#3-trust-boundaries).
Do not commit secrets. Only `.env.example` is tracked.
