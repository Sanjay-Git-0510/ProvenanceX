# Thin wrappers around common commands. Run from the repo root.
PY := backend/.venv/bin
# Group that owns the Docker socket, given to the Compose scan-runner (docker-compose.yml).
export DOCKER_SOCKET_GID ?= $(shell stat -c %g /var/run/docker.sock 2>/dev/null || echo 0)

.PHONY: lock up sandbox-up sandbox-down analyzer-image fetcher-image sandbox-images runner down logs migrate test test-backend test-frontend lint fmt gate e2e demo demo-down

# Regenerate the hash-locked requirement files (audit M6) from backend/requirements*.txt.
lock:
	scripts/lock.sh

up: sandbox-images
	docker compose up --build -d

# Every content-reading scan step runs in a container from this image (docs/security/sandbox.md).
analyzer-image:
	docker compose --profile analyzer-image build analyzer-image

# Every GitHub / Hugging Face download runs in a container from this image (docs/security/fetcher.md).
fetcher-image:
	docker compose --profile fetcher-image build fetcher-image

sandbox-images: analyzer-image fetcher-image

down:
	docker compose down

# OPT-IN behavioral sandbox (docker-compose.sandbox.yml). PX_SANDBOX_WORKSPACE must be an absolute
# path in the Linux filesystem, outside the repository. It is made owned by uid/gid 999 (the
# containers' non-root user), because the sandbox refuses a root-owned workspace.
PX_SANDBOX_WORKSPACE ?= $(HOME)/.local/state/provenancex-sandbox-workspace
SANDBOX_COMPOSE = PX_SANDBOX_WORKSPACE="$(PX_SANDBOX_WORKSPACE)" docker compose -f docker-compose.yml $(if $(wildcard docker-compose.override.yml),-f docker-compose.override.yml,) -f docker-compose.sandbox.yml

sandbox-up: sandbox-images
	docker compose --profile sandbox-image build sandbox-image
	@case "$(PX_SANDBOX_WORKSPACE)" in /*) ;; *) echo "PX_SANDBOX_WORKSPACE must be absolute" >&2; exit 2;; esac
	mkdir -p "$(PX_SANDBOX_WORKSPACE)"
	docker run --rm --user 0 --network none -v "$(PX_SANDBOX_WORKSPACE):/w" --entrypoint chown provenancex-runner:0.1.0 999:999 /w
	$(SANDBOX_COMPOSE) up --build -d

sandbox-down:
	$(SANDBOX_COMPOSE) down

logs:
	docker compose logs -f

# Run the scan runner on the host instead of in Compose (bind-mounted workspace). Downloads still
# need the Compose egress proxy and fetch network: start them with `docker compose up -d egress-proxy`.
runner:
	cd backend && ANALYZER_WORKSPACE_MOUNT=bind .venv/bin/python -m app.runner

migrate:
	docker compose exec api alembic upgrade head

test: test-backend test-frontend

test-backend:
	cd backend && .venv/bin/pytest -q

test-frontend:
	cd frontend && npx vitest --run

# Run the CI gate against the local API: make gate GATE_PATH=path/to/project
GATE_PATH ?= backend/tests/fixtures/software/simple_python_project
gate:
	python3 scripts/ci_gate.py "$(GATE_PATH)"

# Local only: disposable Postgres and Hardhat, real Syft, live OSV. Exit 3 means NOT RUN.
e2e:
	scripts/run_e2e.sh

# A separate Compose project on its own ports, beside any development stack. Exit 3 means NOT RUN.
demo:
	scripts/demo.sh

# Removes only the demo project and its volumes.
demo-down:
	docker compose -p provenancex-demo --project-directory . -f docker-compose.yml -f docker-compose.demo.yml --profile chain-deploy down -v --remove-orphans

lint:
	cd backend && .venv/bin/ruff check . ../ml/scripts ../scripts --config pyproject.toml && .venv/bin/ruff format --check . ../ml/scripts ../scripts --config pyproject.toml
	cd frontend && npm run lint

fmt:
	cd backend && .venv/bin/ruff format . && .venv/bin/ruff check --fix .
