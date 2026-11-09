# Thin wrappers around common commands. Run from the repo root.
PY := backend/.venv/bin

.PHONY: up down logs migrate test test-backend test-frontend lint fmt gate e2e demo demo-down

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f

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
