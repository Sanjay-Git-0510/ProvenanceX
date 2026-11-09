# Thin wrappers around common commands. Run from the repo root.
PY := backend/.venv/bin

.PHONY: up down logs migrate test test-backend test-frontend lint fmt gate

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

lint:
	cd backend && .venv/bin/ruff check . ../ml/scripts ../scripts --config pyproject.toml && .venv/bin/ruff format --check . ../ml/scripts ../scripts --config pyproject.toml
	cd frontend && npm run lint

fmt:
	cd backend && .venv/bin/ruff format . && .venv/bin/ruff check --fix .
