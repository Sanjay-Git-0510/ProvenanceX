# Thin wrappers around common commands. Run from the repo root.
PY := backend/.venv/bin

.PHONY: up down logs migrate test test-backend test-frontend lint fmt

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

lint:
	cd backend && .venv/bin/ruff check . && .venv/bin/ruff format --check .
	cd frontend && npm run lint

fmt:
	cd backend && .venv/bin/ruff format . && .venv/bin/ruff check --fix .
