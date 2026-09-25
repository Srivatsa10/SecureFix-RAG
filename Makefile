.PHONY: help install backend frontend test lint ingest ingest-dry-run eval demo up down

help:  ## Show available targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-16s %s\n", $$1, $$2}'

install:  ## Install backend (uv) and frontend (npm) dependencies
	cd backend && uv sync
	cd frontend && npm ci

backend:  ## Run the FastAPI backend on :8000 (reload)
	cd backend && uv run uvicorn remediation_rag.api.app:create_app --factory --reload --port 8000

frontend:  ## Run the Vite dev server on :5173 (proxies /api to :8000)
	cd frontend && npm run dev

test:  ## Run backend and frontend tests
	cd backend && uv run pytest
	cd frontend && npm test

lint:  ## Lint and type-check both apps
	cd backend && uv run ruff check . && uv run ruff format --check .
	cd frontend && npm run lint && npm run typecheck

ingest-dry-run:  ## Chunk the seed corpus + OWASP cheat sheets and print stats (no keys needed)
	cd backend && uv run remediation-ingest --dry-run

ingest:  ## Embed with Bedrock Titan and upsert into Pinecone (needs keys)
	cd backend && uv run remediation-ingest

eval:  ## Run the evaluation harness (writes backend/remediation_rag/eval/results/latest.md)
	cd backend && uv run remediation-eval

demo:  ## Print the decision trace for one example (CASE=<id> to choose)
	cd backend && uv run remediation-demo $(if $(CASE),--case $(CASE),)

up:  ## Build and run both services with docker compose
	docker compose up --build

down:
	docker compose down
