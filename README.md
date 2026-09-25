# RemediationRAG

RemediationRAG turns a detected vulnerability (starting with SQL injection) into a
specific, reviewable code patch.

1. **Retrieves** your approved secure-code snippets and current OWASP guidance (Pinecone).
2. **Drafts** a patch that follows your framework's conventions (AWS Bedrock).
3. **Scores** the draft for groundedness, security correctness and framework fit using
   Jev, a fast and cheap typed decision model.
4. **Ships, retries or escalates.** If every score passes, the patch ships. Otherwise
   it retries with adjusted retrieval, and after 3 retries it hands off to a human
   reviewer.

The pipeline is a LangGraph state machine served by FastAPI, with a React + Vite UI that
shows the patch diff, the scores, the citations and the full decision trace.

## Getting started

**Prerequisites:** Python 3.12+ with [uv](https://docs.astral.sh/uv/) for the backend, and
Node 20+ with npm for the frontend.

```bash
cp .env.example .env
```

**Backend** (FastAPI on http://localhost:8000), in one terminal:

```bash
cd backend && uv sync && uv run uvicorn remediation_rag.api.app:create_app --factory --reload --port 8000
```

**Frontend** (React + Vite on http://localhost:5173), in a second terminal:

```bash
cd frontend && npm install && npm run dev
```

Then open http://localhost:5173, pick an example and click **Generate patch**.

**No API keys are needed to try it.** By default (`APP_MODE=offline`, `JEV_MODE=mock`)
the app uses clearly labelled local stand-ins for Bedrock, Pinecone and Jev. To use the
real services:
1. Fill in `.env`: AWS credentials with Bedrock access to Claude Haiku 4.5 and Titan
   Embeddings V2, a [pinecone.io](https://www.pinecone.io) API key, and a Jev key.
2. Set `APP_MODE=live` and `JEV_MODE=live`.
3. Load the knowledge base:

```bash
cd backend && uv run remediation-ingest
```

### Other commands

| Command | What it does |
|---|---|
| `docker compose up --build` | Run both services in containers (UI on :5173) |
| `cd backend && uv run remediation-demo --case py-dynamic-order-by` | Print the graph's decision trace in the terminal |
| `cd backend && uv run remediation-eval` | Run the evaluation harness (cost and latency report) |
| `cd backend && uv run pytest` | Backend tests |
| `cd frontend && npm test` | Frontend tests |

If you have `make`, the `Makefile` has the same commands as shortcuts: `make install`,
`make backend`, `make frontend`, `make test`, `make demo`, `make eval`. Run `make help`
to list them.

API docs are served at http://localhost:8000/docs once the backend is running.
