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

**Prerequisites:** Python 3.12+ with [uv](https://docs.astral.sh/uv/), Node 20+.

```bash
cp .env.example .env
```

```bash
make install
```

Start the backend (http://localhost:8000):

```bash
make backend
```

In a second terminal, start the frontend (http://localhost:5173):

```bash
make frontend
```

Then open http://localhost:5173, pick an example and click **Generate patch**.

**No API keys are needed to try it.** By default (`APP_MODE=offline`, `JEV_MODE=mock`)
the app uses clearly labelled local stand-ins for Bedrock, Pinecone and Jev. To use the
real services, fill in `.env` (AWS, Pinecone and Jev keys), set `APP_MODE=live` /
`JEV_MODE=live`, and load the knowledge base:

```bash
make ingest
```

### Other commands

| Command | What it does |
|---|---|
| `docker compose up --build` | Run both services in containers (UI on :5173) |
| `make demo CASE=py-dynamic-order-by` | Print the graph's decision trace in the terminal |
| `make eval` | Run the evaluation harness (cost and latency report) |
| `make test` | Run backend and frontend tests |
| `make lint` | Lint and type-check both apps |

API docs are served at http://localhost:8000/docs once the backend is running.
