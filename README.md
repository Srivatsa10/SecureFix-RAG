# RemediationRAG

RemediationRAG turns a detected vulnerability (starting with SQL injection) into a
specific, reviewable code patch.

1. **Gates** the request: checks it is a remediation request and classifies the
   vulnerability. Off-topic requests and unsupported classes (anything but SQL injection
   for now) are rejected.
2. **Retrieves** your approved secure-code snippets and current OWASP guidance (Pinecone,
   two namespaces), then keeps only the chunks judged relevant to this finding.
3. **Drafts** a patch that follows your framework's conventions (Claude Haiku 4.5 on
   AWS Bedrock, one call per attempt).
4. **Scores** the draft from 0 to 1 for groundedness, security correctness and framework
   fit.
5. **Ships, retries or escalates.** If every score is at least 0.85, the patch ships.
   Otherwise it retries with retrieval adjusted for the weakest score (more OWASP
   guidance, narrower framework snippets, or wider internal recall), and after 3 failed
   retries it hands off to a human reviewer.

Every decision (scope, vulnerability class, chunk relevance, scores) is made by the
**decision layer**: Jev, a fast and cheap typed decision model, when `JEV_API_KEY` is set.
**No Jev key?** An adversarial LLM judge on Bedrock (Claude Haiku 4.5, temperature 0)
answers the same typed questions instead, under a reviewer prompt that assumes every
patch is broken until proven otherwise.

The pipeline is a LangGraph state machine served by FastAPI, with a React + Vite UI that
shows the patch diff, the scores, the citations, the decision trace and the cost of the
run (including what the other decision layer would have cost).

## Getting started

**Prerequisites:** Python 3.12 or 3.13 with [uv](https://docs.astral.sh/uv/) for the backend, and
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

**To use the real services:**
1. Fill in `.env`:
   - a Bedrock API key (`AWS_BEARER_TOKEN_BEDROCK`), or other AWS credentials, with
     access to Claude Haiku 4.5 and Titan Embeddings V2,
   - a [pinecone.io](https://www.pinecone.io) API key,
   - optionally a Jev API key.
2. Leave `APP_MODE=live` and `JEV_MODE=auto`. With a Jev key, decisions go to Jev;
   without one, they go to the LLM judge on Bedrock (slower and costlier, but no extra
   account needed). To force one, set `JEV_MODE` to `live` (Jev, key required), `llm`
   (LLM judge) or `mock` (local heuristics).
3. Load the knowledge base (embeds with Titan and upserts into the `remediation-rag`
   Pinecone index, creating it if needed):

```bash
cd backend && uv run remediation-ingest
```

Add `--dry-run` to only chunk the corpus and print stats, with no keys needed.

Every other setting (model IDs, index name, score threshold, retry count, token prices)
has a default in [`backend/remediation_rag/config.py`](backend/remediation_rag/config.py)
and can be overridden in `.env` in UPPER_CASE, for example `MAX_RETRIES=2`.

### Other commands

| Command | What it does |
|---|---|
| `docker compose up --build` | Run both services in containers (UI on :5173, API on :8000). Uses `APP_MODE` from `.env`, or `offline` if there is none |
| `cd backend && uv run remediation-demo --case py-dynamic-order-by` | Print the graph's decision trace in the terminal (`--list` shows the example ids, `--file` runs your own code) |
| `cd backend && uv run remediation-eval` | Run the evaluation harness over the 12 example cases; writes the cost and latency report to `backend/remediation_rag/eval/results/latest.md` |
| `cd backend && uv run pytest` | Backend tests |
| `cd frontend && npm test` | Frontend tests |

If you have `make`, the `Makefile` has shortcuts for these: `make install`,
`make backend`, `make frontend`, `make test`, `make lint`, `make ingest`,
`make ingest-dry-run`, `make demo` (`CASE=<id>` to choose), `make eval`, `make up` and
`make down`. Run `make help` to list them.

**No keys at all?** Set `APP_MODE=offline` in `.env` (it is also the default when no
`.env` exists). The app then runs end to end on clearly labelled local stand-ins: a
rule-based patch rewriter instead of Bedrock, an in-memory index with hashed embeddings
instead of Pinecone, and heuristic mock decisions. The UI and every API response show
which components are real.

API docs are served at http://localhost:8000/docs once the backend is running. The main
endpoints are `POST /api/remediations`, `GET /api/examples` and `GET /api/health`.
