# Eval results - 2026-09-25T16:57:26Z

**Runtime:** app_mode=`offline`, jev=`MOCK (local heuristics, not the real Jev model)`, generator=`OFFLINE (rule-based rewrite, no LLM)`, vector store=`in-memory (offline)`

> **Not a measurement of Bedrock/Jev.** Jev is mocked: decision scores come from local heuristics. Offline mode: patches come from a rule-based rewriter, not Bedrock.
> Token counts for mocked calls are local estimates; latencies are local compute.

## Summary

| Metric | Value |
|---|---|
| Cases | 12 |
| Correct routing (shipped / rejected as expected) | 9/12 |
| Shipped / human review / rejected | 7 / 3 / 2 |
| Retries triggered (total) | 11 |
| Mean attempts per remediated case | 2.10 |
| End-to-end latency P50 / P95 (all) | 4 ms / 14 ms |
| End-to-end latency P50 / P95 (remediated) | 6 ms / 14 ms |
| Jev decision time per request P50 / P95 | 0.4 ms / 2.1 ms |

## Cost: Jev-gated decisions vs. LLM-judge decisions

277 typed decisions across 54 Jev calls.

| | Generation | Decisions | Total |
|---|---|---|---|
| Jev as decision layer (this run) | $0.2687 | $0.005711 | $0.2744 |
| LLM judge for every decision (counterfactual) | $0.2687 | $0.3626 | $0.6313 |

Decision-layer cost ratio: **63x** cheaper with Jev; total pipeline cost **56.5%** lower.

## Per case

| Case | Expected | Status | Attempts | groundedness | security | framework | Latency (ms) | Gen tokens in/out |
|---|---|---|---|---|---|---|---|---|
| py-psycopg-fstring | shipped | shipped | 1 | 0.993 | 0.895 | 0.852 | 6 | 1264/243 |
| py-sqlite-concat | shipped | human_review_required (!) | 4 | 0.984 | 0.891 | 0.634 | 14 | 5722/1093 |
| py-django-raw-percent | shipped | shipped | 2 | 0.934 | 0.937 | 0.908 | 7 | 1779/500 |
| py-sqlalchemy-text-fstring | shipped | shipped | 2 | 1.0 | 0.935 | 0.909 | 6 | 2782/551 |
| py-dynamic-order-by | shipped | human_review_required (!) | 4 | 1.0 | 0.365 | 0.869 | 14 | 5854/696 |
| js-pg-template-literal | shipped | shipped | 1 | 0.987 | 0.933 | 0.85 | 4 | 1317/268 |
| js-mysql-concat | shipped | human_review_required (!) | 4 | 0.984 | 0.874 | 0.612 | 13 | 4800/964 |
| js-sequelize-query | shipped | shipped | 1 | 1.0 | 0.944 | 0.879 | 3 | 1136/272 |
| java-jdbc-statement | shipped | shipped | 1 | 0.98 | 1.0 | 0.991 | 4 | 1396/355 |
| java-jpa-createquery | shipped | shipped | 1 | 0.997 | 0.88 | 0.884 | 3 | 1401/316 |
| out-of-scope-chat | rejected | rejected | 0 | - | - | - | 1 | 0/0 |
| unsupported-xss | rejected | rejected | 0 | - | - | - | 1 | 0/0 |
