# Eval results - 2026-10-06T23:43:12Z

**Runtime:** app_mode=`offline`, decisions=`MOCK (local heuristics, not the real Jev model)`, generator=`OFFLINE (rule-based rewrite, no LLM)`, vector store=`in-memory (offline)`

> **Read with care.** Jev is mocked: decision scores come from local heuristics. Offline mode: patches come from a rule-based rewriter, not Bedrock.
> Token counts for mocked calls are local estimates; latencies are local compute.

## Summary

| Metric | Value |
|---|---|
| Cases | 12 |
| Correct routing (shipped / rejected as expected) | 9/12 |
| Shipped / human review / rejected | 7 / 3 / 2 |
| Retries triggered (total) | 11 |
| Mean attempts per remediated case | 2.10 |
| End-to-end latency P50 / P95 (all) | 4 ms / 15 ms |
| End-to-end latency P50 / P95 (remediated) | 6 ms / 15 ms |
| Decision-layer time per request P50 / P95 | 0.5 ms / 2.3 ms |

## Cost: Jev decisions vs. LLM-judge decisions

Decision layer this run: **mock**. 277 typed decisions across 54 decision calls.

| | Generation | Decisions | Total |
|---|---|---|---|
| Jev as decision layer (this run) | $0.0537 | $0.005711 | $0.0595 |
| LLM judge for every decision (counterfactual) | $0.0537 | $0.3626 | $0.4164 |

Decision-layer cost ratio: **63x** cheaper with Jev; total pipeline cost **85.7%** lower.

## Per case

| Case | Expected | Status | Attempts | groundedness | security | framework | Latency (ms) | Gen tokens in/out |
|---|---|---|---|---|---|---|---|---|
| py-psycopg-fstring | shipped | shipped | 1 | 0.993 | 0.895 | 0.852 | 6 | 1264/243 |
| py-sqlite-concat | shipped | human_review_required (!) | 4 | 0.984 | 0.891 | 0.634 | 15 | 5722/1093 |
| py-django-raw-percent | shipped | shipped | 2 | 0.934 | 0.937 | 0.908 | 6 | 1779/500 |
| py-sqlalchemy-text-fstring | shipped | shipped | 2 | 1.0 | 0.935 | 0.909 | 6 | 2782/551 |
| py-dynamic-order-by | shipped | human_review_required (!) | 4 | 1.0 | 0.365 | 0.869 | 14 | 5854/696 |
| js-pg-template-literal | shipped | shipped | 1 | 0.987 | 0.933 | 0.85 | 4 | 1317/268 |
| js-mysql-concat | shipped | human_review_required (!) | 4 | 0.984 | 0.874 | 0.612 | 14 | 4800/964 |
| js-sequelize-query | shipped | shipped | 1 | 1.0 | 0.944 | 0.879 | 3 | 1136/272 |
| java-jdbc-statement | shipped | shipped | 1 | 0.98 | 1.0 | 0.991 | 4 | 1396/355 |
| java-jpa-createquery | shipped | shipped | 1 | 0.997 | 0.88 | 0.884 | 4 | 1401/316 |
| out-of-scope-chat | rejected | rejected | 0 | - | - | - | 1 | 0/0 |
| unsupported-xss | rejected | rejected | 0 | - | - | - | 1 | 0/0 |
