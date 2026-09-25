"""Graph node implementations.

Division of labour:
* Jev makes every decision (scope, vulnerability class, chunk relevance, rubric scores).
* Bedrock is called exactly once per attempt, in `draft_patch`.
* Everything else is deterministic bookkeeping.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

from remediation_rag.clients.jev import JevClient, JevError, JevResult
from remediation_rag.domain import (
    SCORE_DIMENSIONS,
    Chunk,
    DimensionScore,
    EvaluationScores,
    PatchDraft,
    RemediationStatus,
    SourceKind,
)
from remediation_rag.generation import DraftContext, DraftGenerationError, PatchGenerator
from remediation_rag.graph import questions as q
from remediation_rag.graph.retrieval_plans import adjust_plan, initial_plan
from remediation_rag.graph.state import Attempt, GraphState, NodeName
from remediation_rag.retrieval.index import KnowledgeIndex
from remediation_rag.telemetry import TraceEvent, UsageRecord, stopwatch

logger = logging.getLogger(__name__)

# Truncation budgets keep every Jev request well inside its 32K-token window.
CODE_BUDGET = 6_000
CHUNK_BUDGET = 1_500
MAX_RERANK_CANDIDATES = 16


@dataclass(frozen=True)
class PipelineConfig:
    max_retries: int
    score_threshold: float
    intent_threshold: float
    relevance_threshold: float
    top_k: int
    supported_vuln_classes: frozenset[str]
    min_chunks_per_source: int = 1


def _clip(text: str, budget: int) -> str:
    return text if len(text) <= budget else text[:budget] + "\n... [truncated]"


def _finding(state: GraphState) -> dict[str, Any]:
    request = state["request"]
    return {
        "vuln_class": state.get("vuln_class"),
        "language": request.language.value if request.language else None,
        "framework": request.framework,
        "description": request.description,
        "code": _clip(request.code, CODE_BUDGET),
    }


def _chunk_view(chunk: Chunk) -> dict[str, Any]:
    return {
        "id": chunk.id,
        "source": chunk.source.value,
        "title": chunk.title,
        "vuln_class": chunk.vuln_class,
        "language": chunk.language,
        "framework": chunk.framework,
        "kind": chunk.kind,
        "text": _clip(chunk.text, CHUNK_BUDGET),
    }


def _jev_usage(node: str, result: JevResult, decisions: int) -> UsageRecord:
    return UsageRecord(
        node=node,
        provider="jev",
        model=result.model,
        input_tokens=result.usage.input_tokens,
        output_tokens=result.usage.output_tokens,
        latency_ms=round(result.latency_ms, 2),
        decisions=decisions,
        mocked=result.mocked,
    )


class RemediationNodes:
    def __init__(
        self,
        jev: JevClient,
        generator: PatchGenerator,
        index: KnowledgeIndex,
        config: PipelineConfig,
    ) -> None:
        self._jev = jev
        self._generator = generator
        self._index = index
        self._config = config

    # ------------------------------------------------------------------ intent_gate
    async def intent_gate(self, state: GraphState) -> dict[str, Any]:
        request = state["request"]
        jev_state = {
            "request": {
                "code": _clip(request.code, CODE_BUDGET),
                "description": request.description,
                "language": request.language.value if request.language else None,
                "framework": request.framework,
                "file_path": request.file_path,
            }
        }
        with stopwatch() as watch:
            result = await self._jev.ask(jev_state, q.intent_questions())
        intent = result.noul(q.IN_SCOPE).probability
        vuln = result.choice(q.VULN_CLASS)

        rejection: str | None = None
        if intent < self._config.intent_threshold:
            rejection = (
                f"Out of scope: Jev scored this as a remediation request with p={intent:.2f} "
                f"(threshold {self._config.intent_threshold:.2f})."
            )
        elif vuln.choice not in self._config.supported_vuln_classes:
            rejection = (
                f"Classified as {vuln.choice!r} (confidence {vuln.confidence:.2f}); this "
                "vulnerability class has no ingested guidance yet."
            )

        update: dict[str, Any] = {
            "in_scope": rejection is None,
            "intent_probability": intent,
            "vuln_class": vuln.choice,
            "vuln_confidence": vuln.confidence,
            "rejection_reason": rejection,
            "attempt": 0,
            "usage": [_jev_usage(NodeName.INTENT_GATE, result, decisions=2)],
            "trace": [
                TraceEvent(
                    node=NodeName.INTENT_GATE,
                    attempt=0,
                    summary=(
                        f"in_scope p={intent:.2f}; class={vuln.choice} "
                        f"(conf {vuln.confidence:.2f}) -> "
                        + ("reject" if rejection else "continue")
                    ),
                    data={
                        "jev": {
                            "in_scope": intent,
                            "vuln_class": vuln.choice,
                            "vuln_class_probabilities": vuln.probabilities,
                        }
                    },
                    duration_ms=round(watch.elapsed_ms, 2),
                )
            ],
        }
        if rejection is None:
            update["plan"] = initial_plan(request, vuln.choice, self._config.top_k)
        return update

    async def reject(self, state: GraphState) -> dict[str, Any]:
        return {
            "status": RemediationStatus.REJECTED,
            "trace": [
                TraceEvent(
                    node=NodeName.REJECT,
                    attempt=0,
                    summary=state.get("rejection_reason") or "rejected",
                )
            ],
        }

    # ------------------------------------------------------------------ retrieve_dual
    async def retrieve_dual(self, state: GraphState) -> dict[str, Any]:
        request = state["request"]
        plan = state["plan"]
        query = " ".join(
            part
            for part in (
                request.description or "",
                request.framework or "",
                plan.query_focus,
                _clip(request.code, 2_000),
            )
            if part
        )
        relaxed = False
        with stopwatch() as watch:
            internal, owasp = await asyncio.gather(
                self._index.search(
                    SourceKind.INTERNAL, query, plan.internal_k, plan.internal_filters
                ),
                self._index.search(SourceKind.OWASP, query, plan.owasp_k, plan.owasp_filters),
            )
            if not internal and "framework" in plan.internal_filters:
                # The caller's framework has no approved snippets; fall back to the language.
                filters = {k: v for k, v in plan.internal_filters.items() if k != "framework"}
                internal = await self._index.search(
                    SourceKind.INTERNAL, query, plan.internal_k, filters
                )
                relaxed = True
        return {
            "candidates": internal + owasp,
            "trace": [
                TraceEvent(
                    node=NodeName.RETRIEVE_DUAL,
                    attempt=state.get("attempt", 0),
                    summary=(
                        f"strategy={plan.strategy}: {len(internal)} internal + "
                        f"{len(owasp)} OWASP candidates"
                        + (" (no snippets for framework; relaxed filter)" if relaxed else "")
                    ),
                    data={
                        "plan": plan.model_dump(),
                        "internal": [c.id for c in internal],
                        "owasp": [c.id for c in owasp],
                    },
                    duration_ms=round(watch.elapsed_ms, 2),
                )
            ],
        }

    # ------------------------------------------------------------------ rerank_chunks
    async def rerank_chunks(self, state: GraphState) -> dict[str, Any]:
        candidates = list({c.id: c for c in state.get("candidates", [])}.values())
        candidates = candidates[:MAX_RERANK_CANDIDATES]
        attempt = state.get("attempt", 0)
        if not candidates:
            return {
                "context_chunks": [],
                "trace": [
                    TraceEvent(
                        node=NodeName.RERANK_CHUNKS, attempt=attempt, summary="no candidates"
                    )
                ],
            }

        keys = [q.relevance_key(i) for i in range(len(candidates))]
        jev_state = {
            "finding": _finding(state),
            "chunks": {
                key.removeprefix(q.RELEVANT_PREFIX): _chunk_view(c)
                for key, c in zip(keys, candidates, strict=True)
            },
        }
        questions = {key: q.relevance_question(key.removeprefix(q.RELEVANT_PREFIX)) for key in keys}
        with stopwatch() as watch:
            result = await self._jev.ask(jev_state, questions)  # one batched call

        scored = [
            c.model_copy(update={"relevance": result.noul(key).probability})
            for key, c in zip(keys, candidates, strict=True)
        ]
        threshold = self._config.relevance_threshold
        kept = [c for c in scored if (c.relevance or 0) >= threshold]
        # Never starve the generator of a whole source: keep the best of each if all dropped.
        for source in SourceKind:
            if sum(c.source is source for c in kept) < self._config.min_chunks_per_source:
                best = sorted(
                    (c for c in scored if c.source is source and c not in kept),
                    key=lambda c: c.relevance or 0,
                    reverse=True,
                )
                kept.extend(best[: self._config.min_chunks_per_source])
        kept.sort(key=lambda c: c.relevance or 0, reverse=True)

        return {
            "context_chunks": kept,
            "usage": [_jev_usage(NodeName.RERANK_CHUNKS, result, decisions=len(questions))],
            "trace": [
                TraceEvent(
                    node=NodeName.RERANK_CHUNKS,
                    attempt=attempt,
                    summary=(
                        f"Jev Noul x{len(questions)} in 1 call: kept {len(kept)}, "
                        f"dropped {len(scored) - len(kept)} (threshold {threshold:.2f})"
                    ),
                    data={"jev": {c.id: c.relevance for c in scored}},
                    duration_ms=round(watch.elapsed_ms, 2),
                )
            ],
        }

    # ------------------------------------------------------------------ draft_patch
    async def draft_patch(self, state: GraphState) -> dict[str, Any]:
        attempt = state.get("attempt", 0)
        chunks = state.get("context_chunks", [])
        previous = state.get("scores")
        context = DraftContext(
            request=state["request"],
            vuln_class=state.get("vuln_class") or "unknown",
            internal_chunks=[c for c in chunks if c.source is SourceKind.INTERNAL],
            owasp_chunks=[c for c in chunks if c.source is SourceKind.OWASP],
            previous_feedback=(
                {d: s.value for d, s in previous.as_dict().items()} if previous else {}
            ),
            attempt=attempt,
        )
        try:
            generation = await self._generator.generate(context)
        except DraftGenerationError as exc:
            logger.warning("draft generation failed on attempt %d: %s", attempt, exc)
            return {
                "draft": None,
                "draft_error": str(exc),
                "trace": [
                    TraceEvent(
                        node=NodeName.DRAFT_PATCH,
                        attempt=attempt,
                        summary=f"generation failed: {exc}",
                    )
                ],
            }

        known_ids = {c.id for c in chunks}
        unknown = [c.chunk_id for c in generation.draft.citations if c.chunk_id not in known_ids]
        return {
            "draft": generation.draft,
            "draft_error": None,
            "usage": [
                UsageRecord(
                    node=NodeName.DRAFT_PATCH,
                    provider="offline" if generation.offline else "bedrock",
                    model=generation.model,
                    input_tokens=generation.input_tokens,
                    output_tokens=generation.output_tokens,
                    latency_ms=round(generation.latency_ms, 2),
                    mocked=generation.offline,
                )
            ],
            "trace": [
                TraceEvent(
                    node=NodeName.DRAFT_PATCH,
                    attempt=attempt,
                    summary=(
                        f"{generation.model}: {generation.input_tokens} in / "
                        f"{generation.output_tokens} out tokens, "
                        f"{len(generation.draft.citations)} citations"
                        + (f", {len(unknown)} unknown" if unknown else "")
                    ),
                    data={"unknown_citations": unknown, "feedback": context.previous_feedback},
                    duration_ms=round(generation.latency_ms, 2),
                )
            ],
        }

    # ------------------------------------------------------------------ evaluate_draft
    async def evaluate_draft(self, state: GraphState) -> dict[str, Any]:
        attempt = state.get("attempt", 0)
        draft: PatchDraft | None = state.get("draft")
        if draft is None:
            return {
                "scores": None,
                "trace": [
                    TraceEvent(
                        node=NodeName.EVALUATE_DRAFT,
                        attempt=attempt,
                        summary="no draft to evaluate (generation failed) - skipped Jev call",
                    )
                ],
            }

        jev_state = {
            "finding": _finding(state),
            "draft": {
                "explanation": draft.explanation,
                "patched_code": _clip(draft.patched_code, CODE_BUDGET),
                "conventions_applied": draft.conventions_applied,
                "citations": [c.model_dump() for c in draft.citations],
            },
            "sources": [_chunk_view(c) for c in state.get("context_chunks", [])],
        }
        try:
            with stopwatch() as watch:
                result = await self._jev.ask(jev_state, q.evaluation_questions())
        except JevError as exc:
            logger.warning("evaluation failed on attempt %d: %s", attempt, exc)
            return {
                "scores": None,
                "trace": [
                    TraceEvent(
                        node=NodeName.EVALUATE_DRAFT, attempt=attempt, summary=f"Jev error: {exc}"
                    )
                ],
            }

        dims = {}
        for dim in SCORE_DIMENSIONS:
            answer = result.score(dim)
            dims[dim] = DimensionScore(
                value=round(answer.normalized, 3),
                confidence=answer.confidence,
                level=answer.level.split(":")[0],
            )
        scores = EvaluationScores(**dims)
        failing = scores.failing(self._config.score_threshold)

        best = state.get("best_attempt")
        if best is None or scores.minimum() > best.scores.minimum():
            best = Attempt(
                attempt=attempt,
                draft=draft,
                scores=scores,
                context_chunks=state.get("context_chunks", []),
            )

        summary = ", ".join(f"{d}={s.value:.2f}" for d, s in scores.as_dict().items())
        verdict = "pass" if not failing else f"fail ({', '.join(failing)})"
        return {
            "scores": scores,
            "best_attempt": best,
            "usage": [_jev_usage(NodeName.EVALUATE_DRAFT, result, decisions=len(dims))],
            "trace": [
                TraceEvent(
                    node=NodeName.EVALUATE_DRAFT,
                    attempt=attempt,
                    summary=f"Jev Score: {summary} -> {verdict}",
                    data={
                        "jev": {d: s.model_dump() for d, s in scores.as_dict().items()},
                        "threshold": self._config.score_threshold,
                        "failing": failing,
                    },
                    duration_ms=round(watch.elapsed_ms, 2),
                )
            ],
        }

    # ------------------------------------------------------------------ circuit_breaker
    async def circuit_breaker(self, state: GraphState) -> dict[str, Any]:
        attempt = state.get("attempt", 0)
        tripped = attempt >= self._config.max_retries
        return {
            "breaker_tripped": tripped,
            "attempt": attempt if tripped else attempt + 1,
            "trace": [
                TraceEvent(
                    node=NodeName.CIRCUIT_BREAKER,
                    attempt=attempt,
                    summary=(
                        f"retries used {attempt}/{self._config.max_retries} -> "
                        + ("TRIPPED, handing off to a human" if tripped else "retry")
                    ),
                )
            ],
        }

    # ------------------------------------------------------------------ retry
    async def retry_with_adjusted_retrieval(self, state: GraphState) -> dict[str, Any]:
        scores = state.get("scores")
        weakest = scores.weakest() if scores else None
        plan = adjust_plan(state["plan"], state["request"], weakest)
        return {
            "plan": plan,
            "trace": [
                TraceEvent(
                    node=NodeName.RETRY_WITH_ADJUSTED_RETRIEVAL,
                    attempt=state.get("attempt", 0),
                    summary=f"weakest={weakest or 'n/a'} -> strategy={plan.strategy}",
                    data={"plan": plan.model_dump()},
                )
            ],
        }

    # ------------------------------------------------------------------ terminals
    async def finalize(self, state: GraphState) -> dict[str, Any]:
        return {
            "status": RemediationStatus.SHIPPED,
            "trace": [
                TraceEvent(
                    node=NodeName.FINALIZE,
                    attempt=state.get("attempt", 0),
                    summary="all rubric dimensions cleared the threshold - shipping patch",
                )
            ],
        }

    async def human_handoff(self, state: GraphState) -> dict[str, Any]:
        best = state.get("best_attempt")
        return {
            "status": RemediationStatus.HUMAN_REVIEW_REQUIRED,
            "trace": [
                TraceEvent(
                    node=NodeName.HUMAN_HANDOFF,
                    attempt=state.get("attempt", 0),
                    summary=(
                        "automated remediation did not clear the bar; returning best partial "
                        f"attempt #{best.attempt} for security-engineer review"
                        if best
                        else "no evaluable draft produced; escalating to a security engineer"
                    ),
                )
            ],
        }
