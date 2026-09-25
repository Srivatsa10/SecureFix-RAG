"""Application service: runs the graph and assembles the public result."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from pydantic import BaseModel

from remediation_rag.config import Settings
from remediation_rag.costing import CostSummary, summarize_costs
from remediation_rag.domain import (
    Chunk,
    EvaluationScores,
    PatchDraft,
    RemediationRequest,
    RemediationStatus,
)
from remediation_rag.graph.state import GraphState, NodeName
from remediation_rag.telemetry import TraceEvent, UsageRecord, stopwatch

logger = logging.getLogger(__name__)


class RuntimeInfo(BaseModel):
    """Which implementations served the request. Surfaced so mocks are never mistaken for real."""

    app_mode: str
    jev: str
    generator: str
    vector_store: str
    embeddings: str
    warnings: list[str]


class ResolvedCitation(BaseModel):
    chunk_id: str
    reason: str
    known: bool
    title: str = ""
    source: str = ""
    source_path: str = ""
    language: str = ""
    framework: str = ""
    relevance: float | None = None
    excerpt: str = ""


class RemediationResult(BaseModel):
    request_id: str
    status: RemediationStatus
    requires_human_review: bool
    vuln_class: str | None
    vuln_confidence: float | None
    intent_probability: float | None
    rejection_reason: str | None
    handoff_reason: str | None
    patch: PatchDraft | None
    citations: list[ResolvedCitation]
    scores: EvaluationScores | None
    score_threshold: float
    attempts: int
    retries: int
    latency_ms: float
    trace: list[TraceEvent]
    usage: list[UsageRecord]
    cost: CostSummary
    runtime: RuntimeInfo


def _resolve_citations(draft: PatchDraft, chunks: list[Chunk]) -> list[ResolvedCitation]:
    by_id = {c.id: c for c in chunks}
    resolved = []
    for citation in draft.citations:
        chunk = by_id.get(citation.chunk_id)
        if chunk is None:
            resolved.append(
                ResolvedCitation(chunk_id=citation.chunk_id, reason=citation.reason, known=False)
            )
            continue
        resolved.append(
            ResolvedCitation(
                chunk_id=chunk.id,
                reason=citation.reason,
                known=True,
                title=chunk.title,
                source=chunk.source.value,
                source_path=chunk.source_path,
                language=chunk.language,
                framework=chunk.framework,
                relevance=chunk.relevance,
                excerpt=chunk.text[:600],
            )
        )
    return resolved


class RemediationService:
    def __init__(self, graph: Any, settings: Settings, runtime: RuntimeInfo) -> None:
        self._graph = graph
        self._settings = settings
        self.runtime = runtime

    async def remediate(
        self, request: RemediationRequest, *, request_id: str | None = None
    ) -> RemediationResult:
        request_id = request_id or uuid.uuid4().hex[:12]
        # Recursion limit: each attempt is ~6 steps; leave headroom over MAX_RETRIES.
        config = {"recursion_limit": 10 + 8 * (self._settings.max_retries + 1)}
        with stopwatch() as watch:
            final: GraphState = await self._graph.ainvoke({"request": request}, config=config)
        result = self._assemble(request_id, final, watch.elapsed_ms)
        logger.info(
            "remediation %s: status=%s attempts=%d latency=%.0fms",
            request_id,
            result.status,
            result.attempts,
            result.latency_ms,
        )
        return result

    def _assemble(self, request_id: str, state: GraphState, latency_ms: float) -> RemediationResult:
        status = state.get("status", RemediationStatus.HUMAN_REVIEW_REQUIRED)
        trace = state.get("trace", [])
        usage = state.get("usage", [])
        attempts = sum(1 for e in trace if e.node == NodeName.DRAFT_PATCH)

        patch: PatchDraft | None = None
        scores: EvaluationScores | None = None
        chunks: list[Chunk] = []
        handoff_reason: str | None = None

        if status is RemediationStatus.SHIPPED:
            patch, scores = state.get("draft"), state.get("scores")
            chunks = state.get("context_chunks", [])
        elif status is RemediationStatus.HUMAN_REVIEW_REQUIRED:
            best = state.get("best_attempt")
            if best is not None:
                patch, scores, chunks = best.draft, best.scores, best.context_chunks
                failing = best.scores.failing(self._settings.score_threshold)
                handoff_reason = (
                    f"After {attempts} attempts the best draft still scored below "
                    f"{self._settings.score_threshold:.2f} on: {', '.join(failing)}. "
                    "Treat the patch below as a starting point, not a fix."
                )
            else:
                handoff_reason = (
                    f"No draft could be evaluated in {attempts} attempts "
                    f"({state.get('draft_error') or 'unknown error'})."
                )

        return RemediationResult(
            request_id=request_id,
            status=status,
            requires_human_review=status is RemediationStatus.HUMAN_REVIEW_REQUIRED,
            vuln_class=state.get("vuln_class"),
            vuln_confidence=state.get("vuln_confidence"),
            intent_probability=state.get("intent_probability"),
            rejection_reason=state.get("rejection_reason"),
            handoff_reason=handoff_reason,
            patch=patch,
            citations=_resolve_citations(patch, chunks) if patch else [],
            scores=scores,
            score_threshold=self._settings.score_threshold,
            attempts=attempts,
            retries=max(0, attempts - 1),
            latency_ms=round(latency_ms, 1),
            trace=trace,
            usage=usage,
            cost=summarize_costs(usage, self._settings),
            runtime=self.runtime,
        )
