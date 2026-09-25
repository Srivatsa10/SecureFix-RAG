"""LangGraph state for the remediation pipeline."""

from __future__ import annotations

import operator
from typing import Annotated, TypedDict

from pydantic import BaseModel, Field

from remediation_rag.domain import (
    Chunk,
    EvaluationScores,
    PatchDraft,
    RemediationRequest,
    RemediationStatus,
)
from remediation_rag.telemetry import TraceEvent, UsageRecord


class NodeName:
    INTENT_GATE = "intent_gate"
    REJECT = "reject"
    RETRIEVE_DUAL = "retrieve_dual"
    RERANK_CHUNKS = "rerank_chunks"
    DRAFT_PATCH = "draft_patch"
    EVALUATE_DRAFT = "evaluate_draft"
    CIRCUIT_BREAKER = "circuit_breaker"
    RETRY_WITH_ADJUSTED_RETRIEVAL = "retry_with_adjusted_retrieval"
    FINALIZE = "finalize"
    HUMAN_HANDOFF = "human_handoff"


class RetrievalPlan(BaseModel):
    """How `retrieve_dual` should query each namespace on this attempt."""

    strategy: str = "initial"
    internal_k: int
    owasp_k: int
    internal_filters: dict[str, str | list[str]] = Field(default_factory=dict)
    owasp_filters: dict[str, str | list[str]] = Field(default_factory=dict)
    query_focus: str = ""


class Attempt(BaseModel):
    """The best-scoring draft so far, kept for the human-handoff partial result."""

    attempt: int
    draft: PatchDraft
    scores: EvaluationScores
    context_chunks: list[Chunk]


class GraphState(TypedDict, total=False):
    # Input
    request: RemediationRequest
    # intent_gate
    in_scope: bool
    intent_probability: float
    vuln_class: str | None
    vuln_confidence: float
    rejection_reason: str | None
    # retrieval
    plan: RetrievalPlan
    candidates: list[Chunk]
    context_chunks: list[Chunk]
    # generation + evaluation
    draft: PatchDraft | None
    draft_error: str | None
    scores: EvaluationScores | None
    best_attempt: Attempt | None
    # control
    attempt: int
    breaker_tripped: bool
    status: RemediationStatus
    # Append-only logs (reducers merge node outputs instead of overwriting).
    trace: Annotated[list[TraceEvent], operator.add]
    usage: Annotated[list[UsageRecord], operator.add]
