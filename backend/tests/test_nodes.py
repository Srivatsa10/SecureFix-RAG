"""Unit tests per node, with a scripted Jev and the offline index/generator."""

import pytest

from remediation_rag.clients.offline import OfflinePatchGenerator
from remediation_rag.domain import (
    Chunk,
    DimensionScore,
    EvaluationScores,
    RemediationStatus,
    SourceKind,
)
from remediation_rag.generation import DraftContext, DraftGenerationError, GenerationResult
from remediation_rag.graph.nodes import PipelineConfig, RemediationNodes
from remediation_rag.graph.retrieval_plans import adjust_plan, initial_plan
from remediation_rag.graph.state import NodeName
from tests.conftest import PY_VULN, ScriptedJev

CONFIG = PipelineConfig(
    max_retries=3,
    score_threshold=0.85,
    intent_threshold=0.6,
    relevance_threshold=0.5,
    top_k=4,
    supported_vuln_classes=frozenset({"sql_injection"}),
)


def nodes(jev: ScriptedJev, index, generator=None) -> RemediationNodes:
    return RemediationNodes(jev, generator or OfflinePatchGenerator(), index, CONFIG)


def chunk(id_: str, source: SourceKind) -> Chunk:
    return Chunk(id=id_, source=source, text="text", vuln_class="sql_injection", source_path="p")


def uniform_scores(value: float) -> EvaluationScores:
    s = DimensionScore(value=value, confidence=0.9, level="x")
    return EvaluationScores(groundedness=s, security_correctness=s, framework_fit=s)


# ---------------------------------------------------------------- intent_gate
async def test_intent_gate_batches_scope_and_class_in_one_call(memory_index):
    jev = ScriptedJev()
    update = await nodes(jev, memory_index).intent_gate({"request": PY_VULN})
    assert len(jev.calls) == 1 and set(jev.calls[0]) == {"in_scope", "vuln_class"}
    assert update["in_scope"] is True
    assert update["plan"].internal_filters == {
        "vuln_class": "sql_injection",
        "language": ["python", "any"],
    }


@pytest.mark.parametrize(
    ("jev", "reason"),
    [
        (ScriptedJev(in_scope=0.2), "Out of scope"),
        (ScriptedJev(vuln_class="xss"), "no ingested guidance"),
    ],
)
async def test_intent_gate_rejects(memory_index, jev, reason):
    update = await nodes(jev, memory_index).intent_gate({"request": PY_VULN})
    assert update["in_scope"] is False
    assert reason in update["rejection_reason"]
    assert "plan" not in update


# ---------------------------------------------------------------- retrieve_dual
async def test_retrieve_dual_queries_both_namespaces_with_filters(memory_index):
    plan = initial_plan(PY_VULN, "sql_injection", top_k=3)
    update = await nodes(ScriptedJev(), memory_index).retrieve_dual(
        {"request": PY_VULN, "plan": plan}
    )
    candidates = update["candidates"]
    internal = [c for c in candidates if c.source is SourceKind.INTERNAL]
    owasp = [c for c in candidates if c.source is SourceKind.OWASP]
    assert len(internal) == 3 and len(owasp) == 3
    assert all(c.language in ("python", "any") for c in internal)


# ---------------------------------------------------------------- rerank_chunks
async def test_rerank_uses_one_batched_call_and_drops_low_relevance(memory_index):
    jev = ScriptedJev(relevance=0.2)
    candidates = [chunk(f"i{i}", SourceKind.INTERNAL) for i in range(3)] + [
        chunk(f"o{i}", SourceKind.OWASP) for i in range(3)
    ]
    update = await nodes(jev, memory_index).rerank_chunks(
        {"request": PY_VULN, "vuln_class": "sql_injection", "candidates": candidates}
    )
    assert len(jev.calls) == 1 and len(jev.calls[0]) == 6
    # All below threshold -> keep the single best of each source rather than starve the generator.
    kept = update["context_chunks"]
    assert {c.source for c in kept} == {SourceKind.INTERNAL, SourceKind.OWASP} and len(kept) == 2
    assert update["usage"][0].decisions == 6


async def test_rerank_dedupes_candidates(memory_index):
    jev = ScriptedJev()
    dup = chunk("same", SourceKind.INTERNAL)
    update = await nodes(jev, memory_index).rerank_chunks(
        {"request": PY_VULN, "candidates": [dup, dup, chunk("o", SourceKind.OWASP)]}
    )
    assert len(jev.calls[0]) == 2
    assert len(update["context_chunks"]) == 2


# ---------------------------------------------------------------- draft_patch
async def test_draft_patch_records_usage_and_unknown_citations(memory_index):
    context_chunks = [chunk("internal:a#0", SourceKind.INTERNAL)]
    update = await nodes(ScriptedJev(), memory_index).draft_patch(
        {"request": PY_VULN, "vuln_class": "sql_injection", "context_chunks": context_chunks}
    )
    assert "%s" in update["draft"].patched_code
    assert update["usage"][0].node == NodeName.DRAFT_PATCH
    assert update["trace"][0].data["unknown_citations"] == []


class FailingGenerator:
    is_offline = True

    async def generate(self, context: DraftContext) -> GenerationResult:
        raise DraftGenerationError("model returned prose")


async def test_draft_patch_failure_is_captured_not_raised(memory_index):
    update = await nodes(ScriptedJev(), memory_index, FailingGenerator()).draft_patch(
        {"request": PY_VULN, "context_chunks": []}
    )
    assert update["draft"] is None and "prose" in update["draft_error"]


async def test_draft_patch_passes_previous_scores_as_feedback(memory_index):
    seen: list[DraftContext] = []

    class Spy(OfflinePatchGenerator):
        async def generate(self, context):
            seen.append(context)
            return await super().generate(context)

    await nodes(ScriptedJev(), memory_index, Spy()).draft_patch(
        {"request": PY_VULN, "context_chunks": [], "scores": uniform_scores(0.5)}
    )
    assert seen[0].previous_feedback == {
        "groundedness": 0.5,
        "security_correctness": 0.5,
        "framework_fit": 0.5,
    }


# ---------------------------------------------------------------- evaluate_draft
async def test_evaluate_draft_returns_three_dimensions_and_tracks_best(memory_index):
    n = nodes(ScriptedJev(scores=[0.6]), memory_index)
    draft = (await n.draft_patch({"request": PY_VULN, "context_chunks": []}))["draft"]
    update = await n.evaluate_draft({"request": PY_VULN, "draft": draft, "context_chunks": []})
    scores = update["scores"]
    assert scores.groundedness.value == pytest.approx(0.6)
    assert scores.failing(0.85) == ["groundedness", "security_correctness", "framework_fit"]
    assert update["best_attempt"].scores == scores


async def test_evaluate_draft_skips_jev_when_no_draft(memory_index):
    jev = ScriptedJev()
    update = await nodes(jev, memory_index).evaluate_draft({"request": PY_VULN, "draft": None})
    assert update["scores"] is None and jev.calls == []


# ---------------------------------------------------------------- circuit_breaker
@pytest.mark.parametrize(
    ("attempt", "tripped", "next_attempt"), [(0, False, 1), (2, False, 3), (3, True, 3)]
)
async def test_circuit_breaker(memory_index, attempt, tripped, next_attempt):
    update = await nodes(ScriptedJev(), memory_index).circuit_breaker({"attempt": attempt})
    assert update["breaker_tripped"] is tripped
    assert update["attempt"] == next_attempt


# ---------------------------------------------------------------- retry plans
@pytest.mark.parametrize(
    ("weakest", "strategy"),
    [
        ("security_correctness", "deepen_owasp_guidance"),
        ("framework_fit", "narrow_to_framework"),
        ("groundedness", "widen_internal_recall"),
        (None, "regenerate_same_context"),
    ],
)
def test_adjust_plan_targets_weakest_dimension(weakest, strategy):
    base = initial_plan(PY_VULN, "sql_injection", top_k=4)
    plan = adjust_plan(base, PY_VULN, weakest)
    assert plan.strategy == strategy
    if strategy == "narrow_to_framework":
        assert plan.internal_filters["framework"] == "psycopg"
    if strategy == "deepen_owasp_guidance":
        assert plan.owasp_k > base.owasp_k


def test_framework_fit_second_retry_relaxes_to_query_patterns():
    base = initial_plan(PY_VULN, "sql_injection", top_k=4)
    once = adjust_plan(base, PY_VULN, "framework_fit")
    twice = adjust_plan(once, PY_VULN, "framework_fit")
    assert twice.strategy == "narrow_to_query_patterns"
    assert "framework" not in twice.internal_filters


# ---------------------------------------------------------------- terminals
async def test_terminal_statuses(memory_index):
    n = nodes(ScriptedJev(), memory_index)
    assert (await n.finalize({}))["status"] is RemediationStatus.SHIPPED
    assert (await n.human_handoff({}))["status"] is RemediationStatus.HUMAN_REVIEW_REQUIRED
    assert (await n.reject({}))["status"] is RemediationStatus.REJECTED
