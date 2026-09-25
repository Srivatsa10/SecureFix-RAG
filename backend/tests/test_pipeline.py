"""End-to-end graph runs (offline index + generator) and cost accounting."""

import pytest

from remediation_rag.clients.offline import OfflinePatchGenerator
from remediation_rag.config import Settings
from remediation_rag.container import build_container
from remediation_rag.costing import summarize_costs
from remediation_rag.domain import RemediationRequest, RemediationStatus
from remediation_rag.graph.builder import build_graph
from remediation_rag.graph.edges import RoutingPolicy
from remediation_rag.graph.nodes import PipelineConfig, RemediationNodes
from remediation_rag.graph.state import NodeName
from remediation_rag.service import RemediationService, RuntimeInfo
from remediation_rag.telemetry import UsageRecord
from tests.conftest import PY_VULN, ScriptedJev
from tests.test_nodes import FailingGenerator

RUNTIME = RuntimeInfo(
    app_mode="test",
    jev="scripted",
    generator="offline",
    vector_store="mem",
    embeddings="hash",
    warnings=[],
)


def service(jev, index, settings: Settings, generator=None) -> RemediationService:
    config = PipelineConfig(
        max_retries=settings.max_retries,
        score_threshold=settings.score_threshold,
        intent_threshold=settings.intent_threshold,
        relevance_threshold=settings.relevance_threshold,
        top_k=settings.retrieval_top_k,
        supported_vuln_classes=frozenset({"sql_injection"}),
    )
    graph = build_graph(
        RemediationNodes(jev, generator or OfflinePatchGenerator(), index, config),
        RoutingPolicy(settings.score_threshold),
    )
    return RemediationService(graph, settings, RUNTIME)


async def test_default_offline_container_ships_python_fix(settings):
    container = await build_container(settings)
    result = await container.service.remediate(PY_VULN)
    assert result.status is RemediationStatus.SHIPPED
    assert "%s" in result.patch.patched_code
    assert all(c.known for c in result.citations)
    assert result.runtime.warnings, "offline/mock mode must be surfaced"
    assert result.cost.priced_mock_calls


async def test_out_of_scope_never_reaches_generator(settings, memory_index):
    result = await service(ScriptedJev(in_scope=0.1), memory_index, settings).remediate(
        RemediationRequest(code="tell me a joke")
    )
    assert result.status is RemediationStatus.REJECTED
    assert [e.node for e in result.trace] == [NodeName.INTENT_GATE, NodeName.REJECT]
    assert result.cost.generation_usd == 0


async def test_low_scores_hand_off_with_best_partial(settings, memory_index):
    jev = ScriptedJev(scores=[0.4, 0.7, 0.5, 0.6])
    result = await service(jev, memory_index, settings).remediate(PY_VULN)
    assert result.status is RemediationStatus.HUMAN_REVIEW_REQUIRED
    assert result.requires_human_review
    assert result.attempts == settings.max_retries + 1 and result.retries == settings.max_retries
    assert result.scores.groundedness.value == pytest.approx(0.7)  # best attempt, not last
    assert result.patch is not None and "below" in result.handoff_reason


async def test_retry_then_ship(settings, memory_index):
    result = await service(ScriptedJev(scores=[0.5, 0.9]), memory_index, settings).remediate(
        PY_VULN
    )
    assert result.status is RemediationStatus.SHIPPED
    assert result.retries == 1
    retry = next(e for e in result.trace if e.node == NodeName.RETRY_WITH_ADJUSTED_RETRIEVAL)
    assert "strategy=" in retry.summary


async def test_generator_failures_hand_off_without_scores(settings, memory_index):
    result = await service(ScriptedJev(), memory_index, settings, FailingGenerator()).remediate(
        PY_VULN
    )
    assert result.status is RemediationStatus.HUMAN_REVIEW_REQUIRED
    assert result.patch is None
    assert "No draft could be evaluated" in result.handoff_reason


def test_cost_summary_counterfactual(settings):
    usage = [
        UsageRecord(
            node="draft_patch", provider="bedrock", model="m", input_tokens=2000, output_tokens=500
        ),
        UsageRecord(
            node="evaluate_draft", provider="jev", model="j", input_tokens=1000, decisions=3
        ),
    ]
    cost = summarize_costs(usage, settings)
    assert cost.generation_usd == pytest.approx(
        2000 * settings.price_generation_input_per_m / 1e6
        + 500 * settings.price_generation_output_per_m / 1e6
    )
    assert cost.jev_usd == pytest.approx(1000 * 0.042 / 1e6)
    judge = (1000 + 350) * 1.0 / 1e6 + 3 * 150 * 5.0 / 1e6
    assert cost.llm_judge_decision_usd == pytest.approx(judge)
    assert cost.decision_cost_ratio == pytest.approx(judge / cost.jev_usd, rel=1e-2)
