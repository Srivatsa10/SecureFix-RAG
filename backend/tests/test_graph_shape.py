"""Exercise the graph's wiring with stub nodes (no Jev/Bedrock/index involved)."""

from typing import Any

import pytest

from remediation_rag.domain import DimensionScore, EvaluationScores, RemediationRequest
from remediation_rag.graph.builder import build_graph
from remediation_rag.graph.edges import RoutingPolicy
from remediation_rag.graph.state import GraphState, NodeName
from remediation_rag.telemetry import TraceEvent

MAX_RETRIES = 3


def scores(value: float) -> EvaluationScores:
    s = DimensionScore(value=value, confidence=0.9, level="x")
    return EvaluationScores(groundedness=s, security_correctness=s, framework_fit=s)


class StubNodes:
    def __init__(self, in_scope: bool, score_sequence: list[float]) -> None:
        self.in_scope = in_scope
        self.score_sequence = list(score_sequence)

    @staticmethod
    def _t(node: str, state: GraphState) -> dict[str, Any]:
        return {"trace": [TraceEvent(node=node, attempt=state.get("attempt", 0), summary="stub")]}

    async def intent_gate(self, state):
        return {"in_scope": self.in_scope, "attempt": 0, **self._t(NodeName.INTENT_GATE, state)}

    async def reject(self, state):
        return self._t(NodeName.REJECT, state)

    async def retrieve_dual(self, state):
        return self._t(NodeName.RETRIEVE_DUAL, state)

    async def rerank_chunks(self, state):
        return self._t(NodeName.RERANK_CHUNKS, state)

    async def draft_patch(self, state):
        return self._t(NodeName.DRAFT_PATCH, state)

    async def evaluate_draft(self, state):
        return {
            "scores": scores(self.score_sequence.pop(0)),
            **self._t(NodeName.EVALUATE_DRAFT, state),
        }

    async def circuit_breaker(self, state):
        attempt = state.get("attempt", 0)
        tripped = attempt >= MAX_RETRIES
        return {
            "breaker_tripped": tripped,
            "attempt": attempt if tripped else attempt + 1,
            **self._t(NodeName.CIRCUIT_BREAKER, state),
        }

    async def retry_with_adjusted_retrieval(self, state):
        return self._t(NodeName.RETRY_WITH_ADJUSTED_RETRIEVAL, state)

    async def finalize(self, state):
        return self._t(NodeName.FINALIZE, state)

    async def human_handoff(self, state):
        return self._t(NodeName.HUMAN_HANDOFF, state)


async def run(nodes: StubNodes) -> list[str]:
    graph = build_graph(nodes, RoutingPolicy(score_threshold=0.85))
    final = await graph.ainvoke({"request": RemediationRequest(code="x")})
    return [event.node for event in final["trace"]]


async def test_out_of_scope_short_circuits_to_reject():
    path = await run(StubNodes(in_scope=False, score_sequence=[]))
    assert path == [NodeName.INTENT_GATE, NodeName.REJECT]


async def test_passing_scores_ship_on_first_attempt():
    path = await run(StubNodes(in_scope=True, score_sequence=[0.9]))
    assert path[-2:] == [NodeName.EVALUATE_DRAFT, NodeName.FINALIZE]
    assert NodeName.CIRCUIT_BREAKER not in path


async def test_one_retry_then_ship():
    path = await run(StubNodes(in_scope=True, score_sequence=[0.5, 0.95]))
    assert path.count(NodeName.DRAFT_PATCH) == 2
    assert path.count(NodeName.RETRY_WITH_ADJUSTED_RETRIEVAL) == 1
    assert path[-1] == NodeName.FINALIZE


@pytest.mark.parametrize("threshold_miss", [0.84, 0.1])
async def test_circuit_breaker_hands_off_after_max_retries(threshold_miss):
    path = await run(StubNodes(in_scope=True, score_sequence=[threshold_miss] * (MAX_RETRIES + 1)))
    assert path.count(NodeName.DRAFT_PATCH) == MAX_RETRIES + 1
    assert path[-1] == NodeName.HUMAN_HANDOFF
    assert NodeName.FINALIZE not in path
