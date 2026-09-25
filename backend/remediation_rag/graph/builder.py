"""Wire the remediation state machine.

START -> intent_gate -(in scope?)-> retrieve_dual -> rerank_chunks -> draft_patch
      -> evaluate_draft -(all scores >= threshold?)-> finalize -> END
                         \\-> circuit_breaker -(retries left?)-> retry_with_adjusted_retrieval
                                              \\-> human_handoff -> END      -> retrieve_dual
      intent_gate -(out of scope)-> reject -> END
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from remediation_rag.graph.edges import (
    RoutingPolicy,
    make_route_after_evaluation,
    route_after_breaker,
    route_after_intent,
)
from remediation_rag.graph.state import GraphState, NodeName

NodeFn = Callable[[GraphState], Awaitable[dict[str, Any]]]


class NodeSet(Protocol):
    """Implemented by `RemediationNodes`; tests supply stubs to exercise the graph shape."""

    async def intent_gate(self, state: GraphState) -> dict[str, Any]: ...
    async def reject(self, state: GraphState) -> dict[str, Any]: ...
    async def retrieve_dual(self, state: GraphState) -> dict[str, Any]: ...
    async def rerank_chunks(self, state: GraphState) -> dict[str, Any]: ...
    async def draft_patch(self, state: GraphState) -> dict[str, Any]: ...
    async def evaluate_draft(self, state: GraphState) -> dict[str, Any]: ...
    async def circuit_breaker(self, state: GraphState) -> dict[str, Any]: ...
    async def retry_with_adjusted_retrieval(self, state: GraphState) -> dict[str, Any]: ...
    async def finalize(self, state: GraphState) -> dict[str, Any]: ...
    async def human_handoff(self, state: GraphState) -> dict[str, Any]: ...


def build_graph(
    nodes: NodeSet, policy: RoutingPolicy
) -> CompiledStateGraph[GraphState, None, GraphState, GraphState]:
    graph = StateGraph(GraphState)

    for name in (
        NodeName.INTENT_GATE,
        NodeName.REJECT,
        NodeName.RETRIEVE_DUAL,
        NodeName.RERANK_CHUNKS,
        NodeName.DRAFT_PATCH,
        NodeName.EVALUATE_DRAFT,
        NodeName.CIRCUIT_BREAKER,
        NodeName.RETRY_WITH_ADJUSTED_RETRIEVAL,
        NodeName.FINALIZE,
        NodeName.HUMAN_HANDOFF,
    ):
        graph.add_node(name, getattr(nodes, name))

    graph.add_edge(START, NodeName.INTENT_GATE)
    graph.add_conditional_edges(
        NodeName.INTENT_GATE,
        route_after_intent,
        [NodeName.RETRIEVE_DUAL, NodeName.REJECT],
    )
    graph.add_edge(NodeName.RETRIEVE_DUAL, NodeName.RERANK_CHUNKS)
    graph.add_edge(NodeName.RERANK_CHUNKS, NodeName.DRAFT_PATCH)
    graph.add_edge(NodeName.DRAFT_PATCH, NodeName.EVALUATE_DRAFT)
    graph.add_conditional_edges(
        NodeName.EVALUATE_DRAFT,
        make_route_after_evaluation(policy),
        [NodeName.FINALIZE, NodeName.CIRCUIT_BREAKER],
    )
    graph.add_conditional_edges(
        NodeName.CIRCUIT_BREAKER,
        route_after_breaker,
        [NodeName.RETRY_WITH_ADJUSTED_RETRIEVAL, NodeName.HUMAN_HANDOFF],
    )
    graph.add_edge(NodeName.RETRY_WITH_ADJUSTED_RETRIEVAL, NodeName.RETRIEVE_DUAL)
    graph.add_edge(NodeName.FINALIZE, END)
    graph.add_edge(NodeName.HUMAN_HANDOFF, END)
    graph.add_edge(NodeName.REJECT, END)

    return graph.compile()
