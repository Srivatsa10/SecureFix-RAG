"""Conditional edges. Pure functions of state; every input they read was produced by Jev.

No edge calls an LLM: routing is decided from Jev's typed outputs (intent probability,
vulnerability class, rubric scores) plus the retry counter.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from remediation_rag.graph.state import GraphState, NodeName


@dataclass(frozen=True)
class RoutingPolicy:
    score_threshold: float


def route_after_intent(state: GraphState) -> str:
    return NodeName.RETRIEVE_DUAL if state.get("in_scope") else NodeName.REJECT


def make_route_after_evaluation(policy: RoutingPolicy) -> Callable[[GraphState], str]:
    def route_after_evaluation(state: GraphState) -> str:
        scores = state.get("scores")
        if scores is not None and not scores.failing(policy.score_threshold):
            return NodeName.FINALIZE
        return NodeName.CIRCUIT_BREAKER

    return route_after_evaluation


def route_after_breaker(state: GraphState) -> str:
    if state.get("breaker_tripped"):
        return NodeName.HUMAN_HANDOFF
    return NodeName.RETRY_WITH_ADJUSTED_RETRIEVAL
