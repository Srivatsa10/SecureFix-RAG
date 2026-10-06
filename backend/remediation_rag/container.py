"""Composition root: build every dependency from Settings, explicitly and visibly."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from remediation_rag.clients.jev import HttpJevClient, JevClient
from remediation_rag.clients.jev_mock import MockJevClient
from remediation_rag.config import AppMode, JevMode, Settings
from remediation_rag.generation import PatchGenerator
from remediation_rag.graph.builder import build_graph
from remediation_rag.graph.edges import RoutingPolicy
from remediation_rag.graph.nodes import PipelineConfig, RemediationNodes
from remediation_rag.ingestion.pipeline import build_plan, ingest
from remediation_rag.ingestion.sources import supported_vuln_classes
from remediation_rag.retrieval.index import KnowledgeIndex
from remediation_rag.service import RemediationService, RuntimeInfo

logger = logging.getLogger(__name__)


@dataclass
class Container:
    service: RemediationService
    _closers: list[Callable[[], Awaitable[None]]] = field(default_factory=list)

    async def aclose(self) -> None:
        for close in self._closers:
            await close()


@dataclass(frozen=True)
class DecisionLayer:
    client: JevClient
    kind: str  # "jev" | "llm_judge" | "mock"
    label: str
    close: Callable[[], Awaitable[None]] | None = None


def _build_decision_layer(settings: Settings) -> DecisionLayer:
    mode = settings.resolved_jev_mode
    if mode is JevMode.LIVE:
        if settings.jev_api_key is None:
            raise ValueError("JEV_MODE=live requires JEV_API_KEY")
        client = HttpJevClient(
            settings.jev_api_key.get_secret_value(),
            base_url=settings.jev_base_url,
            model=settings.jev_model,
            timeout_seconds=settings.jev_timeout_seconds,
            max_attempts=settings.jev_max_attempts,
        )
        return DecisionLayer(client, "jev", f"Jev ({settings.jev_model})", client.aclose)
    if mode is JevMode.LLM:
        from remediation_rag.clients.bedrock import build_judge_model
        from remediation_rag.clients.llm_judge import LlmJudgeClient

        judge = LlmJudgeClient(
            build_judge_model(settings),
            settings.bedrock_judge_model_id,
            max_attempts=settings.judge_max_attempts,
        )
        return DecisionLayer(
            judge, "llm_judge", f"LLM judge (Bedrock {settings.bedrock_judge_model_id})"
        )
    return DecisionLayer(MockJevClient(), "mock", "MOCK (local heuristics, not the real Jev model)")


async def _build_index_and_generator(
    settings: Settings,
) -> tuple[KnowledgeIndex, PatchGenerator, str, str]:
    if settings.app_mode is AppMode.LIVE:
        from remediation_rag.clients.bedrock import BedrockClient, build_embeddings
        from remediation_rag.retrieval.factory import build_pinecone_index

        index = build_pinecone_index(settings, build_embeddings(settings))
        generator = BedrockClient.from_settings(settings)
        return (
            index,
            generator,
            f"bedrock ({settings.bedrock_generation_model_id})",
            f"bedrock ({settings.bedrock_embedding_model_id})",
        )

    from remediation_rag.clients.offline import HashingEmbeddings, OfflinePatchGenerator
    from remediation_rag.retrieval.factory import build_memory_index

    index = build_memory_index(HashingEmbeddings())
    plan = build_plan(settings.data_cache_dir / "owasp", offline=True)
    counts = await ingest(index, plan)
    logger.info("offline index loaded: %s (digest=%s)", counts, plan.used_digest)
    return (
        index,
        OfflinePatchGenerator(),
        "OFFLINE (rule-based rewrite, no LLM)",
        "OFFLINE (hashed bag-of-words)",
    )


async def build_container(settings: Settings) -> Container:
    decisions = _build_decision_layer(settings)
    jev = decisions.client
    index, generator, generator_label, embeddings_label = await _build_index_and_generator(settings)

    warnings = []
    if decisions.kind == "mock":
        warnings.append("Jev is mocked: decision scores come from local heuristics.")
    elif decisions.kind == "llm_judge":
        warnings.append(
            "No Jev API key: decisions are made by an LLM judge on Bedrock "
            "(higher cost and latency than Jev)."
        )
    if generator.is_offline:
        warnings.append("Offline mode: patches come from a rule-based rewriter, not Bedrock.")

    config = PipelineConfig(
        max_retries=settings.max_retries,
        score_threshold=settings.score_threshold,
        intent_threshold=settings.intent_threshold,
        relevance_threshold=settings.relevance_threshold,
        top_k=settings.retrieval_top_k,
        supported_vuln_classes=frozenset(vc.value for vc in supported_vuln_classes()),
    )
    graph = build_graph(
        RemediationNodes(jev, generator, index, config),
        RoutingPolicy(score_threshold=settings.score_threshold),
    )
    runtime = RuntimeInfo(
        app_mode=settings.app_mode.value,
        decision_layer=decisions.kind,
        jev=decisions.label,
        generator=generator_label,
        vector_store=index.label,
        embeddings=embeddings_label,
        warnings=warnings,
    )
    for warning in warnings:
        logger.warning(warning)
    return Container(
        service=RemediationService(graph, settings, runtime),
        _closers=[decisions.close] if decisions.close else [],
    )
