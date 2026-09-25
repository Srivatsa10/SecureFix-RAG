"""AWS Bedrock client: patch generation (Converse API) and Titan text embeddings.

LangChain's `ChatBedrockConverse` / `BedrockEmbeddings` are used as the integration
glue; the chat model is injectable so tests can substitute a fake.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from langchain_core.embeddings import Embeddings
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from remediation_rag.config import Settings
from remediation_rag.generation import (
    SYSTEM_PROMPT,
    DraftContext,
    DraftGenerationError,
    GenerationResult,
    parse_draft,
    render_user_prompt,
)
from remediation_rag.telemetry import stopwatch

logger = logging.getLogger(__name__)


def build_chat_model(settings: Settings) -> BaseChatModel:
    from langchain_aws import ChatBedrockConverse

    kwargs: dict[str, Any] = {
        "model_id": settings.bedrock_generation_model_id,
        "region_name": settings.aws_region,
        "max_tokens": settings.bedrock_generation_max_tokens,
    }
    if settings.aws_profile:
        kwargs["credentials_profile_name"] = settings.aws_profile
    return ChatBedrockConverse(**kwargs)


def build_embeddings(settings: Settings) -> Embeddings:
    from langchain_aws import BedrockEmbeddings

    kwargs: dict[str, Any] = {
        "model_id": settings.bedrock_embedding_model_id,
        "region_name": settings.aws_region,
        "dimensions": settings.bedrock_embedding_dimensions,
        "normalize": True,
    }
    if settings.aws_profile:
        kwargs["credentials_profile_name"] = settings.aws_profile
    return BedrockEmbeddings(**kwargs)


class BedrockClient:
    """Generates patch drafts with a Bedrock-hosted model. The only generation-heavy call."""

    def __init__(self, chat_model: BaseChatModel, model_id: str) -> None:
        self._chat = chat_model
        self._model_id = model_id

    @classmethod
    def from_settings(cls, settings: Settings) -> BedrockClient:
        return cls(build_chat_model(settings), settings.bedrock_generation_model_id)

    @property
    def is_offline(self) -> bool:
        return False

    async def generate(self, context: DraftContext) -> GenerationResult:
        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=render_user_prompt(context)),
        ]
        with stopwatch() as watch:
            try:
                reply = await self._chat.ainvoke(messages)
            except Exception as exc:  # boto/botocore raise a wide range of error types
                logger.exception("Bedrock generation failed")
                raise DraftGenerationError(f"Bedrock call failed: {exc}") from exc

        if not isinstance(reply, AIMessage):
            raise DraftGenerationError(f"unexpected reply type {type(reply).__name__}")
        usage: Mapping[str, Any] = reply.usage_metadata or {}
        return GenerationResult(
            draft=parse_draft(reply.text),
            model=self._model_id,
            input_tokens=int(usage.get("input_tokens", 0)),
            output_tokens=int(usage.get("output_tokens", 0)),
            latency_ms=watch.elapsed_ms,
        )
