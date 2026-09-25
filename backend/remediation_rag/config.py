"""Application settings, loaded from environment variables / `.env`.

Every external dependency is selected explicitly here. `APP_MODE=offline` swaps in
clearly-labelled local stand-ins (MockJevClient, hashing embeddings, in-memory vector
store, template generator) so the graph can run without any API keys. The active mode
is surfaced in every API response and in the UI; it is never swapped silently.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = BACKEND_ROOT.parent


class AppMode(StrEnum):
    LIVE = "live"
    OFFLINE = "offline"


class JevMode(StrEnum):
    LIVE = "live"
    MOCK = "mock"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(REPO_ROOT / ".env", BACKEND_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        # `PINECONE_API_KEY=` left blank means "not set", not an empty key.
        env_ignore_empty=True,
    )

    # --- Runtime mode -------------------------------------------------------------------
    app_mode: AppMode = AppMode.OFFLINE
    # Jev can be mocked independently (e.g. real Bedrock + Pinecone, but no Jev access yet).
    jev_mode: JevMode = JevMode.MOCK
    log_level: str = "INFO"

    # --- AWS Bedrock --------------------------------------------------------------------
    aws_region: str = "us-east-1"
    aws_profile: str | None = None
    # Claude Haiku 4.5 via the US cross-region inference profile (on-demand Haiku 4.5 on
    # Bedrock requires an inference profile). Swap the prefix for `global.`/`eu.` as needed.
    bedrock_generation_model_id: str = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
    bedrock_generation_max_tokens: int = 4096
    bedrock_embedding_model_id: str = "amazon.titan-embed-text-v2:0"
    bedrock_embedding_dimensions: int = 1024

    # --- Pinecone (pinecone.io, used directly with an API key) ---------------------------
    # cloud/region only choose where Pinecone hosts the serverless index; the free Starter
    # plan supports aws/us-east-1. No AWS account is involved.
    pinecone_api_key: SecretStr | None = None
    pinecone_index_name: str = "remediation-rag"
    pinecone_cloud: str = "aws"
    pinecone_region: str = "us-east-1"
    pinecone_namespace_internal: str = "internal-secure-code"
    pinecone_namespace_owasp: str = "owasp-guidance"

    # --- Jev (TypeSafe AI) --------------------------------------------------------------
    jev_api_key: SecretStr | None = None
    jev_base_url: str = "https://api.typesafe.ai"
    jev_model: str = "jev-latest"
    jev_timeout_seconds: float = 5.0
    jev_max_attempts: int = 3

    # --- Pipeline tuning ----------------------------------------------------------------
    max_retries: int = Field(default=3, ge=0, le=10)
    score_threshold: float = Field(default=0.85, ge=0.0, le=1.0)
    intent_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    relevance_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    retrieval_top_k: int = Field(default=4, ge=1, le=20)
    max_input_code_chars: int = 20_000

    # --- Cost model (USD per 1M tokens). Bedrock pricing is partner-set: override these
    # with your region's Bedrock price sheet before quoting results. ---------------------
    price_generation_input_per_m: float = 1.00  # Claude Haiku 4.5 list price
    price_generation_output_per_m: float = 5.00
    price_jev_input_per_m: float = 0.042
    # Counterfactual "LLM-as-judge" used in the cost comparison (defaults: Haiku 4.5 list).
    price_judge_input_per_m: float = 1.00
    price_judge_output_per_m: float = 5.00
    judge_output_tokens_per_decision: int = 150
    judge_prompt_overhead_tokens: int = 350

    # --- API ----------------------------------------------------------------------------
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # --- Paths --------------------------------------------------------------------------
    data_cache_dir: Path = BACKEND_ROOT / "data" / "cache"

    @model_validator(mode="after")
    def _check_live_credentials(self) -> Settings:
        if self.app_mode is AppMode.LIVE and self.pinecone_api_key is None:
            raise ValueError("APP_MODE=live requires PINECONE_API_KEY")
        if self.jev_mode is JevMode.LIVE and self.jev_api_key is None:
            raise ValueError("JEV_MODE=live requires JEV_API_KEY")
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
