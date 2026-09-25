"""Cost accounting, including the "what if every decision were an LLM call" comparison.

Measured side: token counts reported by Bedrock and Jev for this run, priced with the
configured per-million-token rates.

Counterfactual side (an estimate, by construction - those calls were never made): each
Jev request is replaced by one LLM-judge request that reads the same state plus a
rubric/instruction prompt and writes a short structured verdict per decision:

    judge_input  = jev_input_tokens + judge_prompt_overhead_tokens
    judge_output = judge_output_tokens_per_decision * decisions_in_that_call
"""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel

from remediation_rag.config import Settings
from remediation_rag.telemetry import UsageRecord


class CostSummary(BaseModel):
    generation_usd: float
    jev_usd: float
    total_usd: float
    jev_calls: int
    jev_decisions: int
    jev_input_tokens: int
    generation_input_tokens: int
    generation_output_tokens: int
    # Counterfactual: same decisions made by an LLM judge instead of Jev.
    llm_judge_decision_usd: float
    total_with_llm_judge_usd: float
    decision_cost_ratio: float | None
    priced_mock_calls: bool


def _per_m(tokens: int, price_per_m: float) -> float:
    return tokens * price_per_m / 1_000_000


def summarize_costs(usage: Iterable[UsageRecord], settings: Settings) -> CostSummary:
    records = list(usage)
    generation = [r for r in records if r.provider in ("bedrock", "offline")]
    jev = [r for r in records if r.provider == "jev"]

    gen_in = sum(r.input_tokens for r in generation)
    gen_out = sum(r.output_tokens for r in generation)
    generation_usd = _per_m(gen_in, settings.price_generation_input_per_m) + _per_m(
        gen_out, settings.price_generation_output_per_m
    )

    jev_in = sum(r.input_tokens for r in jev)
    jev_usd = _per_m(jev_in, settings.price_jev_input_per_m)  # Jev output tokens are free

    judge_usd = sum(
        _per_m(
            r.input_tokens + settings.judge_prompt_overhead_tokens, settings.price_judge_input_per_m
        )
        + _per_m(
            settings.judge_output_tokens_per_decision * r.decisions,
            settings.price_judge_output_per_m,
        )
        for r in jev
    )

    return CostSummary(
        generation_usd=round(generation_usd, 6),
        jev_usd=round(jev_usd, 8),
        total_usd=round(generation_usd + jev_usd, 6),
        jev_calls=len(jev),
        jev_decisions=sum(r.decisions for r in jev),
        jev_input_tokens=jev_in,
        generation_input_tokens=gen_in,
        generation_output_tokens=gen_out,
        llm_judge_decision_usd=round(judge_usd, 6),
        total_with_llm_judge_usd=round(generation_usd + judge_usd, 6),
        decision_cost_ratio=round(judge_usd / jev_usd, 1) if jev_usd > 0 else None,
        priced_mock_calls=any(r.mocked for r in records),
    )
