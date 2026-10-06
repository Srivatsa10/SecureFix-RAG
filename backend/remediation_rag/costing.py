"""Cost accounting for generation and for the decision layer, Jev vs. LLM judge.

Every run makes its decisions with one engine and estimates the other:

* Decision layer = Jev (or mocked Jev): Jev cost is priced from the tokens reported per
  call. The LLM-judge figure is a counterfactual - each Jev request replaced by one judge
  request reading the same state plus a rubric prompt and writing a short verdict:

      judge_input  = decision_input_tokens + judge_prompt_overhead_tokens
      judge_output = judge_output_tokens_per_decision * decisions_in_that_call

* Decision layer = LLM judge (no Jev key): judge cost is priced from the real input and
  output tokens Bedrock reported. The Jev figure is the estimate: the same input tokens at
  Jev's input price (Jev output is free).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Literal

from pydantic import BaseModel

from remediation_rag.config import Settings
from remediation_rag.telemetry import UsageRecord

DecisionLayerKind = Literal["jev", "llm_judge", "none"]


class CostSummary(BaseModel):
    generation_usd: float
    generation_input_tokens: int
    generation_output_tokens: int
    # Which engine made this run's decisions; the other engine's cost is an estimate.
    decision_layer: DecisionLayerKind
    decision_calls: int
    decisions: int
    decision_input_tokens: int
    decision_output_tokens: int
    jev_usd: float
    llm_judge_decision_usd: float
    total_usd: float  # actual: generation + the decision layer that ran
    total_with_jev_usd: float
    total_with_llm_judge_usd: float
    decision_cost_ratio: float | None  # LLM judge cost / Jev cost
    priced_mock_calls: bool


def _per_m(tokens: int, price_per_m: float) -> float:
    return tokens * price_per_m / 1_000_000


def summarize_costs(usage: Iterable[UsageRecord], settings: Settings) -> CostSummary:
    records = list(usage)
    generation = [r for r in records if r.provider in ("bedrock", "offline")]
    decision = [r for r in records if r.provider in ("jev", "llm_judge")]
    layer: DecisionLayerKind = (
        "llm_judge"
        if any(r.provider == "llm_judge" for r in decision)
        else ("jev" if decision else "none")
    )

    gen_in = sum(r.input_tokens for r in generation)
    gen_out = sum(r.output_tokens for r in generation)
    generation_usd = _per_m(gen_in, settings.price_generation_input_per_m) + _per_m(
        gen_out, settings.price_generation_output_per_m
    )

    dec_in = sum(r.input_tokens for r in decision)
    dec_out = sum(r.output_tokens for r in decision)
    jev_usd = _per_m(dec_in, settings.price_jev_input_per_m)  # Jev output tokens are free

    if layer == "llm_judge":
        judge_usd = _per_m(dec_in, settings.price_judge_input_per_m) + _per_m(
            dec_out, settings.price_judge_output_per_m
        )
    else:
        judge_usd = sum(
            _per_m(
                r.input_tokens + settings.judge_prompt_overhead_tokens,
                settings.price_judge_input_per_m,
            )
            + _per_m(
                settings.judge_output_tokens_per_decision * r.decisions,
                settings.price_judge_output_per_m,
            )
            for r in decision
        )

    actual_decision_usd = judge_usd if layer == "llm_judge" else jev_usd
    return CostSummary(
        generation_usd=round(generation_usd, 6),
        generation_input_tokens=gen_in,
        generation_output_tokens=gen_out,
        decision_layer=layer,
        decision_calls=len(decision),
        decisions=sum(r.decisions for r in decision),
        decision_input_tokens=dec_in,
        decision_output_tokens=dec_out,
        jev_usd=round(jev_usd, 8),
        llm_judge_decision_usd=round(judge_usd, 6),
        total_usd=round(generation_usd + actual_decision_usd, 6),
        total_with_jev_usd=round(generation_usd + jev_usd, 6),
        total_with_llm_judge_usd=round(generation_usd + judge_usd, 6),
        decision_cost_ratio=round(judge_usd / jev_usd, 1) if jev_usd > 0 else None,
        priced_mock_calls=any(r.mocked for r in records),
    )
