"""Evaluation harness: run every case through the full graph and report cost/latency.

    uv run remediation-eval                 # uses APP_MODE / JEV_MODE from the environment
    uv run remediation-eval --concurrency 4

Writes `eval/results/<timestamp>.json` (raw per-case records) and `eval/results/latest.md`
(the tables quoted in the README). Every report is stamped with the runtime mode; numbers
from offline/mock runs describe the harness, not Bedrock or Jev.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import math
import statistics
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

from remediation_rag.config import Settings, get_settings
from remediation_rag.container import build_container
from remediation_rag.eval.dataset import EvalCase, load_cases
from remediation_rag.service import RemediationResult, RemediationService, RuntimeInfo

logger = logging.getLogger(__name__)

RESULTS_DIR = Path(__file__).resolve().parent / "results"


class CaseRecord(BaseModel):
    case_id: str
    expected_status: str
    status: str
    correct_route: bool
    attempts: int
    retries: int
    scores: dict[str, float] | None
    latency_ms: float
    jev_latency_ms: float
    jev_calls: int
    jev_decisions: int
    generation_input_tokens: int
    generation_output_tokens: int
    generation_usd: float
    jev_usd: float
    llm_judge_decision_usd: float


class Report(BaseModel):
    generated_at: str
    runtime: RuntimeInfo
    cases: list[CaseRecord]


def percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile (no interpolation) - honest for small samples."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100 * len(ordered)))
    return ordered[rank - 1]


def to_record(case: EvalCase, result: RemediationResult) -> CaseRecord:
    jev_usage = [u for u in result.usage if u.provider == "jev"]
    return CaseRecord(
        case_id=case.id,
        expected_status=case.expected_status.value,
        status=result.status.value,
        correct_route=result.status is case.expected_status,
        attempts=result.attempts,
        retries=result.retries,
        scores={d: s.value for d, s in result.scores.as_dict().items()} if result.scores else None,
        latency_ms=result.latency_ms,
        jev_latency_ms=round(sum(u.latency_ms for u in jev_usage), 2),
        jev_calls=result.cost.jev_calls,
        jev_decisions=result.cost.jev_decisions,
        generation_input_tokens=result.cost.generation_input_tokens,
        generation_output_tokens=result.cost.generation_output_tokens,
        generation_usd=result.cost.generation_usd,
        jev_usd=result.cost.jev_usd,
        llm_judge_decision_usd=result.cost.llm_judge_decision_usd,
    )


async def run_cases(
    service: RemediationService, cases: tuple[EvalCase, ...], concurrency: int
) -> list[CaseRecord]:
    semaphore = asyncio.Semaphore(concurrency)

    async def run_one(case: EvalCase) -> CaseRecord:
        async with semaphore:
            result = await service.remediate(case.to_request(), request_id=f"eval-{case.id}")
            return to_record(case, result)

    return list(await asyncio.gather(*(run_one(c) for c in cases)))


def _fmt_usd(value: float) -> str:
    return f"${value:.6f}" if value < 0.01 else f"${value:.4f}"


def render_markdown(report: Report) -> str:
    cases = report.cases
    runtime = report.runtime
    remediated = [c for c in cases if c.attempts > 0]
    gen = sum(c.generation_usd for c in cases)
    jev = sum(c.jev_usd for c in cases)
    judge = sum(c.llm_judge_decision_usd for c in cases)
    latencies = [c.latency_ms for c in cases]
    remediated_latencies = [c.latency_ms for c in remediated]
    jev_latencies = [c.jev_latency_ms for c in cases]
    decisions = sum(c.jev_decisions for c in cases)

    lines = [
        f"# Eval results - {report.generated_at}",
        "",
        f"**Runtime:** app_mode=`{runtime.app_mode}`, jev=`{runtime.jev}`, "
        f"generator=`{runtime.generator}`, vector store=`{runtime.vector_store}`",
        "",
    ]
    if runtime.warnings:
        lines += [
            "> **Not a measurement of Bedrock/Jev.** " + " ".join(runtime.warnings),
            "> Token counts for mocked calls are local estimates; latencies are local compute.",
            "",
        ]
    lines += [
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Cases | {len(cases)} |",
        f"| Correct routing (shipped / rejected as expected) | "
        f"{sum(c.correct_route for c in cases)}/{len(cases)} |",
        f"| Shipped / human review / rejected | {sum(c.status == 'shipped' for c in cases)} / "
        f"{sum(c.status == 'human_review_required' for c in cases)} / "
        f"{sum(c.status == 'rejected' for c in cases)} |",
        f"| Retries triggered (total) | {sum(c.retries for c in cases)} |",
        f"| Mean attempts per remediated case | "
        f"{statistics.fmean([c.attempts for c in remediated]) if remediated else 0:.2f} |",
        f"| End-to-end latency P50 / P95 (all) | {percentile(latencies, 50):.0f} ms / "
        f"{percentile(latencies, 95):.0f} ms |",
        f"| End-to-end latency P50 / P95 (remediated) | "
        f"{percentile(remediated_latencies, 50):.0f} ms / "
        f"{percentile(remediated_latencies, 95):.0f} ms |",
        f"| Jev decision time per request P50 / P95 | {percentile(jev_latencies, 50):.1f} ms / "
        f"{percentile(jev_latencies, 95):.1f} ms |",
        "",
        "## Cost: Jev-gated decisions vs. LLM-judge decisions",
        "",
        f"{decisions} typed decisions across {sum(c.jev_calls for c in cases)} Jev calls.",
        "",
        "| | Generation | Decisions | Total |",
        "|---|---|---|---|",
        f"| Jev as decision layer (this run) | {_fmt_usd(gen)} | {_fmt_usd(jev)} | "
        f"{_fmt_usd(gen + jev)} |",
        f"| LLM judge for every decision (counterfactual) | {_fmt_usd(gen)} | {_fmt_usd(judge)} | "
        f"{_fmt_usd(gen + judge)} |",
        "",
        f"Decision-layer cost ratio: **{judge / jev:.0f}x** cheaper with Jev; "
        f"total pipeline cost **{(1 - (gen + jev) / (gen + judge)) * 100:.1f}%** lower."
        if jev > 0 and gen + judge > 0
        else "Decision-layer cost ratio: n/a",
        "",
        "## Per case",
        "",
        "| Case | Expected | Status | Attempts | groundedness | security | framework | "
        "Latency (ms) | Gen tokens in/out |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for c in cases:
        s = c.scores or {}
        lines.append(
            f"| {c.case_id} | {c.expected_status} | {c.status}{'' if c.correct_route else ' (!)'} "
            f"| {c.attempts} | {s.get('groundedness', '-')} | {s.get('security_correctness', '-')} "
            f"| {s.get('framework_fit', '-')} | {c.latency_ms:.0f} | "
            f"{c.generation_input_tokens}/{c.generation_output_tokens} |"
        )
    return "\n".join(lines) + "\n"


async def evaluate(settings: Settings, concurrency: int) -> Report:
    container = await build_container(settings)
    try:
        records = await run_cases(container.service, load_cases(), concurrency)
    finally:
        await container.aclose()
    return Report(
        generated_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        runtime=container.service.runtime,
        cases=records,
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--out", type=Path, default=RESULTS_DIR)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING)

    report = asyncio.run(evaluate(get_settings(), args.concurrency))
    args.out.mkdir(parents=True, exist_ok=True)
    stamp = report.generated_at.replace(":", "").replace("-", "")
    (args.out / f"{stamp}.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")
    markdown = render_markdown(report)
    (args.out / "latest.md").write_text(markdown, encoding="utf-8")
    print(markdown)


if __name__ == "__main__":
    main()
