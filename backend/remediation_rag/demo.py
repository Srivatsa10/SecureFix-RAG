"""Run one remediation end-to-end and print the graph's decision trace.

uv run remediation-demo                              # default example
uv run remediation-demo --case py-dynamic-order-by   # exercises retries + handoff
uv run remediation-demo --file vuln.py --language python --framework psycopg
uv run remediation-demo --list
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

from remediation_rag.config import get_settings
from remediation_rag.container import build_container
from remediation_rag.domain import Language, RemediationRequest
from remediation_rag.eval.dataset import load_cases
from remediation_rag.graph.state import NodeName
from remediation_rag.service import RemediationResult

_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


NODE_STYLE = {
    NodeName.INTENT_GATE: "35",  # magenta = Jev
    NodeName.RERANK_CHUNKS: "35",
    NodeName.EVALUATE_DRAFT: "35",
    NodeName.DRAFT_PATCH: "34",  # blue = Bedrock
    NodeName.CIRCUIT_BREAKER: "33",
    NodeName.RETRY_WITH_ADJUSTED_RETRIEVAL: "33",
    NodeName.FINALIZE: "32",
    NodeName.HUMAN_HANDOFF: "31",
    NodeName.REJECT: "31",
}


def render(result: RemediationResult) -> str:
    out: list[str] = []
    runtime = result.runtime
    out.append(_c("RemediationRAG - decision trace", "1"))
    out.append(
        f"  jev: {runtime.jev}\n  generator: {runtime.generator}\n  index: {runtime.vector_store}"
    )
    for warning in runtime.warnings:
        out.append(_c(f"  ! {warning}", "33"))
    out.append("")

    for event in result.trace:
        node = _c(f"{event.node:<30}", NODE_STYLE.get(event.node, "0"))
        timing = f"{event.duration_ms:7.1f} ms" if event.duration_ms else " " * 10
        out.append(f"  #{event.attempt} {node} {timing}  {event.summary}")
    out.append("")

    status_color = {"shipped": "32", "rejected": "31", "human_review_required": "33"}
    out.append(
        f"status: {_c(result.status.value, status_color[result.status.value])}   "
        f"attempts: {result.attempts}   retries: {result.retries}   "
        f"latency: {result.latency_ms:.0f} ms"
    )
    if result.rejection_reason:
        out.append(f"reason: {result.rejection_reason}")
    if result.handoff_reason:
        out.append(_c(f"handoff: {result.handoff_reason}", "33"))

    if result.scores:
        out.append(f"\nJev scores (threshold {result.score_threshold:.2f}):")
        for dim, score in result.scores.as_dict().items():
            bar = "#" * round(score.value * 20)
            ok = score.value >= result.score_threshold
            out.append(
                f"  {dim:<22} {score.value:5.2f} {_c(f'{bar:<20}', '32' if ok else '31')} "
                f"conf {score.confidence:.2f}  ({score.level})"
            )

    if result.patch:
        out.append("\n" + _c("patch", "1"))
        out.append(result.patch.diff or result.patch.patched_code)
        out.append(_c("explanation: ", "1") + result.patch.explanation)
        for citation in result.citations:
            flag = "" if citation.known else _c(" [UNKNOWN ID]", "31")
            out.append(f"  cites {citation.chunk_id}{flag}: {citation.reason}")

    cost = result.cost
    out.append(
        "\n"
        + _c("cost", "1")
        + (" (mocked/offline calls priced at list rates)" if cost.priced_mock_calls else "")
    )
    out.append(f"  generation            ${cost.generation_usd:.6f}")
    out.append(
        f"  Jev decisions         ${cost.jev_usd:.8f}  "
        f"({cost.jev_decisions} decisions / {cost.jev_calls} calls)"
    )
    out.append(
        f"  as LLM-judge calls    ${cost.llm_judge_decision_usd:.6f}"
        + (f"  -> {cost.decision_cost_ratio:.0f}x" if cost.decision_cost_ratio else "")
    )
    return "\n".join(out)


def build_request(args: argparse.Namespace) -> RemediationRequest:
    if args.file:
        return RemediationRequest(
            code=Path(args.file).read_text(encoding="utf-8"),
            language=Language(args.language) if args.language else None,
            framework=args.framework,
            description=args.description,
            file_path=args.file,
        )
    cases = {c.id: c for c in load_cases()}
    if args.case not in cases:
        raise SystemExit(f"unknown case {args.case!r}; use --list")
    return cases[args.case].to_request()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--case", default="py-psycopg-fstring")
    parser.add_argument("--file")
    parser.add_argument("--language", choices=[lang.value for lang in Language])
    parser.add_argument("--framework")
    parser.add_argument("--description")
    parser.add_argument("--list", action="store_true", help="list example case ids")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.ERROR)

    if args.list:
        for case in load_cases():
            print(f"{case.id:<28} {case.title}")
        return

    async def run() -> RemediationResult:
        container = await build_container(get_settings())
        try:
            return await container.service.remediate(build_request(args))
        finally:
            await container.aclose()

    print(render(asyncio.run(run())))


if __name__ == "__main__":
    main()
