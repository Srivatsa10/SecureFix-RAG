"""Patch-generation contract shared by the Bedrock generator and the offline stand-in."""

from __future__ import annotations

import json
import re
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field, ValidationError

from remediation_rag.domain import Chunk, PatchDraft, RemediationRequest, ScoreDimension


class DraftGenerationError(RuntimeError):
    """The generator failed or returned output that could not be parsed into a PatchDraft."""


class DraftContext(BaseModel):
    """Everything `draft_patch` hands to the generator."""

    request: RemediationRequest
    vuln_class: str
    internal_chunks: list[Chunk]
    owasp_chunks: list[Chunk]
    # Populated on retries so the generator can target the dimension that failed.
    previous_feedback: dict[ScoreDimension, float] = Field(default_factory=dict)
    attempt: int = 0


class GenerationResult(BaseModel):
    draft: PatchDraft
    model: str
    input_tokens: int
    output_tokens: int
    latency_ms: float
    offline: bool = False


@runtime_checkable
class PatchGenerator(Protocol):
    @property
    def is_offline(self) -> bool: ...

    async def generate(self, context: DraftContext) -> GenerationResult: ...


# --------------------------------------------------------------------------------------
# Prompting
# --------------------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a senior application-security engineer producing a code patch for a detected \
vulnerability. You ship patches that other engineers will merge, so they must be \
specific to the code provided, not generic advice.

Ground every change in the supplied sources:
- INTERNAL snippets are the company's approved secure patterns. Infer the house \
conventions from them (query API, placeholder style, ORM usage, helper names, error \
handling) and follow those conventions in the patch.
- OWASP guidance defines what a correct fix for this vulnerability class requires.

Close the vulnerability class, not just the visible instance: every untrusted value \
that reaches the query must be bound as a parameter, and identifiers that cannot be \
parameterized (column names, sort direction, table names) must go through an allowlist.

Respond with ONLY one JSON object, no prose before or after it, matching:
{
  "explanation": "why the original is exploitable and how the patch closes it",
  "patched_code": "the full corrected version of the provided code",
  "diff": "unified diff from original to patched code",
  "conventions_applied": ["short phrases naming the internal conventions you followed"],
  "citations": [{"chunk_id": "<id of a provided source>", "reason": "what it contributed"}]
}
Cite only chunk ids that appear in the sources. Do not invent helpers that are neither in \
the original code nor in the internal snippets."""

_DIMENSION_HINTS: dict[str, str] = {
    "groundedness": (
        "Derive the patch more directly from the cited sources and cite them precisely."
    ),
    "security_correctness": (
        "The previous patch did not fully close the vulnerability: bind every untrusted value "
        "and allowlist any dynamic identifiers."
    ),
    "framework_fit": "Match the internal snippets' framework conventions more closely.",
}


def _render_chunks(chunks: list[Chunk]) -> str:
    if not chunks:
        return "(none retrieved)"
    parts = []
    for chunk in chunks:
        header = (
            f"[{chunk.id}] {chunk.title or chunk.source_path} "
            f"(language={chunk.language}, framework={chunk.framework}, kind={chunk.kind})"
        )
        parts.append(f"{header}\n{chunk.text}")
    return "\n\n---\n\n".join(parts)


def render_user_prompt(context: DraftContext) -> str:
    request = context.request
    lines = [
        f"Vulnerability class: {context.vuln_class}",
        f"Language: {request.language or 'unspecified'}",
        f"Framework: {request.framework or 'unspecified'}",
    ]
    if request.file_path:
        lines.append(f"File: {request.file_path}")
    if request.description:
        lines.append(f"Finding: {request.description}")
    lines += [
        "",
        "## Vulnerable code",
        "```",
        request.code,
        "```",
        "",
        "## INTERNAL approved secure snippets",
        _render_chunks(context.internal_chunks),
        "",
        "## OWASP guidance",
        _render_chunks(context.owasp_chunks),
    ]
    if context.previous_feedback:
        lines += ["", "## Reviewer feedback on your previous attempt"]
        for dim, value in context.previous_feedback.items():
            lines.append(f"- {dim} scored {value:.2f}: {_DIMENSION_HINTS.get(dim, '')}")
    return "\n".join(lines)


_JSON_FENCE = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL)


def parse_draft(text: str) -> PatchDraft:
    """Parse the model's reply into a PatchDraft, tolerating code fences around the JSON."""
    fenced = _JSON_FENCE.search(text)
    candidate = fenced.group(1) if fenced else text
    start, end = candidate.find("{"), candidate.rfind("}")
    if start == -1 or end <= start:
        raise DraftGenerationError("generator reply contained no JSON object")
    try:
        return PatchDraft.model_validate(json.loads(candidate[start : end + 1]))
    except (json.JSONDecodeError, ValidationError) as exc:
        raise DraftGenerationError(f"generator reply was not a valid PatchDraft: {exc}") from exc
