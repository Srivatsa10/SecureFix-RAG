"""Every Jev question the graph asks, in one place.

Question names are part of the contract with `MockJevClient`'s heuristics, so they are
defined here once and referenced by name everywhere else.
"""

from __future__ import annotations

from remediation_rag.clients.jev import ChoiceQuestion, NoulQuestion, ScoreQuestion
from remediation_rag.domain import VULN_CLASS_DESCRIPTIONS

IN_SCOPE = "in_scope"
VULN_CLASS = "vuln_class"
RELEVANT_PREFIX = "relevant__"
GROUNDEDNESS = "groundedness"
SECURITY_CORRECTNESS = "security_correctness"
FRAMEWORK_FIT = "framework_fit"


def intent_questions() -> dict[str, NoulQuestion | ChoiceQuestion]:
    """Batched into one call: scope gate (Noul) + vulnerability classification (Choice)."""
    return {
        IN_SCOPE: NoulQuestion(
            instructions=(
                "The state is a request sent to an automated security-remediation service. "
                "Is it asking to fix a security vulnerability in the supplied source code?"
            ),
            if_true="It contains source code with a suspected vulnerability to remediate.",
            if_false=(
                "It is not a remediation request: general chat, a question, non-code text, "
                "or code with no security concern."
            ),
        ),
        VULN_CLASS: ChoiceQuestion(
            instructions="Which vulnerability class best describes the issue in request.code?",
            options={vc.value: desc for vc, desc in VULN_CLASS_DESCRIPTIONS.items()},
        ),
    }


def relevance_question(chunk_key: str) -> NoulQuestion:
    return NoulQuestion(
        instructions=(
            f"Would chunks.{chunk_key} directly help write a correct, convention-following "
            "patch for the vulnerability described in `finding`?"
        ),
        if_true=(
            "It shows a secure pattern for the same language/framework or states a defense "
            "that applies to this exact vulnerable code."
        ),
        if_false="It is off-topic, for an unrelated stack, or too generic to shape the patch.",
    )


def relevance_key(index: int) -> str:
    return f"{RELEVANT_PREFIX}c{index}"


_FIVE_LEVELS = {
    GROUNDEDNESS: [
        "Unsupported: the patch or its citations are not traceable to the sources.",
        "Weak: a few elements trace to sources; most is invented.",
        "Partial: the core approach is sourced but notable parts are not.",
        "Strong: nearly everything traces to cited sources; minor unsourced glue.",
        "Complete: every change is derived from, and correctly cites, the sources.",
    ],
    SECURITY_CORRECTNESS: [
        "Still exploitable: untrusted input still reaches the query structure.",
        "Mostly exploitable: some paths fixed, others remain injectable.",
        "Partially fixed: values are bound but identifiers or edge cases stay unsafe.",
        "Fixed: every untrusted value is bound; minor hardening missing.",
        "Fully closed: all values bound, dynamic identifiers allowlisted, no regressions.",
    ],
    FRAMEWORK_FIT: [
        "Foreign: ignores the internal conventions entirely.",
        "Poor: same language but a different library or style than the internal snippets.",
        "Mixed: follows some internal conventions, contradicts others.",
        "Good: matches the internal snippets' APIs and style with small deviations.",
        "Native: indistinguishable from the approved internal patterns.",
    ],
}

_RUBRIC_INSTRUCTIONS = {
    GROUNDEDNESS: (
        "Judge draft.patched_code and draft.citations against `sources`. Is the patch "
        "derived from the provided sources rather than invented? Citations to ids that are "
        "not in `sources` count against groundedness."
    ),
    SECURITY_CORRECTNESS: (
        "Judge whether draft.patched_code actually closes the vulnerability class in "
        "finding.code, not just whether it looks plausible."
    ),
    FRAMEWORK_FIT: (
        "Judge whether draft.patched_code follows the conventions of the `sources` entries "
        "whose source is 'internal' (query API, placeholder style, ORM usage, helpers)."
    ),
}


def evaluation_questions() -> dict[str, ScoreQuestion]:
    return {
        name: ScoreQuestion(instructions=_RUBRIC_INSTRUCTIONS[name], levels=levels)
        for name, levels in _FIVE_LEVELS.items()
    }
