"""MockJevClient - a LOCAL, HEURISTIC stand-in for Jev. NOT the real model.

Used only when `JEV_MODE=mock` (the default while Jev is early-access). It speaks the
same typed interface as `HttpJevClient` so the graph runs end-to-end, and it returns
plausible, deterministic, roughly-calibrated answers derived from cheap lexical and
regex signals. Every `JevResult` it returns has `mocked=True`, which the API, demo,
eval harness and UI all surface. Numbers produced in mock mode say nothing about
Jev's real accuracy, latency or cost.

Heuristics are keyed by the question names defined in `graph.questions`; unknown
questions fall back to maximally-uncertain answers (0.5 / uniform / mid-scale).
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping
from typing import Any

from remediation_rag.clients.jev import (
    ChoiceAnswer,
    ChoiceQuestion,
    JevAnswer,
    JevQuestion,
    JevResult,
    JevUsage,
    NoulAnswer,
    NoulQuestion,
    ScoreAnswer,
    ScoreQuestion,
    check_context,
    estimate_tokens,
)
from remediation_rag.telemetry import stopwatch

MOCK_MODEL_NAME = "mock-jev-heuristic"

_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")

SQL_SIGNALS = re.compile(
    r"\b(select|insert|update|delete|where|from|execute|executemany|query|cursor|sql|jdbc|"
    r"statement|raw|order\s+by)\b",
    re.IGNORECASE,
)
_SQL_KW = r"\b(?:select|insert|update|delete|where)\b"
# Match a double- or single-quoted literal separately so nested quotes of the other kind
# (e.g. "... name = '{name}'") do not end the match early.
_DQ = rf'"[^"\n]*{_SQL_KW}[^"\n]*'
_SQ = rf"'[^'\n]*{_SQL_KW}[^'\n]*"
UNSAFE_SQL_PATTERNS = [
    # f-strings / template literals interpolating into SQL text
    re.compile(rf"f(?:{_DQ}|{_SQ})\{{", re.I),
    re.compile(rf"`[^`]*{_SQL_KW}[^`]*\$\{{", re.I),
    # string concatenation onto SQL text
    re.compile(rf"""(?:{_DQ}"|{_SQ}')\s*\+""", re.I),
    # %-formatting / .format() applied to SQL text
    re.compile(rf"""(?:{_DQ}"|{_SQ}')\s*%\s*[(\w]""", re.I),
    re.compile(rf"""(?:{_DQ}"|{_SQ}')\.format\(""", re.I),
]
SAFE_SQL_MARKERS = re.compile(
    r"(%s|\?|:\w+|\$\d|PreparedStatement|setString|setInt|setLong|bindparam|params\s*=|"
    r"\.filter\(|\.where\(|objects\.|findBy|@Param|sql\.Identifier|text\(|replacements|"
    r"MapSqlParameterSource|queryForObject|ALLOWED_|allowlist)"
)


def _tokens(text: str) -> set[str]:
    return {w.lower() for w in _WORD.findall(text)}


def _jaccard(a: set[str], b: set[str]) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def _jitter(seed: str, spread: float = 0.04) -> float:
    """Deterministic pseudo-noise in [-spread, spread] so answers are not suspiciously flat."""
    digest = hashlib.sha256(seed.encode()).digest()
    return (digest[0] / 255.0 * 2 - 1) * spread


def _clamp(value: float, low: float = 0.01, high: float = 0.99) -> float:
    return max(low, min(high, value))


def _sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-x))


def _text(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, default=str)


def _score_answer(question: ScoreQuestion, fraction: float, seed: str) -> ScoreAnswer:
    top = len(question.levels) - 1
    fraction = _clamp(fraction + _jitter(seed, 0.02), 0.0, 1.0)
    score = fraction * top
    # Spread probability mass around the point estimate; confidence = peak mass.
    weights = [math.exp(-((i - score) ** 2) / 0.5) for i in range(top + 1)]
    total = sum(weights)
    probs = {level: w / total for level, w in zip(question.levels, weights, strict=True)}
    return ScoreAnswer(
        score=round(score, 3),
        confidence=round(max(probs.values()), 3),
        levels=question.levels,
        probabilities={k: round(v, 4) for k, v in probs.items()},
    )


# --------------------------------------------------------------------------------------
# Question-specific heuristics
# --------------------------------------------------------------------------------------


def _request_text(state: Mapping[str, Any]) -> str:
    request = state.get("request", state)
    if isinstance(request, Mapping):
        return "\n".join(str(request.get(k) or "") for k in ("code", "description"))
    return _text(request)


def _in_scope(state: Mapping[str, Any], q: NoulQuestion) -> JevAnswer:
    text = _request_text(state)
    hits = len(SQL_SIGNALS.findall(text))
    looks_like_code = bool(re.search(r"[(){};=]", text))
    if hits >= 2 and looks_like_code:
        p = 0.9 + min(hits, 10) * 0.005
    elif looks_like_code:
        p = 0.4
    else:
        p = 0.06
    return NoulAnswer(probability=round(_clamp(p + _jitter(text, 0.02)), 3))


_CLASS_SIGNALS: dict[str, re.Pattern[str]] = {
    "sql_injection": SQL_SIGNALS,
    "xss": re.compile(r"(innerHTML|document\.write|dangerouslySetInnerHTML|<script|\|safe)", re.I),
    "command_injection": re.compile(
        r"(os\.system|subprocess|shell=True|child_process|exec\(|Runtime\.getRuntime)", re.I
    ),
    "path_traversal": re.compile(r"(\.\./|sendFile|readFile|open\(|Paths\.get|path\.join)", re.I),
}


def _vuln_class(state: Mapping[str, Any], q: ChoiceQuestion) -> JevAnswer:
    text = _request_text(state)
    logits = {}
    for option in q.options:
        pattern = _CLASS_SIGNALS.get(option)
        logits[option] = float(len(pattern.findall(text))) if pattern else 0.5
    total = sum(math.exp(v) for v in logits.values())
    probs = {k: math.exp(v) / total for k, v in logits.items()}
    best = max(probs, key=lambda k: probs[k])
    return ChoiceAnswer(
        choice=best,
        confidence=round(probs[best], 3),
        probabilities={k: round(v, 4) for k, v in probs.items()},
    )


def _chunk_relevance(state: Mapping[str, Any], q: NoulQuestion, chunk_key: str) -> JevAnswer:
    finding = state.get("finding", {})
    chunk = state.get("chunks", {}).get(chunk_key)
    if not isinstance(chunk, Mapping):
        return NoulAnswer(probability=0.5)
    overlap = _jaccard(
        _tokens(_text(finding.get("code", ""))), _tokens(_text(chunk.get("text", "")))
    )
    logit = -2.2 + overlap * 20
    if chunk.get("vuln_class") == finding.get("vuln_class"):
        logit += 0.8
    language = finding.get("language")
    if language and chunk.get("language") == language:
        logit += 1.2
    elif language and chunk.get("source") == "internal":
        logit -= 1.5
    framework = finding.get("framework")
    if framework and chunk.get("framework") == framework:
        logit += 0.8
    return NoulAnswer(probability=round(_clamp(_sigmoid(logit) + _jitter(chunk_key, 0.02)), 3))


def _cited_sources(state: Mapping[str, Any]) -> tuple[list[Mapping[str, Any]], float]:
    draft = state.get("draft", {})
    sources = {s.get("id"): s for s in state.get("sources", []) if isinstance(s, Mapping)}
    cited_ids = [c.get("chunk_id") for c in draft.get("citations", []) if isinstance(c, Mapping)]
    valid = [sources[c] for c in cited_ids if c in sources]
    ratio = len(valid) / len(cited_ids) if cited_ids else 0.0
    return valid, ratio


def _groundedness(state: Mapping[str, Any], q: ScoreQuestion) -> JevAnswer:
    draft = state.get("draft", {})
    valid, ratio = _cited_sources(state)
    patch_tokens = _tokens(_text(draft.get("patched_code", "")))
    source_tokens = (
        set().union(*(_tokens(_text(s.get("text", ""))) for s in valid)) if valid else set()
    )
    support = len(patch_tokens & source_tokens) / len(patch_tokens) if patch_tokens else 0.0
    fraction = 0.45 * ratio + 0.55 * min(1.0, support * 1.6)
    return _score_answer(q, fraction, "g" + _text(draft)[:200])


def _security_correctness(state: Mapping[str, Any], q: ScoreQuestion) -> JevAnswer:
    patch = _text(state.get("draft", {}).get("patched_code", ""))
    if not patch.strip():
        return _score_answer(q, 0.0, "s-empty")
    # A "patch" that no longer contains the original code's identifiers does not fix it,
    # however safe it looks in isolation.
    original = _tokens(_text(state.get("finding", {}).get("code", "")))
    coverage = len(original & _tokens(patch)) / len(original) if original else 1.0
    unsafe = sum(1 for pattern in UNSAFE_SQL_PATTERNS if pattern.search(patch))
    safe = len(SAFE_SQL_MARKERS.findall(patch))
    if unsafe:
        fraction = 0.3 - 0.1 * (unsafe - 1) + 0.05 * min(safe, 2)
    elif safe:
        fraction = 0.84 + 0.05 * min(safe, 3)
    else:
        fraction = 0.5
    if coverage < 0.6:
        fraction *= coverage
    return _score_answer(q, _clamp(fraction, 0.0, 1.0), "s" + patch[:200])


def _framework_fit(state: Mapping[str, Any], q: ScoreQuestion) -> JevAnswer:
    finding = state.get("finding", {})
    draft = state.get("draft", {})
    internal = [s for s in state.get("sources", []) if s.get("source") == "internal"]
    if not internal:
        return _score_answer(q, 0.25, "f-none")
    language = finding.get("language")
    framework = finding.get("framework")
    lang_match = any(s.get("language") == language for s in internal) if language else True
    fw_match = any(s.get("framework") == framework for s in internal) if framework else True
    overlap = _jaccard(
        _tokens(_text(draft.get("patched_code", ""))),
        set().union(*(_tokens(_text(s.get("text", ""))) for s in internal)),
    )
    fraction = 0.25 + 0.3 * lang_match + 0.2 * fw_match + min(0.25, overlap * 1.5)
    return _score_answer(q, fraction, "f" + _text(draft)[:200])


_NAMED_HEURISTICS: dict[str, Callable[[Mapping[str, Any], Any], JevAnswer]] = {
    "in_scope": _in_scope,
    "vuln_class": _vuln_class,
    "groundedness": _groundedness,
    "security_correctness": _security_correctness,
    "framework_fit": _framework_fit,
}


def _fallback(question: JevQuestion) -> JevAnswer:
    if isinstance(question, NoulQuestion):
        return NoulAnswer(probability=0.5)
    if isinstance(question, ChoiceQuestion):
        p = 1 / len(question.options)
        first = next(iter(question.options))
        return ChoiceAnswer(
            choice=first, confidence=p, probabilities=dict.fromkeys(question.options, p)
        )
    return _score_answer(question, 0.5, "fallback")


class MockJevClient:
    """Heuristic Jev stand-in. See module docstring - results are flagged `mocked=True`."""

    @property
    def is_mock(self) -> bool:
        return True

    async def ask(
        self, state: Mapping[str, Any] | str, questions: Mapping[str, JevQuestion]
    ) -> JevResult:
        if not questions:
            raise ValueError("at least one question is required")
        check_context(state, questions)
        state_map: Mapping[str, Any] = state if isinstance(state, Mapping) else {"text": state}
        with stopwatch() as watch:
            answers = {name: self._answer(name, q, state_map) for name, q in questions.items()}
        return JevResult(
            model=MOCK_MODEL_NAME,
            answers=answers,
            usage=JevUsage(
                input_tokens=estimate_tokens(state)
                + estimate_tokens({k: q.to_payload() for k, q in questions.items()}),
                output_tokens=len(questions) * 8,
            ),
            latency_ms=watch.elapsed_ms,
            mocked=True,
        )

    @staticmethod
    def _answer(name: str, question: JevQuestion, state: Mapping[str, Any]) -> JevAnswer:
        if name.startswith("relevant__") and isinstance(question, NoulQuestion):
            return _chunk_relevance(state, question, name.removeprefix("relevant__"))
        heuristic = _NAMED_HEURISTICS.get(name)
        if heuristic is None:
            return _fallback(question)
        return heuristic(state, question)
