"""Typed client for Jev (TypeSafe AI's "System One" decision model).

Jev answers typed questions about a JSON/text `state` instead of generating text:

* **Noul**   - calibrated yes/no probability in [0, 1].
* **Choice** - one-of-N label with a probability per option and a confidence.
* **Score**  - position on an ordered 2-10 level rubric (fractional), plus confidence.

Several questions can share one request (and one input-token bill), which is how this
project batches e.g. per-chunk relevance checks into a single call.

Contract (per TypeSafe's public docs, Sept 2026)::

    POST {base_url}/v1/systemone
    {"model": "jev-latest", "state": ..., "questions": {"name": {"type": ..., ...}}}
    -> {"model": "...", "answers": {"name": {...}}, "usage": {"input_tokens": N, ...}}

`HttpJevClient` is the real implementation. `MockJevClient` (see `jev_mock.py`) is a
local, heuristic stand-in that is only used when `JEV_MODE=mock`, and every result it
produces is flagged `mocked=True`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from collections.abc import Mapping
from typing import Any, Literal, Protocol, TypeVar, runtime_checkable

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Jev's documented context window. Checked client-side before sending so an oversized
# request fails fast and predictably instead of as an opaque 4xx.
JEV_CONTEXT_TOKENS = 32_000
_CHARS_PER_TOKEN = 4

_AnswerT = TypeVar("_AnswerT", bound=BaseModel)


class JevError(RuntimeError):
    """Base error for Jev failures."""


class JevContextOverflowError(JevError):
    pass


class JevResponseError(JevError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


# --------------------------------------------------------------------------------------
# Questions
# --------------------------------------------------------------------------------------


class NoulQuestion(BaseModel):
    type: Literal["noul"] = "noul"
    instructions: str
    if_true: str
    if_false: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "type": "noul",
            "instructions": self.instructions,
            "criteria": {"true": self.if_true, "false": self.if_false},
        }


class ChoiceQuestion(BaseModel):
    type: Literal["choice"] = "choice"
    instructions: str
    options: dict[str, str] = Field(min_length=2, max_length=255)

    def to_payload(self) -> dict[str, Any]:
        return {"type": "choice", "instructions": self.instructions, "criteria": self.options}


class ScoreQuestion(BaseModel):
    type: Literal["score"] = "score"
    instructions: str
    levels: list[str] = Field(min_length=2, max_length=10, description="Ordered, worst first.")

    def to_payload(self) -> dict[str, Any]:
        return {"type": "score", "instructions": self.instructions, "criteria": self.levels}


JevQuestion = NoulQuestion | ChoiceQuestion | ScoreQuestion


# --------------------------------------------------------------------------------------
# Answers
# --------------------------------------------------------------------------------------


class NoulAnswer(BaseModel):
    type: Literal["noul"] = "noul"
    probability: float = Field(ge=0.0, le=1.0)


class ChoiceAnswer(BaseModel):
    type: Literal["choice"] = "choice"
    choice: str
    confidence: float = Field(ge=0.0, le=1.0)
    probabilities: dict[str, float] = Field(default_factory=dict)


class ScoreAnswer(BaseModel):
    type: Literal["score"] = "score"
    score: float = Field(ge=0.0, description="Fractional level index, 0 = worst level.")
    confidence: float = Field(ge=0.0, le=1.0)
    levels: list[str]
    probabilities: dict[str, float] = Field(default_factory=dict)

    @property
    def normalized(self) -> float:
        """Score mapped onto [0, 1] so thresholds are rubric-size independent."""
        top = len(self.levels) - 1
        return max(0.0, min(1.0, self.score / top)) if top > 0 else 0.0

    @property
    def level(self) -> str:
        return self.levels[max(0, min(len(self.levels) - 1, round(self.score)))]


JevAnswer = NoulAnswer | ChoiceAnswer | ScoreAnswer


class JevUsage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0


class JevResult(BaseModel):
    model: str
    answers: dict[str, JevAnswer]
    usage: JevUsage
    latency_ms: float
    mocked: bool = False

    def noul(self, name: str) -> NoulAnswer:
        return self._get(name, NoulAnswer)

    def choice(self, name: str) -> ChoiceAnswer:
        return self._get(name, ChoiceAnswer)

    def score(self, name: str) -> ScoreAnswer:
        return self._get(name, ScoreAnswer)

    def _get(self, name: str, kind: type[_AnswerT]) -> _AnswerT:
        answer = self.answers.get(name)
        if not isinstance(answer, kind):
            raise JevResponseError(
                f"expected {kind.__name__} for question {name!r}, got {answer!r}"
            )
        return answer


# --------------------------------------------------------------------------------------
# Client interface
# --------------------------------------------------------------------------------------


@runtime_checkable
class JevClient(Protocol):
    """What the graph depends on. Implemented by `HttpJevClient` and `MockJevClient`."""

    @property
    def is_mock(self) -> bool: ...

    async def ask(
        self, state: Mapping[str, Any] | str, questions: Mapping[str, JevQuestion]
    ) -> JevResult: ...


def estimate_tokens(payload: Any) -> int:
    text = payload if isinstance(payload, str) else json.dumps(payload, default=str)
    return max(1, len(text) // _CHARS_PER_TOKEN)


def check_context(state: Mapping[str, Any] | str, questions: Mapping[str, JevQuestion]) -> int:
    """Return the estimated input size, raising if it cannot fit Jev's context window."""
    estimate = estimate_tokens(state) + estimate_tokens(
        {k: q.to_payload() for k, q in questions.items()}
    )
    if estimate > JEV_CONTEXT_TOKENS:
        raise JevContextOverflowError(
            f"estimated {estimate} tokens exceeds Jev's {JEV_CONTEXT_TOKENS}-token context"
        )
    return estimate


def parse_answers(
    raw_answers: Mapping[str, Any], questions: Mapping[str, JevQuestion]
) -> dict[str, JevAnswer]:
    answers: dict[str, JevAnswer] = {}
    for name, question in questions.items():
        raw = raw_answers.get(name)
        if not isinstance(raw, Mapping):
            raise JevResponseError(f"missing answer for question {name!r}")
        try:
            if isinstance(question, NoulQuestion):
                answers[name] = NoulAnswer(probability=float(raw["noul"]))
            elif isinstance(question, ChoiceQuestion):
                answers[name] = ChoiceAnswer(
                    choice=str(raw["choice"]),
                    confidence=float(raw.get("confidence", 0.0)),
                    probabilities=dict(raw.get("probabilities", {})),
                )
            else:
                answers[name] = ScoreAnswer(
                    score=float(raw["score"]),
                    confidence=float(raw.get("confidence", 0.0)),
                    levels=question.levels,
                    probabilities={
                        str(k): float(v) for k, v in raw.get("probabilities", {}).items()
                    },
                )
        except (KeyError, TypeError, ValueError) as exc:
            raise JevResponseError(f"malformed answer for question {name!r}: {raw!r}") from exc
    return answers


class HttpJevClient:
    """Real Jev client over HTTPS, with retries on transient failures."""

    _RETRYABLE_STATUS = frozenset({408, 409, 429, 500, 502, 503, 504})

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = "https://api.typesafe.ai",
        model: str = "jev-latest",
        timeout_seconds: float = 5.0,
        max_attempts: int = 3,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._model = model
        self._max_attempts = max(1, max_attempts)
        self._client = http_client or httpx.AsyncClient(
            base_url=base_url,
            timeout=timeout_seconds,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        )

    @property
    def is_mock(self) -> bool:
        return False

    async def aclose(self) -> None:
        await self._client.aclose()

    async def ask(
        self, state: Mapping[str, Any] | str, questions: Mapping[str, JevQuestion]
    ) -> JevResult:
        if not questions:
            raise ValueError("at least one question is required")
        check_context(state, questions)
        body = {
            "model": self._model,
            "state": state,
            "questions": {name: q.to_payload() for name, q in questions.items()},
        }
        # One key for all attempts so a retried request is never double-processed.
        headers = {"Idempotency-Key": str(uuid.uuid4())}

        start = time.perf_counter()
        response = await self._post_with_retries(body, headers)
        latency_ms = (time.perf_counter() - start) * 1000

        try:
            payload = response.json()
        except ValueError as exc:
            raise JevResponseError("Jev returned non-JSON body", response.status_code) from exc

        usage = payload.get("usage") or {}
        return JevResult(
            model=str(payload.get("model", self._model)),
            answers=parse_answers(payload.get("answers") or {}, questions),
            usage=JevUsage(
                input_tokens=int(usage.get("input_tokens", 0)),
                output_tokens=int(usage.get("output_tokens", 0)),
            ),
            latency_ms=latency_ms,
        )

    async def _post_with_retries(
        self, body: dict[str, Any], headers: dict[str, str]
    ) -> httpx.Response:
        last_error: Exception | None = None
        for attempt in range(1, self._max_attempts + 1):
            try:
                response = await self._client.post("/v1/systemone", json=body, headers=headers)
            except httpx.TransportError as exc:
                last_error = exc
                logger.warning("Jev transport error (attempt %d): %s", attempt, exc)
            else:
                if response.status_code < 400:
                    return response
                if response.status_code not in self._RETRYABLE_STATUS:
                    raise JevResponseError(
                        f"Jev request failed: {response.status_code} {response.text[:300]}",
                        response.status_code,
                    )
                last_error = JevResponseError(
                    f"Jev transient error {response.status_code}", response.status_code
                )
                logger.warning("Jev returned %d (attempt %d)", response.status_code, attempt)
            if attempt < self._max_attempts:
                await asyncio.sleep(min(2.0, 0.2 * 2 ** (attempt - 1)))
        raise JevResponseError(f"Jev request failed after {self._max_attempts} attempts") from (
            last_error
        )
