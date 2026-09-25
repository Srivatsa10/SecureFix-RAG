import json

import httpx
import pytest

from remediation_rag.clients.jev import (
    ChoiceQuestion,
    HttpJevClient,
    JevContextOverflowError,
    JevResponseError,
    NoulQuestion,
    ScoreQuestion,
)

QUESTIONS = {
    "in_scope": NoulQuestion(instructions="Is it?", if_true="yes", if_false="no"),
    "vuln_class": ChoiceQuestion(instructions="Which?", options={"a": "A", "b": "B"}),
    "quality": ScoreQuestion(
        instructions="How good?", levels=["bad", "ok", "good", "great", "perfect"]
    ),
}

OK_BODY = {
    "model": "jev-1.13.0",
    "answers": {
        "in_scope": {"type": "noul", "noul": 0.91},
        "vuln_class": {
            "type": "choice",
            "choice": "a",
            "confidence": 0.8,
            "probabilities": {"a": 0.8, "b": 0.2},
        },
        "quality": {"type": "score", "score": 3.0, "confidence": 0.7, "probabilities": {}},
    },
    "usage": {"input_tokens": 210, "output_tokens": 31},
}


def make_client(handler, **kwargs) -> HttpJevClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport, base_url="https://jev.test")
    return HttpJevClient("key", http_client=http, **kwargs)


async def test_request_shape_and_typed_parsing():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["headers"] = request.headers
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=OK_BODY)

    result = await make_client(handler).ask({"code": "x"}, QUESTIONS)

    assert seen["path"] == "/v1/systemone"
    assert "idempotency-key" in seen["headers"]
    body = seen["body"]
    assert body["model"] == "jev-latest"
    assert body["questions"]["in_scope"] == {
        "type": "noul",
        "instructions": "Is it?",
        "criteria": {"true": "yes", "false": "no"},
    }
    assert body["questions"]["quality"]["criteria"] == ["bad", "ok", "good", "great", "perfect"]

    assert result.noul("in_scope").probability == pytest.approx(0.91)
    assert result.choice("vuln_class").choice == "a"
    quality = result.score("quality")
    assert quality.normalized == pytest.approx(0.75)
    assert quality.level == "great"
    assert result.usage.input_tokens == 210
    assert result.mocked is False


async def test_retries_transient_errors_with_same_idempotency_key():
    keys: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        keys.append(request.headers["idempotency-key"])
        return httpx.Response(503) if len(keys) < 2 else httpx.Response(200, json=OK_BODY)

    result = await make_client(handler, max_attempts=3).ask({"code": "x"}, QUESTIONS)
    assert result.noul("in_scope").probability == pytest.approx(0.91)
    assert len(keys) == 2 and keys[0] == keys[1]


async def test_non_retryable_error_raises_immediately():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(401, json={"error": "bad key"})

    with pytest.raises(JevResponseError) as exc:
        await make_client(handler).ask({"code": "x"}, QUESTIONS)
    assert exc.value.status_code == 401
    assert calls == 1


async def test_missing_answer_is_an_error():
    body = {**OK_BODY, "answers": {"in_scope": {"type": "noul", "noul": 0.5}}}
    client = make_client(lambda r: httpx.Response(200, json=body))
    with pytest.raises(JevResponseError, match="missing answer"):
        await client.ask({"code": "x"}, QUESTIONS)


async def test_wrong_answer_type_accessor_raises():
    result = await make_client(lambda r: httpx.Response(200, json=OK_BODY)).ask({"c": 1}, QUESTIONS)
    with pytest.raises(JevResponseError):
        result.score("in_scope")


async def test_context_overflow_fails_before_sending():
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must not run
        raise AssertionError("request should not be sent")

    with pytest.raises(JevContextOverflowError):
        await make_client(handler).ask({"code": "x" * 200_000}, QUESTIONS)
