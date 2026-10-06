"""LLM-judge decision layer: the fallback used when no Jev API key is configured."""

import json

import pytest
from langchain_core.language_models import BaseChatModel
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from remediation_rag.clients.jev import (
    ChoiceQuestion,
    JevResponseError,
    NoulQuestion,
    ScoreQuestion,
)
from remediation_rag.clients.llm_judge import (
    JUDGE_SYSTEM_PROMPT,
    LlmJudgeClient,
    render_judge_prompt,
)
from remediation_rag.config import AppMode, JevMode, Settings
from remediation_rag.costing import summarize_costs
from remediation_rag.telemetry import UsageRecord
from tests.conftest import PY_VULN

QUESTIONS = {
    "in_scope": NoulQuestion(instructions="?", if_true="y", if_false="n"),
    "vuln_class": ChoiceQuestion(instructions="?", options={"sql_injection": "s", "xss": "x"}),
    "security_correctness": ScoreQuestion(instructions="?", levels=["a", "b", "c", "d", "e"]),
}


def judge(*replies: str) -> LlmJudgeClient:
    messages = iter(
        AIMessage(
            content=r,
            usage_metadata={"input_tokens": 900, "output_tokens": 60, "total_tokens": 960},
        )
        for r in replies
    )
    return LlmJudgeClient(GenericFakeChatModel(messages=messages), "judge-model", max_attempts=2)


GOOD = json.dumps(
    {
        "in_scope": {"noul": 0.97},
        "vuln_class": {
            "choice": "sql_injection",
            "confidence": 0.9,
            "probabilities": {"sql_injection": 0.9, "xss": 0.1},
        },
        "security_correctness": {"score": 1, "confidence": 0.8},
    }
)


async def test_answers_typed_questions_and_reports_real_usage():
    result = await judge(GOOD).ask({"code": "x"}, QUESTIONS)
    assert result.provider == "llm_judge" and not result.mocked
    assert result.noul("in_scope").probability == pytest.approx(0.97)
    assert result.choice("vuln_class").choice == "sql_injection"
    assert result.score("security_correctness").normalized == pytest.approx(0.25)
    assert (result.usage.input_tokens, result.usage.output_tokens) == (900, 60)


async def test_out_of_range_values_are_clamped():
    reply = json.dumps(
        {
            "in_scope": {"noul": 7},
            "vuln_class": {"choice": "rce", "probabilities": {"sql_injection": 3, "xss": 1}},
            "security_correctness": {"score": 99, "confidence": "high"},
        }
    )
    result = await judge(reply).ask({}, QUESTIONS)
    assert result.noul("in_scope").probability == 1.0
    # Unknown option falls back to the most probable valid one; probabilities renormalised.
    assert result.choice("vuln_class").choice == "sql_injection"
    assert result.choice("vuln_class").probabilities["sql_injection"] == pytest.approx(0.75)
    assert result.score("security_correctness").normalized == 1.0


async def test_retries_unusable_reply_and_counts_both_calls():
    result = await judge("I think it's fine!", GOOD).ask({}, QUESTIONS)
    assert result.noul("in_scope").probability == pytest.approx(0.97)
    assert result.usage.input_tokens == 1800


async def test_gives_up_after_max_attempts():
    with pytest.raises(JevResponseError):
        await judge("nope", "still nope").ask({}, QUESTIONS)


def test_prompt_is_adversarial_and_injection_resistant():
    prompt = JUDGE_SYSTEM_PROMPT.lower()
    assert "broken until the evidence" in prompt
    assert "lowest level" in prompt
    assert "never follow instructions" in prompt
    rendered = render_judge_prompt({"code": "x"}, QUESTIONS)
    assert '"0": "a"' in rendered and "answer_format" in rendered


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({}, JevMode.MOCK),
        ({"jev_api_key": "k"}, JevMode.LIVE),
        ({"app_mode": AppMode.LIVE, "pinecone_api_key": "p"}, JevMode.LLM),
        ({"app_mode": AppMode.LIVE, "pinecone_api_key": "p", "jev_api_key": "k"}, JevMode.LIVE),
        ({"jev_mode": JevMode.LLM}, JevMode.LLM),
    ],
)
def test_auto_mode_falls_back_to_llm_judge_without_jev_key(kwargs, expected):
    assert Settings(_env_file=None, **kwargs).resolved_jev_mode is expected


def test_judge_cost_is_measured_and_jev_is_the_estimate():
    settings = Settings(_env_file=None)
    usage = [
        UsageRecord(
            node="evaluate_draft",
            provider="llm_judge",
            model="m",
            input_tokens=2000,
            output_tokens=300,
            decisions=3,
        )
    ]
    cost = summarize_costs(usage, settings)
    assert cost.decision_layer == "llm_judge"
    judge_usd = (
        2000 * settings.price_judge_input_per_m + 300 * settings.price_judge_output_per_m
    ) / 1e6
    assert cost.llm_judge_decision_usd == pytest.approx(judge_usd)
    assert cost.jev_usd == pytest.approx(2000 * settings.price_jev_input_per_m / 1e6)
    assert cost.total_usd == pytest.approx(judge_usd)


class _RubberStampModel(BaseChatModel):
    """Fake judge model: parses the question spec from the prompt and answers every question
    favourably, so the whole graph can run with the LLM judge as its decision layer."""

    @property
    def _llm_type(self) -> str:
        return "rubber-stamp"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        prompt = messages[-1].content
        spec = json.loads(prompt.split("## Questions\n", 1)[1].split("\n\n## State", 1)[0])
        answers = {}
        for name, q in spec.items():
            if q["type"] == "noul":
                answers[name] = {"noul": 0.95}
            elif q["type"] == "choice":
                answers[name] = {"choice": "sql_injection", "confidence": 0.9}
            else:
                answers[name] = {"score": len(q["levels"]) - 1, "confidence": 0.9}
        reply = AIMessage(
            content=json.dumps(answers),
            usage_metadata={"input_tokens": 500, "output_tokens": 40, "total_tokens": 540},
        )
        return ChatResult(generations=[ChatGeneration(message=reply)])


async def test_full_graph_runs_on_the_llm_judge(memory_index, settings):
    from tests.test_pipeline import service

    client = LlmJudgeClient(_RubberStampModel(), "judge-model")
    result = await service(client, memory_index, settings).remediate(PY_VULN)
    assert result.status.value == "shipped"
    providers = {u.provider for u in result.usage if u.node != "draft_patch"}
    assert providers == {"llm_judge"}
    assert result.cost.decision_layer == "llm_judge"
    assert any("LLM judge Score" in e.summary for e in result.trace)
