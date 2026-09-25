from remediation_rag.clients.jev import ChoiceQuestion, NoulQuestion, ScoreQuestion
from remediation_rag.clients.jev_mock import MockJevClient

VULN_SQL = "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")"
LEVELS = ["none", "weak", "partial", "strong", "complete"]


async def test_mock_is_labelled_and_deterministic():
    client = MockJevClient()
    q = {"in_scope": NoulQuestion(instructions="?", if_true="y", if_false="n")}
    first = await client.ask({"request": {"code": VULN_SQL}}, q)
    second = await client.ask({"request": {"code": VULN_SQL}}, q)
    assert client.is_mock and first.mocked
    assert first.noul("in_scope").probability == second.noul("in_scope").probability
    assert first.usage.input_tokens > 0


async def test_intent_separates_sql_from_chitchat():
    client = MockJevClient()
    q = {"in_scope": NoulQuestion(instructions="?", if_true="y", if_false="n")}
    sql = await client.ask({"request": {"code": VULN_SQL}}, q)
    chat = await client.ask({"request": {"code": "what is the weather like today"}}, q)
    assert sql.noul("in_scope").probability > 0.85
    assert chat.noul("in_scope").probability < 0.2


async def test_vuln_class_choice_picks_sql_injection():
    q = {
        "vuln_class": ChoiceQuestion(
            instructions="?", options={"sql_injection": "sql", "xss": "xss", "other": "other"}
        )
    }
    result = await MockJevClient().ask({"request": {"code": VULN_SQL}}, q)
    answer = result.choice("vuln_class")
    assert answer.choice == "sql_injection"
    assert abs(sum(answer.probabilities.values()) - 1) < 1e-3


async def test_security_score_prefers_parameterized_patch():
    q = {"security_correctness": ScoreQuestion(instructions="?", levels=LEVELS)}
    client = MockJevClient()
    bad = await client.ask({"draft": {"patched_code": VULN_SQL}}, q)
    good = await client.ask(
        {
            "draft": {
                "patched_code": 'cursor.execute("SELECT * FROM users WHERE name = %s", (name,))'
            }
        },
        q,
    )
    assert good.score("security_correctness").normalized > 0.85
    assert bad.score("security_correctness").normalized < 0.5


async def test_unknown_question_falls_back_to_uncertain():
    q = {"mystery": NoulQuestion(instructions="?", if_true="y", if_false="n")}
    result = await MockJevClient().ask({"x": 1}, q)
    assert result.noul("mystery").probability == 0.5
