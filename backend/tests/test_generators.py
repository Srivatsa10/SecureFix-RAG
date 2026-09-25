import json

import pytest
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage

from remediation_rag.clients.bedrock import BedrockClient
from remediation_rag.clients.offline import OfflinePatchGenerator
from remediation_rag.domain import Chunk, Language, RemediationRequest, SourceKind
from remediation_rag.generation import (
    DraftContext,
    DraftGenerationError,
    parse_draft,
    render_user_prompt,
)

INTERNAL = Chunk(
    id="internal:python/psycopg.py#0",
    source=SourceKind.INTERNAL,
    text='cur.execute("SELECT id FROM users WHERE email = %s", (email,))',
    vuln_class="sql_injection",
    language="python",
    framework="psycopg",
    kind="parameterized_query",
    source_path="python/psycopg.py",
)
OWASP = Chunk(
    id="owasp:sql_injection/0",
    source=SourceKind.OWASP,
    text="Use prepared statements with parameterized queries.",
    vuln_class="sql_injection",
    source_path="owasp",
)


def context(code: str, language: Language) -> DraftContext:
    return DraftContext(
        request=RemediationRequest(code=code, language=language),
        vuln_class="sql_injection",
        internal_chunks=[INTERNAL],
        owasp_chunks=[OWASP],
    )


DRAFT_JSON = {
    "explanation": "String formatting lets input alter the query.",
    "patched_code": 'cur.execute("SELECT * FROM t WHERE a = %s", (a,))',
    "diff": "",
    "conventions_applied": ["psycopg %s placeholders"],
    "citations": [{"chunk_id": INTERNAL.id, "reason": "placeholder style"}],
}


async def test_bedrock_client_parses_json_and_usage():
    reply = AIMessage(
        content="```json\n" + json.dumps(DRAFT_JSON) + "\n```",
        usage_metadata={"input_tokens": 1200, "output_tokens": 300, "total_tokens": 1500},
    )
    client = BedrockClient(GenericFakeChatModel(messages=iter([reply])), "test-model")
    result = await client.generate(
        context('cur.execute(f"SELECT * FROM t WHERE a = {a}")', Language.PYTHON)
    )
    assert result.draft.citations[0].chunk_id == INTERNAL.id
    assert (result.input_tokens, result.output_tokens) == (1200, 300)
    assert result.model == "test-model" and not result.offline


async def test_bedrock_client_rejects_unparseable_reply():
    client = BedrockClient(GenericFakeChatModel(messages=iter([AIMessage(content="sorry")])), "m")
    with pytest.raises(DraftGenerationError):
        await client.generate(context("x", Language.PYTHON))


def test_prompt_includes_sources_and_retry_feedback():
    ctx = context("q = 1", Language.PYTHON)
    ctx.previous_feedback = {"security_correctness": 0.4}
    prompt = render_user_prompt(ctx)
    assert INTERNAL.id in prompt and OWASP.id in prompt
    assert "security_correctness scored 0.40" in prompt


def test_parse_draft_tolerates_leading_prose():
    draft = parse_draft("Here you go: " + json.dumps(DRAFT_JSON))
    assert draft.patched_code.startswith("cur.execute")


@pytest.mark.parametrize(
    ("language", "code", "expected"),
    [
        (
            Language.PYTHON,
            "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
            'cursor.execute("SELECT * FROM users WHERE name = %s", (name,))',
        ),
        (
            Language.JAVASCRIPT,
            "const r = await pool.query(`SELECT * FROM orders WHERE id = ${req.params.id}`);",
            "pool.query('SELECT * FROM orders WHERE id = $1', [req.params.id])",
        ),
        (
            Language.JAVA,
            "Statement st = connection.createStatement();\n"
            "ResultSet rs = st.executeQuery("
            '"SELECT * FROM accounts WHERE owner = \'" + owner + "\'");\n',
            "st.setString(1, owner);",
        ),
    ],
)
async def test_offline_generator_parameterizes(language, code, expected):
    result = await OfflinePatchGenerator().generate(context(code, language))
    assert result.offline
    assert expected in result.draft.patched_code
    assert result.draft.diff.startswith("--- a/")
    assert "OFFLINE MODE" in result.draft.explanation
