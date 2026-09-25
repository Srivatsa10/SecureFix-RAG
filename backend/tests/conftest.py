from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from remediation_rag.clients.jev import (
    ChoiceAnswer,
    ChoiceQuestion,
    JevQuestion,
    JevResult,
    JevUsage,
    NoulAnswer,
    NoulQuestion,
    ScoreAnswer,
    ScoreQuestion,
)
from remediation_rag.clients.offline import HashingEmbeddings
from remediation_rag.config import Settings
from remediation_rag.domain import Language, RemediationRequest
from remediation_rag.ingestion.pipeline import build_plan, ingest
from remediation_rag.retrieval.factory import build_memory_index
from remediation_rag.retrieval.index import KnowledgeIndex

PY_VULN = RemediationRequest(
    code=(
        "def get_user(cursor, name):\n"
        "    cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"
        "    return cursor.fetchone()\n"
    ),
    language=Language.PYTHON,
    framework="psycopg",
    description="Bandit B608: possible SQL injection via string-based query construction",
)


class ScriptedJev:
    """Deterministic Jev fake: answers come from a script keyed by question name.

    `scores` is a list consumed one evaluation call at a time (value in [0, 1]).
    """

    def __init__(
        self,
        *,
        in_scope: float = 0.95,
        vuln_class: str = "sql_injection",
        relevance: float = 0.9,
        scores: list[float] | None = None,
    ) -> None:
        self.in_scope = in_scope
        self.vuln_class = vuln_class
        self.relevance = relevance
        self.scores = list(scores or [0.95])
        self.calls: list[dict[str, JevQuestion]] = []

    @property
    def is_mock(self) -> bool:
        return True

    async def ask(
        self, state: Mapping[str, Any] | str, questions: Mapping[str, JevQuestion]
    ) -> JevResult:
        self.calls.append(dict(questions))
        is_eval = any(isinstance(qn, ScoreQuestion) for qn in questions.values())
        score_value = self.scores.pop(0) if is_eval and len(self.scores) > 1 else self.scores[0]
        answers: dict[str, Any] = {}
        for name, question in questions.items():
            if isinstance(question, NoulQuestion):
                p = self.in_scope if name == "in_scope" else self.relevance
                answers[name] = NoulAnswer(probability=p)
            elif isinstance(question, ChoiceQuestion):
                answers[name] = ChoiceAnswer(choice=self.vuln_class, confidence=0.9)
            else:
                top = len(question.levels) - 1
                answers[name] = ScoreAnswer(
                    score=score_value * top, confidence=0.8, levels=question.levels
                )
        return JevResult(
            model="scripted",
            answers=answers,
            usage=JevUsage(input_tokens=1000),
            latency_ms=1.0,
            mocked=True,
        )


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None)


@pytest.fixture
async def memory_index(tmp_path: Path) -> KnowledgeIndex:
    index = build_memory_index(HashingEmbeddings())
    await ingest(index, build_plan(tmp_path, offline=True))
    return index
