"""Load the evaluation cases (also served to the UI as examples)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel

from remediation_rag.domain import Language, RemediationRequest, RemediationStatus

CASES_PATH = Path(__file__).resolve().parent / "cases.yaml"


class EvalCase(BaseModel):
    id: str
    title: str
    code: str
    language: Language | None = None
    framework: str | None = None
    description: str | None = None
    expected_status: RemediationStatus

    def to_request(self) -> RemediationRequest:
        return RemediationRequest(
            code=self.code,
            language=self.language,
            framework=self.framework,
            description=self.description,
        )


@lru_cache(maxsize=1)
def load_cases(path: Path = CASES_PATH) -> tuple[EvalCase, ...]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return tuple(EvalCase.model_validate(case) for case in raw["cases"])
