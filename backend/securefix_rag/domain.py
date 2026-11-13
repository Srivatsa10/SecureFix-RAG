"""Core domain types shared across ingestion, graph, API and eval."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class VulnClass(StrEnum):
    """Vulnerability classes the classifier can emit.

    Only classes with ingested knowledge (see `ingestion.owasp_sources`) are remediable;
    the rest are recognised so they can be rejected with a precise reason.
    """

    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    OTHER = "other"


VULN_CLASS_DESCRIPTIONS: dict[VulnClass, str] = {
    VulnClass.SQL_INJECTION: "SQL injection (CWE-89): untrusted input reaches a SQL query string",
    VulnClass.XSS: "Cross-site scripting (CWE-79): untrusted input rendered into HTML/JS",
    VulnClass.COMMAND_INJECTION: "OS command injection (CWE-78): input reaches a shell command",
    VulnClass.PATH_TRAVERSAL: "Path traversal (CWE-22): input controls a filesystem path",
    VulnClass.OTHER: "Something else, or no identifiable vulnerability",
}


class Language(StrEnum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"


class SourceKind(StrEnum):
    INTERNAL = "internal"
    OWASP = "owasp"


class Chunk(BaseModel):
    """A retrieved knowledge chunk (internal secure snippet or OWASP guidance)."""

    id: str
    source: SourceKind
    text: str
    vuln_class: str
    language: str = "any"
    framework: str = "any"
    kind: str = "guidance"
    source_path: str
    title: str = ""
    similarity: float = 0.0
    relevance: float | None = None


class RemediationRequest(BaseModel):
    code: str = Field(min_length=1, description="The vulnerable code snippet.")
    language: Language | None = None
    framework: str | None = Field(default=None, max_length=64)
    description: str | None = Field(
        default=None, max_length=2_000, description="Scanner finding or free-text context."
    )
    file_path: str | None = Field(default=None, max_length=512)


class Citation(BaseModel):
    chunk_id: str
    reason: str


class PatchDraft(BaseModel):
    """Structured output of the `draft_patch` node."""

    explanation: str
    patched_code: str
    diff: str = Field(default="", description="Unified diff from original to patched code.")
    conventions_applied: list[str] = Field(default_factory=list)
    citations: list[Citation] = Field(default_factory=list)


ScoreDimension = Literal["groundedness", "security_correctness", "framework_fit"]
SCORE_DIMENSIONS: tuple[ScoreDimension, ...] = (
    "groundedness",
    "security_correctness",
    "framework_fit",
)


class DimensionScore(BaseModel):
    value: float = Field(ge=0.0, le=1.0, description="Normalised score in [0, 1].")
    confidence: float = Field(ge=0.0, le=1.0)
    level: str = Field(description="Most probable rubric level.")


class EvaluationScores(BaseModel):
    groundedness: DimensionScore
    security_correctness: DimensionScore
    framework_fit: DimensionScore

    def as_dict(self) -> dict[ScoreDimension, DimensionScore]:
        return {d: getattr(self, d) for d in SCORE_DIMENSIONS}

    def failing(self, threshold: float) -> list[ScoreDimension]:
        return [d for d, s in self.as_dict().items() if s.value < threshold]

    def weakest(self) -> ScoreDimension:
        return min(SCORE_DIMENSIONS, key=lambda d: getattr(self, d).value)

    def minimum(self) -> float:
        return min(s.value for s in self.as_dict().values())


class RemediationStatus(StrEnum):
    SHIPPED = "shipped"
    REJECTED = "rejected"
    HUMAN_REVIEW_REQUIRED = "human_review_required"
