"""HTTP-facing schemas. Domain/result models are reused where they are already public."""

from __future__ import annotations

from pydantic import BaseModel

from remediation_rag.domain import Language
from remediation_rag.service import RuntimeInfo


class HealthResponse(BaseModel):
    status: str
    runtime: RuntimeInfo


class ExampleCase(BaseModel):
    id: str
    title: str
    code: str
    language: Language | None
    framework: str | None
    description: str | None
    expected_status: str


class ErrorResponse(BaseModel):
    error: str
    detail: str
    request_id: str | None = None
