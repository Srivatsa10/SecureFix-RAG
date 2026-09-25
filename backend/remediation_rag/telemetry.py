"""Per-call usage accounting and the graph decision trace."""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, Literal

from pydantic import BaseModel, Field

Provider = Literal["bedrock", "jev", "offline"]


class UsageRecord(BaseModel):
    """One billable (or would-be billable) model call."""

    node: str
    provider: Provider
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0.0
    # Number of typed decisions answered by this call (Jev batches several per request).
    decisions: int = 0
    mocked: bool = False


class TraceEvent(BaseModel):
    """One step in the graph's decision trace, rendered by the demo script and the UI."""

    node: str
    attempt: int
    summary: str
    data: dict[str, Any] = Field(default_factory=dict)
    duration_ms: float = 0.0


class Stopwatch:
    def __init__(self) -> None:
        self.elapsed_ms = 0.0


@contextmanager
def stopwatch() -> Iterator[Stopwatch]:
    watch = Stopwatch()
    start = time.perf_counter()
    try:
        yield watch
    finally:
        watch.elapsed_ms = (time.perf_counter() - start) * 1000
