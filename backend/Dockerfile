FROM python:3.12-slim AS base
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependencies first for layer caching.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY remediation_rag ./remediation_rag
RUN uv sync --frozen --no-dev

RUN useradd --create-home --uid 10001 app && mkdir -p /app/data && chown -R app /app/data
USER app

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"

CMD ["/app/.venv/bin/uvicorn", "remediation_rag.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
