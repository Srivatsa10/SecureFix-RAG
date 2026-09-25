"""FastAPI application exposing the remediation pipeline.

uv run uvicorn remediation_rag.api.app:create_app --factory --reload
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from remediation_rag.api.schemas import ErrorResponse, ExampleCase, HealthResponse
from remediation_rag.clients.jev import JevError
from remediation_rag.config import Settings, get_settings
from remediation_rag.container import Container, build_container
from remediation_rag.domain import RemediationRequest
from remediation_rag.eval.dataset import load_cases
from remediation_rag.service import RemediationResult, RemediationService

logger = logging.getLogger(__name__)

REQUEST_ID_HEADER = "X-Request-ID"

router = APIRouter(prefix="/api")


def get_service(request: Request) -> RemediationService:
    container: Container = request.app.state.container
    return container.service


def get_app_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


ServiceDep = Annotated[RemediationService, Depends(get_service)]
SettingsDep = Annotated[Settings, Depends(get_app_settings)]


@router.get("/health", response_model=HealthResponse)
async def health(service: ServiceDep) -> HealthResponse:
    return HealthResponse(status="ok", runtime=service.runtime)


@router.get("/examples", response_model=list[ExampleCase])
async def examples() -> list[ExampleCase]:
    return [
        ExampleCase(
            id=c.id,
            title=c.title,
            code=c.code,
            language=c.language,
            framework=c.framework,
            description=c.description,
            expected_status=c.expected_status.value,
        )
        for c in load_cases()
    ]


@router.post(
    "/remediations",
    response_model=RemediationResult,
    responses={
        413: {"model": ErrorResponse},
        502: {"model": ErrorResponse},
    },
)
async def create_remediation(
    body: RemediationRequest, request: Request, service: ServiceDep, settings: SettingsDep
) -> RemediationResult:
    if len(body.code) > settings.max_input_code_chars:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"code exceeds {settings.max_input_code_chars} characters",
        )
    return await service.remediate(body, request_id=request.state.request_id)


def create_app(
    settings: Settings | None = None,
    container_factory: Callable[[Settings], Awaitable[Container]] = build_container,
) -> FastAPI:
    settings = settings or get_settings()
    logging.basicConfig(
        level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.settings = settings
        app.state.container = await container_factory(settings)
        try:
            yield
        finally:
            await app.state.container.aclose()

    app = FastAPI(
        title="RemediationRAG",
        version="0.1.0",
        summary="Self-correcting security remediation: Bedrock drafts, Jev decides.",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", REQUEST_ID_HEADER],
        expose_headers=[REQUEST_ID_HEADER],
    )

    @app.middleware("http")
    async def request_id(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        rid = request.headers.get(REQUEST_ID_HEADER) or uuid.uuid4().hex[:12]
        request.state.request_id = rid
        response = await call_next(request)
        response.headers[REQUEST_ID_HEADER] = rid
        return response

    @app.exception_handler(JevError)
    async def jev_error_handler(request: Request, exc: JevError) -> JSONResponse:
        logger.error("Jev failure: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content=ErrorResponse(
                error="decision_service_unavailable",
                detail="The Jev decision service failed; no patch was produced.",
                request_id=getattr(request.state, "request_id", None),
            ).model_dump(),
        )

    @app.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled error")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(
                error="internal_error",
                detail="Unexpected server error.",
                request_id=getattr(request.state, "request_id", None),
            ).model_dump(),
        )

    app.include_router(router)
    return app
