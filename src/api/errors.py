"""Consistent error handling for FastAPI endpoints."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from src.core.exceptions import (
    ApprovalAlreadyConsumedError,
    ApprovalError,
    ApprovalExpiredError,
    ApprovalMismatchError,
    ApprovalNotFoundError,
    ApprovalRevokedError,
    AuthorizationDeniedError,
    BootstrapError,
    ModelValidationError,
    PlanTamperingError,
    PlanValidationError,
    ResourceOwnershipError,
    SecurityViolationError,
    TokenError,
    TokenNotFoundError,
    TokenRevokedError,
    TokenScopeError,
    WorkflowError,
)

logger = logging.getLogger(__name__)


def build_error_payload(code: str, message: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    """Format uniform error envelope."""
    return {
        "error": {
            "code": code,
            "message": message,
            "details": details or {},
        }
    }


def register_error_handlers(app: FastAPI) -> None:
    """Register uniform exception handlers with FastAPI application."""

    @app.exception_handler(TokenNotFoundError)
    async def token_not_found_handler(request: Request, exc: TokenNotFoundError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=build_error_payload(exc.__class__.__name__, str(exc), getattr(exc, "details", {})),
            headers={"WWW-Authenticate": "Bearer"},
        )

    @app.exception_handler(TokenRevokedError)
    async def token_revoked_handler(request: Request, exc: TokenRevokedError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=build_error_payload(exc.__class__.__name__, str(exc), getattr(exc, "details", {})),
        )

    @app.exception_handler(TokenScopeError)
    @app.exception_handler(AuthorizationDeniedError)
    @app.exception_handler(ResourceOwnershipError)
    @app.exception_handler(PlanTamperingError)
    async def security_violation_handler(request: Request, exc: SecurityViolationError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=build_error_payload(exc.__class__.__name__, str(exc), getattr(exc, "details", {})),
        )

    @app.exception_handler(ApprovalNotFoundError)
    async def approval_not_found_handler(request: Request, exc: ApprovalNotFoundError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=build_error_payload(exc.__class__.__name__, str(exc), getattr(exc, "details", {})),
        )

    @app.exception_handler(ApprovalAlreadyConsumedError)
    @app.exception_handler(ApprovalMismatchError)
    @app.exception_handler(ApprovalExpiredError)
    @app.exception_handler(ApprovalRevokedError)
    @app.exception_handler(ApprovalError)
    async def approval_error_handler(request: Request, exc: ApprovalError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=build_error_payload(exc.__class__.__name__, str(exc), getattr(exc, "details", {})),
        )

    @app.exception_handler(ModelValidationError)
    @app.exception_handler(PlanValidationError)
    async def validation_error_handler(request: Request, exc: BootstrapError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=build_error_payload(exc.__class__.__name__, str(exc), getattr(exc, "details", {})),
        )

    @app.exception_handler(WorkflowError)
    async def workflow_error_handler(request: Request, exc: WorkflowError) -> JSONResponse:
        status_code = status.HTTP_404_NOT_FOUND if "not found" in str(exc).lower() else status.HTTP_400_BAD_REQUEST
        return JSONResponse(
            status_code=status_code,
            content=build_error_payload(exc.__class__.__name__, str(exc), getattr(exc, "details", {})),
        )

    @app.exception_handler(BootstrapError)
    async def generic_bootstrap_handler(request: Request, exc: BootstrapError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=build_error_payload(exc.__class__.__name__, str(exc), getattr(exc, "details", {})),
        )

    @app.exception_handler(RequestValidationError)
    async def fastapi_validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=build_error_payload(
                "RequestValidationError",
                "Request body or parameters failed validation.",
                {"errors": exc.errors()},
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def starlette_http_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code_name = "HTTPException"
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            code_name = "NotFoundError"
        elif exc.status_code == status.HTTP_401_UNAUTHORIZED:
            code_name = "UnauthorizedError"
        elif exc.status_code == status.HTTP_403_FORBIDDEN:
            code_name = "ForbiddenError"
        return JSONResponse(
            status_code=exc.status_code,
            content=build_error_payload(code_name, exc.detail if isinstance(exc.detail, str) else str(exc.detail)),
            headers=exc.headers,
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled server exception: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=build_error_payload(
                "InternalServerError",
                "An unexpected internal server error occurred.",
            ),
        )
