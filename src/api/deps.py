"""Dependency injection providers for FastAPI application."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Generator
import os

from fastapi import Depends, Header, HTTPException, Request, status

from src.core.config import Settings, get_settings
from src.core.exceptions import TokenError, TokenNotFoundError, TokenRevokedError
from src.models.approvals import ApproverIdentity
from src.security.approvals import ApprovalService
from src.security.audit_chain import AuditChainService
from src.security.tokens import TokenService
from src.workflow.orchestrator import WorkflowOrchestrator


def get_api_settings() -> Settings:
    """Retrieve application settings."""
    return get_settings()


def get_token_service() -> TokenService:
    """Provide TokenService instance."""
    return TokenService()


def get_approval_service() -> ApprovalService:
    """Provide ApprovalService instance."""
    return ApprovalService()


def get_audit_service() -> AuditChainService:
    """Provide AuditChainService instance."""
    return AuditChainService()


def get_orchestrator(
    approval_service: ApprovalService = Depends(get_approval_service),
    audit_service: AuditChainService = Depends(get_audit_service),
) -> WorkflowOrchestrator:
    """Provide WorkflowOrchestrator instance reusing core security services."""
    return WorkflowOrchestrator(
        approval_service=approval_service,
        audit_service=audit_service,
    )


def extract_bearer_token(
    authorization: str | None = Header(None, alias="Authorization"),
) -> str | None:
    """
    Extract Bearer token from the standard Authorization header.
    Returns None if header is omitted or not formatted as 'Bearer <token>'.
    """
    if not authorization:
        return None
    parts = authorization.strip().split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def get_current_approver(
    raw_token: str | None = Depends(extract_bearer_token),
    token_service: TokenService = Depends(get_token_service),
) -> ApproverIdentity:
    """
    Resolve caller's authenticated ApproverIdentity using the Bearer token.
    Enforces server-side identity resolution and rejects invalid/revoked tokens.
    """
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Bearer authorization token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        identity = token_service.resolve_identity(raw_token)
        return identity
    except TokenRevokedError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Approver token revoked: {exc}",
        ) from exc
    except TokenNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid approver token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token error: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
