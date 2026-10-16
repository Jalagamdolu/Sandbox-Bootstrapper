"""Approver token management endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field

from src.api.deps import get_token_service
from src.models.enums import PermissionScope
from src.security.tokens import TokenCreationResult, TokenService

router = APIRouter(prefix="/tokens", tags=["Tokens"])


class TokenCreatePayload(BaseModel):
    approver_id: str = Field(..., min_length=3, max_length=128, description="Unique human approver identifier")
    role: str = Field(default="SECURITY_LEAD", max_length=64, description="Approver role")
    authorized_scopes: list[PermissionScope] = Field(
        ..., min_length=1, description="List of permission scopes this approver can authorize"
    )


class TokenCreateResponse(BaseModel):
    raw_token: str = Field(..., description="Plaintext bearer token. Displayed once; never stored or logged.")
    token_hash: str = Field(..., description="SHA-256 digest stored server-side.")
    approver_id: str
    role: str
    authorized_scopes: list[PermissionScope]
    created_at: datetime
    security_notice: str = "Store this token securely. Raw tokens are never logged, stored, or re-displayed."


class TokenRevokePayload(BaseModel):
    token_hash: str = Field(..., min_length=64, max_length=64, description="SHA-256 hash of token to revoke")


class TokenRevokeResponse(BaseModel):
    status: str
    token_hash: str


@router.post(
    "",
    response_model=TokenCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Issue a development approver token",
    description="Generates a cryptographically random token with 256 bits of entropy and returns it once.",
)
def create_approver_token(
    payload: TokenCreatePayload,
    token_service: TokenService = Depends(get_token_service),
) -> TokenCreateResponse:
    result: TokenCreationResult = token_service.create_token(
        approver_id=payload.approver_id,
        role=payload.role,
        authorized_scopes=payload.authorized_scopes,
    )
    return TokenCreateResponse(
        raw_token=result.raw_token,
        token_hash=result.token_hash,
        approver_id=result.approver_id,
        role=result.role,
        authorized_scopes=result.authorized_scopes,
        created_at=result.created_at,
    )


@router.post(
    "/revoke",
    response_model=TokenRevokeResponse,
    status_code=status.HTTP_200_OK,
    summary="Revoke an approver token",
    description="Marks a token hash as revoked in SQLite.",
)
def revoke_approver_token(
    payload: TokenRevokePayload,
    token_service: TokenService = Depends(get_token_service),
) -> TokenRevokeResponse:
    token_service.revoke_token_by_hash(payload.token_hash)
    return TokenRevokeResponse(status="revoked", token_hash=payload.token_hash)
