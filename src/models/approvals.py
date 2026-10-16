"""Approval and server-side identity data contracts for Developer Sandbox Bootstrapper."""

from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field

from src.models.enums import ApprovalDecisionType, PermissionScope, StepActionType, WorkflowStatus


class ApproverIdentity(BaseModel):
    """Server-side record mapping a hashed token to a verified approver identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approver_id: str = Field(
        ...,
        min_length=2,
        max_length=64,
        description="Immutable identifier of the authorized approver",
    )
    role: str = Field(
        ...,
        min_length=2,
        max_length=64,
        description="Security role of the approver (e.g. 'SECURITY_LEAD', 'PROJECT_OWNER')",
    )
    authorized_scopes: list[PermissionScope] = Field(
        ...,
        description="Maximum scopes this identity is authorized to approve",
    )
    token_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="SHA-256 digest of the raw bearer token",
    )
    created_at: datetime = Field(..., description="Timestamp when token was issued")
    revoked_at: datetime | None = Field(default=None, description="Timestamp when token was revoked")


class ApprovalRequest(BaseModel):
    """
    Client submission to record an approval or rejection decision.
    Notice: NO client-supplied approver_id or approved flag exists here.
    Caller identity is established strictly server-side from the bearer token.
    """

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(..., description="Bootstrap request ID to approve or reject")
    decision: ApprovalDecisionType = Field(..., description="Decision: APPROVE or REJECT")
    submitted_plan_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Canonical SHA-256 plan fingerprint displayed to and verified by reviewer",
    )
    plan_version: int = Field(default=1, ge=1, description="Plan schema version being approved")
    rejection_reason: str | None = Field(
        default=None,
        max_length=512,
        description="Mandatory explanation if decision is REJECT",
    )


class ApprovalRecord(BaseModel):
    """Immutable server-side database record representing an authentic approval decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: str = Field(..., description="Unique approval record ID")
    request_id: str = Field(..., description="Associated request ID")
    approver_id: str = Field(..., description="Server-resolved identity of approving human")
    decision: ApprovalDecisionType = Field(..., description="Decision outcome")
    canonical_plan_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$", description="Approved plan fingerprint")
    plan_version: int = Field(..., ge=1, description="Approved plan version")
    target_environment: str = Field(..., description="Target environment approved for execution")
    granted_scopes: list[PermissionScope] = Field(..., description="Explicit scopes granted by approval")
    created_at: datetime = Field(..., description="Approval record creation timestamp")
    expires_at: datetime = Field(..., description="Timestamp after which approval expires (TTL)")
    is_revoked: bool = Field(default=False, description="Flag indicating if approval was revoked")
    execution_consumed: bool = Field(default=False, description="Flag indicating if approval was used")
    consumed_at: datetime | None = Field(default=None, description="Timestamp of execution consumption")
    rejection_reason: str | None = Field(default=None, description="Reason if decision was REJECT")
    execution_id: str | None = Field(default=None, description="Execution ID bound during atomic consumption")


class AuthGuardEvaluationContext(BaseModel):
    """The 8 parameters revalidated by ServerSideAuthGuard inside adapters."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: str
    request_id: str
    action_type: StepActionType
    target_environment: str
    required_scope: PermissionScope
    active_plan_hash: str
    active_plan_version: int
    current_status: WorkflowStatus
    current_time: datetime
