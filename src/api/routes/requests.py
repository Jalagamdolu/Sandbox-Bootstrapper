"""Bootstrap request workflow and lifecycle endpoints."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field

from src.api.deps import (
    extract_bearer_token,
    get_approval_service,
    get_audit_service,
    get_orchestrator,
    get_token_service,
)
from src.core.config import get_settings
from src.core.exceptions import (
    ApprovalNotFoundError,
    ModelValidationError,
    SecurityViolationError,
    TokenScopeError,
    WorkflowError,
)
from src.models.approvals import ApprovalDecisionType, ApprovalRecord, ApprovalRequest, ApproverIdentity
from src.models.enums import AuditEventType, PermissionScope, WorkflowStatus
from src.models.manifest import SetupManifest
from src.models.plans import SetupPlan
from src.models.requests import BootstrapRequest, BootstrapRequestCreate
from src.models.workflow import WorkflowRunResult
from src.security.approvals import ApprovalService
from src.security.audit_chain import AuditChainService, VerificationReport
from src.security.tokens import TokenService
from src.storage.connection import get_connection
from src.workflow.discovery import RepoDiscoveryResult, discover_local_repository, discover_mock_dashboard
from src.workflow.orchestrator import WorkflowOrchestrator

router = APIRouter(prefix="/requests", tags=["Requests"])


# =============================================================================
# Request / Response Models
# =============================================================================


class ApprovalSubmitPayload(BaseModel):
    decision: ApprovalDecisionType = Field(default=ApprovalDecisionType.APPROVE, description="Approval decision")
    rejection_reason: str | None = Field(default=None, description="Reason if decision is REJECTED")
    target_environment: str | None = Field(default=None, description="Approved environment override")
    granted_scopes: list[PermissionScope] | None = Field(default=None, description="Explicit granted scopes")
    approver_token: str | None = Field(
        default=None,
        description="Plaintext approver token (optional if Authorization Bearer header is passed)",
    )


class ApprovalStateResponse(BaseModel):
    request_id: str
    status: WorkflowStatus
    approval_required: bool
    canonical_plan_hash: str | None = None
    plan_version: int | None = None
    target_environment: str
    requested_scopes: list[PermissionScope]
    active_approval: ApprovalRecord | None = None
    is_approved: bool = False
    is_consumed: bool = False


class WorkflowRunPayload(BaseModel):
    execution_id: str | None = Field(default=None, description="Optional execution trace ID")
    caller_token: str | None = Field(default=None, description="Approver token if needed for execution tracing")


class CleanupPayload(BaseModel):
    sandbox_id: str = Field(..., description="ID of mock sandbox to delete")
    approval_id: str = Field(..., description="Approval ID granting delete authority")
    execution_id: str = Field(default="cleanup-execution", description="Execution tracking ID")
    approver_token: str | None = Field(default=None, description="Token with SANDBOX_DELETE scope")


class AuditEventResponse(BaseModel):
    event_id: str
    request_id: str
    sequence_number: int
    timestamp: str
    event_type: str
    severity: str
    actor_id: str
    actor_role: str
    action_name: str
    state_before: str | None = None
    state_after: str | None = None
    previous_event_hash: str
    payload_hash: str
    event_hash: str
    details: dict[str, Any]


class AuditLogResponse(BaseModel):
    request_id: str
    chain_valid: bool
    events_inspected: int
    events: list[AuditEventResponse]
    verification_errors: list[str] = []


# =============================================================================
# Helper Functions
# =============================================================================


def _resolve_token(
    header_token: str | None,
    payload_token: str | None,
    token_service: TokenService,
) -> tuple[str, ApproverIdentity]:
    """Resolve raw token and identity strictly server-side."""
    raw = header_token or payload_token
    if not raw or not raw.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required approver authentication token. Provide via Authorization header or payload.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    identity = token_service.resolve_identity(raw.strip())
    return raw.strip(), identity


# =============================================================================
# Endpoints
# =============================================================================


@router.post(
    "",
    response_model=BootstrapRequest,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new sandbox bootstrap request",
    description="Validates and persists a draft bootstrap request without provisioning or seeding.",
)
def create_request(
    payload: BootstrapRequestCreate,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    orchestrator: WorkflowOrchestrator = Depends(get_orchestrator),
) -> BootstrapRequest:
    return orchestrator.create_request(request_in=payload, idempotency_key=idempotency_key)


@router.get(
    "/{request_id}",
    response_model=BootstrapRequest,
    summary="Get bootstrap request details",
)
def get_request(
    request_id: str,
    orchestrator: WorkflowOrchestrator = Depends(get_orchestrator),
) -> BootstrapRequest:
    return orchestrator.get_request(request_id)


@router.get(
    "/{request_id}/discovery",
    response_model=dict[str, Any],
    summary="Inspect discovery findings for request",
    description="Inspects local repository structure and mock dashboard environment range.",
)
def get_discovery(
    request_id: str,
    orchestrator: WorkflowOrchestrator = Depends(get_orchestrator),
) -> dict[str, Any]:
    req = orchestrator.get_request(request_id)
    repo_discovery = discover_local_repository(req.repository_path)
    dash_discovery = discover_mock_dashboard()
    return {
        "request_id": req.request_id,
        "repository_path": req.repository_path,
        "repository_discovery": repo_discovery.model_dump(),
        "dashboard_discovery": dash_discovery.model_dump(),
    }


@router.get(
    "/{request_id}/plan",
    response_model=SetupPlan,
    summary="Inspect setup plan and canonical hash",
    description="Fetches or constructs deterministic template plan without executing privileged operations.",
)
def get_plan(
    request_id: str,
    orchestrator: WorkflowOrchestrator = Depends(get_orchestrator),
) -> SetupPlan:
    req = orchestrator.get_request(request_id)
    return orchestrator._get_or_create_plan(req)


@router.get(
    "/{request_id}/approval-state",
    response_model=ApprovalStateResponse,
    summary="Obtain approval requirement and current status",
    description="Inspects whether human approval is required before privileged execution can proceed.",
)
def get_approval_state(
    request_id: str,
    orchestrator: WorkflowOrchestrator = Depends(get_orchestrator),
) -> ApprovalStateResponse:
    req = orchestrator.get_request(request_id)
    plan = orchestrator._get_or_create_plan(req)
    approval = orchestrator._check_approval(req, plan)

    is_approved = approval is not None and approval.decision == ApprovalDecisionType.APPROVE
    is_consumed = approval.execution_consumed if approval else False
    approval_required = not is_approved and req.status not in (WorkflowStatus.COMPLETED, WorkflowStatus.FAILED)

    return ApprovalStateResponse(
        request_id=req.request_id,
        status=req.status,
        approval_required=approval_required,
        canonical_plan_hash=plan.canonical_plan_hash,
        plan_version=plan.plan_version,
        target_environment=plan.target_environment,
        requested_scopes=req.requested_scopes,
        active_approval=approval,
        is_approved=is_approved,
        is_consumed=is_consumed,
    )


@router.post(
    "/{request_id}/approve",
    response_model=ApprovalRecord,
    status_code=status.HTTP_200_OK,
    summary="Submit an authorized approval or rejection",
    description="Enforces server-side approver identity resolution, scope authorization, and plan hash verification.",
)
def submit_approval(
    request_id: str,
    payload: ApprovalSubmitPayload,
    bearer_token: str | None = Depends(extract_bearer_token),
    orchestrator: WorkflowOrchestrator = Depends(get_orchestrator),
    approval_service: ApprovalService = Depends(get_approval_service),
    token_service: TokenService = Depends(get_token_service),
) -> ApprovalRecord:
    _, identity = _resolve_token(bearer_token, payload.approver_token, token_service)

    req = orchestrator.get_request(request_id)
    plan = orchestrator._get_or_create_plan(req)

    granted_scopes = payload.granted_scopes or req.requested_scopes
    target_env = payload.target_environment or req.target_environment

    approval_req = ApprovalRequest(
        request_id=request_id,
        submitted_plan_hash=plan.canonical_plan_hash,
        plan_version=plan.plan_version,
        decision=payload.decision,
        rejection_reason=payload.rejection_reason,
    )

    approval_record = approval_service.create_approval(
        request=approval_req,
        approver=identity,
        target_environment=target_env,
        granted_scopes=granted_scopes,
    )

    return approval_record


@router.post(
    "/{request_id}/run",
    response_model=WorkflowRunResult,
    summary="Trigger or resume bootstrapper workflow execution",
    description="Coordinates workflow stages. Pauses at AWAIT_APPROVAL if valid human approval is missing.",
)
def run_workflow(
    request_id: str,
    payload: WorkflowRunPayload | None = None,
    bearer_token: str | None = Depends(extract_bearer_token),
    orchestrator: WorkflowOrchestrator = Depends(get_orchestrator),
) -> WorkflowRunResult:
    caller_token = bearer_token
    exec_id = None
    if payload:
        caller_token = caller_token or payload.caller_token
        exec_id = payload.execution_id

    result = orchestrator.run_workflow(
        request_id=request_id,
        execution_id=exec_id,
        caller_token=caller_token,
        raise_on_failure=False,
    )
    return result


@router.get(
    "/{request_id}/manifest",
    response_model=SetupManifest,
    summary="Retrieve finalized setup manifest",
    description="Returns the deterministic setup manifest containing environment details, fixtures, and integrity digest.",
)
def get_manifest(
    request_id: str,
    orchestrator: WorkflowOrchestrator = Depends(get_orchestrator),
) -> SetupManifest:
    req = orchestrator.get_request(request_id)
    settings = get_settings()
    sandbox_root = Path(settings.sandbox_storage_dir)

    tracked = orchestrator._find_tracked_sandbox(request_id, sandbox_root)
    if tracked is None or not tracked.sandbox_dir.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No provisioned sandbox or manifest found for request '{request_id}'.",
        )

    manifest_path = tracked.sandbox_dir / "manifest.json"
    if not manifest_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Manifest not found in sandbox '{tracked.sandbox_id}'.",
        )

    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        return SetupManifest.model_validate(data)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to parse manifest: {exc}",
        ) from exc


@router.get(
    "/{request_id}/audit",
    response_model=AuditLogResponse,
    summary="Inspect hash-chained audit events",
    description="Retrieves chronological audit events for this request and verifies chain integrity.",
)
def get_audit_log(
    request_id: str,
    audit_service: AuditChainService = Depends(get_audit_service),
) -> AuditLogResponse:
    report: VerificationReport = audit_service.verify_chain()

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT event_id, request_id, sequence_number, timestamp, event_type,
                   severity, actor_id, actor_role, action_name, state_before,
                   state_after, previous_event_hash, payload_hash, event_hash, details
            FROM audit_log
            WHERE request_id = ?
            ORDER BY sequence_number ASC;
            """,
            (request_id,),
        )
        rows = cursor.fetchall()
        cursor.close()
    finally:
        conn.close()

    events = [
        AuditEventResponse(
            event_id=row["event_id"],
            request_id=row["request_id"],
            sequence_number=row["sequence_number"],
            timestamp=row["timestamp"],
            event_type=row["event_type"],
            severity=row["severity"],
            actor_id=row["actor_id"],
            actor_role=row["actor_role"],
            action_name=row["action_name"],
            state_before=row["state_before"],
            state_after=row["state_after"],
            previous_event_hash=row["previous_event_hash"],
            payload_hash=row["payload_hash"],
            event_hash=row["event_hash"],
            details=json.loads(row["details"]),
        )
        for row in rows
    ]

    return AuditLogResponse(
        request_id=request_id,
        chain_valid=report.is_valid,
        events_inspected=len(events),
        events=events,
        verification_errors=report.errors,
    )


@router.post(
    "/{request_id}/cleanup",
    response_model=dict[str, Any],
    summary="Delete mock sandbox under authorized SANDBOX_DELETE scope",
    description="Enforces server-side verification that caller token holds SANDBOX_DELETE before removing sandbox files.",
)
def cleanup_sandbox(
    request_id: str,
    payload: CleanupPayload,
    bearer_token: str | None = Depends(extract_bearer_token),
    orchestrator: WorkflowOrchestrator = Depends(get_orchestrator),
    token_service: TokenService = Depends(get_token_service),
) -> dict[str, Any]:
    raw_token, identity = _resolve_token(bearer_token, payload.approver_token, token_service)

    if PermissionScope.SANDBOX_DELETE not in identity.authorized_scopes:
        raise TokenScopeError(
            f"Approver '{identity.approver_id}' lacks required permission scope 'sandbox:delete'."
        )

    success = orchestrator.cleanup_workflow_sandbox(
        request_id=request_id,
        sandbox_id=payload.sandbox_id,
        approval_id=payload.approval_id,
        execution_id=payload.execution_id,
        caller_token=raw_token,
    )

    return {
        "status": "deleted" if success else "failed",
        "sandbox_id": payload.sandbox_id,
        "request_id": request_id,
        "approver_id": identity.approver_id,
    }
