"""Tests for ServerSideAuthGuard enforcing 8-point revalidation and failing closed."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

from src.core.exceptions import AuthorizationDeniedError
from src.models.approvals import (
    ApprovalDecisionType,
    ApprovalRequest,
    AuthGuardEvaluationContext,
)
from src.models.enums import PermissionScope, StepActionType, WorkflowStatus
from src.security.approvals import ApprovalService
from src.security.guard import ServerSideAuthGuard
from src.security.tokens import TokenService
from src.storage.connection import get_connection


def _setup_base_env(db_path: Path, request_id: str, plan_hash: str) -> None:
    """Helper to set up database request and plan rows."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    cursor.execute(
        """
        INSERT OR IGNORE INTO bootstrap_requests (
            request_id, idempotency_key, project_name, template, repository_path,
            requested_scopes, developer_id, target_environment, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            request_id,
            f"idem-{request_id}",
            "guard-proj",
            "python-fastapi-service",
            "c:/repos/proj",
            '["sandbox:create", "data:seed:synthetic"]',
            "dev-1",
            "local-sandbox",
            "APPROVED",
            now,
            now,
        ),
    )
    cursor.execute(
        """
        INSERT OR REPLACE INTO setup_plans (
            plan_id, request_id, plan_version, target_environment, canonical_plan_hash, plan_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?);
        """,
        (
            f"plan-{request_id}",
            request_id,
            1,
            "local-sandbox",
            plan_hash,
            "{}",
            now,
        ),
    )
    conn.commit()
    conn.close()


def test_guard_valid_operation_accepted(
    auth_guard: ServerSideAuthGuard,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify an authentic, unexpired approval with matching plan and scope passes guard evaluation."""
    req_id = "req-guard-ok"
    plan_hash = "a" * 64
    _setup_base_env(initialized_db_path, req_id, plan_hash)

    token_res = token_service.create_token(
        approver_id="lead-guard",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)

    record = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )

    ctx = AuthGuardEvaluationContext(
        approval_id=record.approval_id,
        request_id=req_id,
        action_type=StepActionType.PROVISION_MOCK_SANDBOX,
        target_environment="local-sandbox",
        required_scope=PermissionScope.SANDBOX_CREATE,
        active_plan_hash=plan_hash,
        active_plan_version=1,
        current_status=WorkflowStatus.APPROVED,
        current_time=datetime.now(timezone.utc),
    )

    assert auth_guard.evaluate(ctx, caller_token=token_res.raw_token, db_path=initialized_db_path) is True


def test_guard_missing_approval_fails_closed(
    auth_guard: ServerSideAuthGuard,
    initialized_db_path: Path,
) -> None:
    """Verify missing approval record denies the operation and fails closed."""
    ctx = AuthGuardEvaluationContext(
        approval_id="appr-nonexistent",
        request_id="req-none",
        action_type=StepActionType.PROVISION_MOCK_SANDBOX,
        target_environment="local-sandbox",
        required_scope=PermissionScope.SANDBOX_CREATE,
        active_plan_hash="b" * 64,
        active_plan_version=1,
        current_status=WorkflowStatus.APPROVED,
        current_time=datetime.now(timezone.utc),
    )
    with pytest.raises(AuthorizationDeniedError, match="does not exist"):
        auth_guard.evaluate(ctx, db_path=initialized_db_path)


def test_guard_revoked_approval_fails_closed(
    auth_guard: ServerSideAuthGuard,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify revoked approval denies the operation and fails closed."""
    req_id = "req-guard-rev"
    plan_hash = "c" * 64
    _setup_base_env(initialized_db_path, req_id, plan_hash)

    token_res = token_service.create_token(
        approver_id="lead-rev",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)

    record = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )

    # Revoke approval
    approval_service.revoke_approval(record.approval_id, "Revoked for security test", db_path=initialized_db_path)

    ctx = AuthGuardEvaluationContext(
        approval_id=record.approval_id,
        request_id=req_id,
        action_type=StepActionType.PROVISION_MOCK_SANDBOX,
        target_environment="local-sandbox",
        required_scope=PermissionScope.SANDBOX_CREATE,
        active_plan_hash=plan_hash,
        active_plan_version=1,
        current_status=WorkflowStatus.APPROVED,
        current_time=datetime.now(timezone.utc),
    )

    with pytest.raises(AuthorizationDeniedError, match="has been revoked"):
        auth_guard.evaluate(ctx, db_path=initialized_db_path)


def test_guard_expired_approval_fails_closed(
    auth_guard: ServerSideAuthGuard,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify expired approval denies the operation and fails closed."""
    req_id = "req-guard-exp"
    plan_hash = "d" * 64
    _setup_base_env(initialized_db_path, req_id, plan_hash)

    token_res = token_service.create_token(
        approver_id="lead-exp",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)

    record = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )

    # Evaluate 1 hour into future (past 30 min TTL)
    future_time = datetime.now(timezone.utc) + timedelta(hours=1)
    ctx = AuthGuardEvaluationContext(
        approval_id=record.approval_id,
        request_id=req_id,
        action_type=StepActionType.PROVISION_MOCK_SANDBOX,
        target_environment="local-sandbox",
        required_scope=PermissionScope.SANDBOX_CREATE,
        active_plan_hash=plan_hash,
        active_plan_version=1,
        current_status=WorkflowStatus.APPROVED,
        current_time=future_time,
    )

    with pytest.raises(AuthorizationDeniedError, match="has expired"):
        auth_guard.evaluate(ctx, db_path=initialized_db_path)


def test_guard_insufficient_scope_fails_closed(
    auth_guard: ServerSideAuthGuard,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify approval without required scope denies privileged operation."""
    req_id = "req-guard-scope"
    plan_hash = "e" * 64
    _setup_base_env(initialized_db_path, req_id, plan_hash)

    token_res = token_service.create_token(
        approver_id="lead-scope",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_READ],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)

    record = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_READ],
        db_path=initialized_db_path,
    )

    # Attempt action requiring SANDBOX_CREATE when only SANDBOX_READ is approved
    ctx = AuthGuardEvaluationContext(
        approval_id=record.approval_id,
        request_id=req_id,
        action_type=StepActionType.PROVISION_MOCK_SANDBOX,
        target_environment="local-sandbox",
        required_scope=PermissionScope.SANDBOX_CREATE,  # Not granted!
        active_plan_hash=plan_hash,
        active_plan_version=1,
        current_status=WorkflowStatus.APPROVED,
        current_time=datetime.now(timezone.utc),
    )

    with pytest.raises(AuthorizationDeniedError, match="Required scope .* is not granted"):
        auth_guard.evaluate(ctx, db_path=initialized_db_path)


def test_guard_plan_drift_fails_closed(
    auth_guard: ServerSideAuthGuard,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify drift between approved hash and active plan hash denies execution."""
    req_id = "req-guard-drift"
    plan_hash = "f" * 64
    _setup_base_env(initialized_db_path, req_id, plan_hash)

    token_res = token_service.create_token(
        approver_id="lead-drift",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)

    record = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )

    # Caller submits drifted plan hash
    ctx = AuthGuardEvaluationContext(
        approval_id=record.approval_id,
        request_id=req_id,
        action_type=StepActionType.PROVISION_MOCK_SANDBOX,
        target_environment="local-sandbox",
        required_scope=PermissionScope.SANDBOX_CREATE,
        active_plan_hash="0" * 64,  # Drifted!
        active_plan_version=1,
        current_status=WorkflowStatus.APPROVED,
        current_time=datetime.now(timezone.utc),
    )

    with pytest.raises(AuthorizationDeniedError, match="Plan hash mismatch"):
        auth_guard.evaluate(ctx, db_path=initialized_db_path)


def test_guard_incompatible_workflow_status_fails_closed(
    auth_guard: ServerSideAuthGuard,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify operations are denied if the request is in a terminal/incompatible state (e.g. FAILED)."""
    req_id = "req-guard-status"
    plan_hash = "9" * 64
    _setup_base_env(initialized_db_path, req_id, plan_hash)

    token_res = token_service.create_token(
        approver_id="lead-status",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)

    record = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )

    # Set request to FAILED in database
    conn = get_connection(initialized_db_path)
    cursor = conn.cursor()
    cursor.execute("UPDATE bootstrap_requests SET status = 'FAILED' WHERE request_id = ?;", (req_id,))
    conn.commit()
    conn.close()

    ctx = AuthGuardEvaluationContext(
        approval_id=record.approval_id,
        request_id=req_id,
        action_type=StepActionType.PROVISION_MOCK_SANDBOX,
        target_environment="local-sandbox",
        required_scope=PermissionScope.SANDBOX_CREATE,
        active_plan_hash=plan_hash,
        active_plan_version=1,
        current_status=WorkflowStatus.APPROVED,
        current_time=datetime.now(timezone.utc),
    )

    with pytest.raises(AuthorizationDeniedError, match="not permitted while request is in 'FAILED'"):
        auth_guard.evaluate(ctx, db_path=initialized_db_path)


def test_guard_approver_token_revoked_fails_closed(
    auth_guard: ServerSideAuthGuard,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify operation is denied if the original approving human's token has been revoked."""
    req_id = "req-guard-appr-rev"
    plan_hash = "8" * 64
    _setup_base_env(initialized_db_path, req_id, plan_hash)

    token_res = token_service.create_token(
        approver_id="lead-revoked-cred",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)

    record = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )

    # Revoke approver's token
    token_service.revoke_token(token_res.raw_token, db_path=initialized_db_path)

    ctx = AuthGuardEvaluationContext(
        approval_id=record.approval_id,
        request_id=req_id,
        action_type=StepActionType.PROVISION_MOCK_SANDBOX,
        target_environment="local-sandbox",
        required_scope=PermissionScope.SANDBOX_CREATE,
        active_plan_hash=plan_hash,
        active_plan_version=1,
        current_status=WorkflowStatus.APPROVED,
        current_time=datetime.now(timezone.utc),
    )

    with pytest.raises(AuthorizationDeniedError, match="has no active \\(non-revoked\\) credential"):
        auth_guard.evaluate(ctx, db_path=initialized_db_path)


def test_guard_caller_token_revoked_or_insufficient_scope(
    auth_guard: ServerSideAuthGuard,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify caller token is validated for non-revocation and required scope."""
    req_id = "req-guard-caller-chk"
    plan_hash = "7" * 64
    _setup_base_env(initialized_db_path, req_id, plan_hash)

    approver_res = token_service.create_token(
        approver_id="approver-lead",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(approver_res.raw_token, db_path=initialized_db_path)

    record = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )

    ctx = AuthGuardEvaluationContext(
        approval_id=record.approval_id,
        request_id=req_id,
        action_type=StepActionType.PROVISION_MOCK_SANDBOX,
        target_environment="local-sandbox",
        required_scope=PermissionScope.SANDBOX_CREATE,
        active_plan_hash=plan_hash,
        active_plan_version=1,
        current_status=WorkflowStatus.APPROVED,
        current_time=datetime.now(timezone.utc),
    )

    # 1. Caller token lacks SANDBOX_CREATE
    caller_token_no_scope = token_service.create_token(
        approver_id="dev-readonly",
        role="DEVELOPER",
        authorized_scopes=[PermissionScope.SANDBOX_READ],
        db_path=initialized_db_path,
    )
    with pytest.raises(AuthorizationDeniedError, match="lacks required scope"):
        auth_guard.evaluate(ctx, caller_token=caller_token_no_scope.raw_token, db_path=initialized_db_path)

    # 2. Caller token is revoked
    revoked_caller = token_service.create_token(
        approver_id="dev-revoked",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )
    token_service.revoke_token(revoked_caller.raw_token, db_path=initialized_db_path)
    with pytest.raises(AuthorizationDeniedError):
        auth_guard.evaluate(ctx, caller_token=revoked_caller.raw_token, db_path=initialized_db_path)
