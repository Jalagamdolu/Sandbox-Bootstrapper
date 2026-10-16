"""Tests for approval creation, validation, atomic CAS consumption, and concurrency."""

from __future__ import annotations

import concurrent.futures
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import pytest

from src.core.exceptions import (
    ApprovalAlreadyConsumedError,
    ApprovalExpiredError,
    ApprovalMismatchError,
    ApprovalNotFoundError,
    ApprovalRevokedError,
    TokenScopeError,
)
from src.models.approvals import ApprovalDecisionType, ApprovalRequest, ApproverIdentity
from src.models.enums import PermissionScope
from src.security.approvals import ApprovalService
from src.security.tokens import TokenService
from src.storage.connection import get_connection


def _setup_request_and_plan(db_path: Path, request_id: str, plan_hash: str, plan_version: int = 1) -> None:
    """Helper to insert matching bootstrap request and setup plan rows."""
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
            "test-proj",
            "python-fastapi-service",
            "c:/repos/proj",
            '["sandbox:create", "data:seed:synthetic"]',
            "dev-1",
            "local-sandbox",
            "PENDING_APPROVAL",
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
            plan_version,
            "local-sandbox",
            plan_hash,
            "{}",
            now,
        ),
    )
    conn.commit()
    conn.close()


def test_valid_approval_creation_and_retrieval(
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify an authentic approval is created with 30-min TTL and can be retrieved."""
    req_id = "req-appr-01"
    plan_hash = "a" * 64
    _setup_request_and_plan(initialized_db_path, req_id, plan_hash)

    token_res = token_service.create_token(
        approver_id="approver-alice",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.DATA_SEED_SYNTHETIC],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)

    request = ApprovalRequest(
        request_id=req_id,
        decision=ApprovalDecisionType.APPROVE,
        submitted_plan_hash=plan_hash,
        plan_version=1,
    )

    record = approval_service.create_approval(
        request=request,
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )

    assert record.approval_id.startswith("appr-")
    assert record.request_id == req_id
    assert record.approver_id == "approver-alice"
    assert record.decision == ApprovalDecisionType.APPROVE
    assert record.canonical_plan_hash == plan_hash
    assert record.execution_consumed is False
    assert record.is_revoked is False
    # Verified TTL is approximately 30 minutes in future
    ttl_seconds = (record.expires_at - record.created_at).total_seconds()
    assert 1790 <= ttl_seconds <= 1810

    # Retrieve from DB
    retrieved = approval_service.get_approval(record.approval_id, db_path=initialized_db_path)
    assert retrieved.approval_id == record.approval_id
    assert retrieved.approver_id == "approver-alice"


def test_unauthorized_approver_scope_rejected(
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify approver cannot grant scopes exceeding their authorized scopes."""
    req_id = "req-scope-fail"
    plan_hash = "b" * 64
    _setup_request_and_plan(initialized_db_path, req_id, plan_hash)

    # Token only has SANDBOX_READ
    token_res = token_service.create_token(
        approver_id="junior-dev",
        role="DEVELOPER",
        authorized_scopes=[PermissionScope.SANDBOX_READ],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)

    request = ApprovalRequest(
        request_id=req_id,
        decision=ApprovalDecisionType.APPROVE,
        submitted_plan_hash=plan_hash,
        plan_version=1,
    )

    with pytest.raises(TokenScopeError):
        approval_service.create_approval(
            request=request,
            approver=identity,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.SANDBOX_CREATE],  # Not authorized!
            db_path=initialized_db_path,
        )


def test_plan_hash_mismatch_rejected(
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify approval creation is rejected if submitted plan hash does not match stored plan."""
    req_id = "req-hash-fail"
    stored_hash = "c" * 64
    _setup_request_and_plan(initialized_db_path, req_id, stored_hash)

    token_res = token_service.create_token(
        approver_id="approver-lead",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)

    request = ApprovalRequest(
        request_id=req_id,
        decision=ApprovalDecisionType.APPROVE,
        submitted_plan_hash="d" * 64,  # Drifts from stored hash!
        plan_version=1,
    )

    with pytest.raises(ApprovalMismatchError):
        approval_service.create_approval(
            request=request,
            approver=identity,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.SANDBOX_CREATE],
            db_path=initialized_db_path,
        )


def test_atomic_cas_consumption_single_use(
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify single-use consumption succeeds once and subsequent attempt fails."""
    req_id = "req-cas-01"
    plan_hash = "e" * 64
    _setup_request_and_plan(initialized_db_path, req_id, plan_hash)

    token_res = token_service.create_token(
        approver_id="approver-bob",
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

    # First consumption succeeds
    consumed = approval_service.consume_approval_atomic(
        approval_id=record.approval_id,
        request_id=req_id,
        canonical_plan_hash=plan_hash,
        plan_version=1,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        execution_id="exec-run-1",
        db_path=initialized_db_path,
    )
    assert consumed.execution_consumed is True
    assert consumed.consumed_at is not None
    assert consumed.execution_id == "exec-run-1"

    # Second consumption with a different execution ID fails (Replay Protection)
    with pytest.raises(ApprovalAlreadyConsumedError):
        approval_service.consume_approval_atomic(
            approval_id=record.approval_id,
            request_id=req_id,
            canonical_plan_hash=plan_hash,
            plan_version=1,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.SANDBOX_CREATE],
            execution_id="exec-run-2",  # Different execution: Replay attempt!
            db_path=initialized_db_path,
        )


def test_crash_retry_idempotency_allows_same_execution_id(
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify crash recovery: retrying with the SAME execution_id reconciles safely rather than failing."""
    req_id = "req-crash-retry"
    plan_hash = "f" * 64
    _setup_request_and_plan(initialized_db_path, req_id, plan_hash)

    token_res = token_service.create_token(
        approver_id="lead-1",
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

    # First attempt consumes approval
    first_run = approval_service.consume_approval_atomic(
        approval_id=record.approval_id,
        request_id=req_id,
        canonical_plan_hash=plan_hash,
        plan_version=1,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        execution_id="exec-reconcile-001",
        db_path=initialized_db_path,
    )

    # Retry after simulated crash with the exact SAME execution ID
    retry_run = approval_service.consume_approval_atomic(
        approval_id=record.approval_id,
        request_id=req_id,
        canonical_plan_hash=plan_hash,
        plan_version=1,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        execution_id="exec-reconcile-001",  # Same execution: Reconcile!
        db_path=initialized_db_path,
    )

    assert retry_run.approval_id == first_run.approval_id
    assert retry_run.execution_consumed is True
    assert retry_run.execution_id == "exec-reconcile-001"


def test_concurrent_consumption_has_exactly_one_winner(
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """
    CRITICAL CONCURRENCY REQUIREMENT:
    Simulate 5 concurrent threads racing to consume the same approval.
    Demonstrates that exactly ONE thread succeeds and all 4 others fail with ApprovalAlreadyConsumedError.
    """
    req_id = "req-concur-race"
    plan_hash = "1" * 64
    _setup_request_and_plan(initialized_db_path, req_id, plan_hash)

    token_res = token_service.create_token(
        approver_id="approver-lead",
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

    results: list[str] = []
    errors: list[Exception] = []

    def _worker(thread_idx: int) -> None:
        try:
            consumed = approval_service.consume_approval_atomic(
                approval_id=record.approval_id,
                request_id=req_id,
                canonical_plan_hash=plan_hash,
                plan_version=1,
                target_environment="local-sandbox",
                granted_scopes=[PermissionScope.SANDBOX_CREATE],
                execution_id=f"exec-thread-{thread_idx}",
                db_path=initialized_db_path,
            )
            results.append(f"WINNER: {thread_idx}")
        except ApprovalAlreadyConsumedError as err:
            errors.append(err)

    # Run 5 threads in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(_worker, i) for i in range(5)]
        concurrent.futures.wait(futures)

    # Exactly one winner, exactly 4 failures
    assert len(results) == 1
    assert len(errors) == 4
    for err in errors:
        assert isinstance(err, ApprovalAlreadyConsumedError)


def test_expired_approval_rejected(
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify expired approval cannot be consumed."""
    req_id = "req-expired"
    plan_hash = "2" * 64
    _setup_request_and_plan(initialized_db_path, req_id, plan_hash)

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

    # Artificially expire the record in the database
    conn = get_connection(initialized_db_path)
    cursor = conn.cursor()
    past_time = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    cursor.execute("UPDATE approval_records SET expires_at = ? WHERE approval_id = ?;", (past_time, record.approval_id))
    conn.commit()
    conn.close()

    with pytest.raises(ApprovalExpiredError):
        approval_service.consume_approval_atomic(
            approval_id=record.approval_id,
            request_id=req_id,
            canonical_plan_hash=plan_hash,
            plan_version=1,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.SANDBOX_CREATE],
            execution_id="exec-late",
            db_path=initialized_db_path,
        )


def test_revoked_approval_rejected(
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify explicitly revoked approval cannot be consumed."""
    req_id = "req-revoked"
    plan_hash = "3" * 64
    _setup_request_and_plan(initialized_db_path, req_id, plan_hash)

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

    # Explicitly revoke
    approval_service.revoke_approval(record.approval_id, "Security concern detected", db_path=initialized_db_path)

    with pytest.raises(ApprovalRevokedError):
        approval_service.consume_approval_atomic(
            approval_id=record.approval_id,
            request_id=req_id,
            canonical_plan_hash=plan_hash,
            plan_version=1,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.SANDBOX_CREATE],
            execution_id="exec-revoked",
            db_path=initialized_db_path,
        )


def test_plan_mutation_auto_invalidates_approval(
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify modifying setup_plans fires trigger revoke_approvals_on_plan_change, invalidating approval."""
    req_id = "req-plan-mutate"
    orig_hash = "4" * 64
    _setup_request_and_plan(initialized_db_path, req_id, orig_hash)

    token_res = token_service.create_token(
        approver_id="lead-mut",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)

    record = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=orig_hash,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )

    # Mutate the plan in setup_plans
    conn = get_connection(initialized_db_path)
    cursor = conn.cursor()
    new_hash = "5" * 64
    cursor.execute(
        "UPDATE setup_plans SET canonical_plan_hash = ? WHERE request_id = ?;",
        (new_hash, req_id),
    )
    conn.commit()
    conn.close()

    # Database trigger has marked is_revoked = 1!
    updated_approval = approval_service.get_approval(record.approval_id, db_path=initialized_db_path)
    assert updated_approval.is_revoked is True
    assert "Plan altered post-approval" in str(updated_approval.rejection_reason)

    # Consumption attempt must raise ApprovalRevokedError
    with pytest.raises(ApprovalRevokedError):
        approval_service.consume_approval_atomic(
            approval_id=record.approval_id,
            request_id=req_id,
            canonical_plan_hash=orig_hash,
            plan_version=1,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.SANDBOX_CREATE],
            execution_id="exec-after-mutate",
            db_path=initialized_db_path,
        )


def test_get_and_revoke_approval_not_found(
    approval_service: ApprovalService,
    initialized_db_path: Path,
) -> None:
    """Verify get_approval and revoke_approval raise ApprovalNotFoundError on missing ID."""
    with pytest.raises(ApprovalNotFoundError):
        approval_service.get_approval("appr-missing", db_path=initialized_db_path)

    with pytest.raises(ApprovalNotFoundError):
        approval_service.revoke_approval("appr-missing", "Some reason", db_path=initialized_db_path)


def test_create_approval_version_and_env_mismatches(
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify create_approval rejects plan version or environment mismatches against setup_plans."""
    req_id = "req-mismatch-create"
    plan_hash = "6" * 64
    _setup_request_and_plan(initialized_db_path, req_id, plan_hash, plan_version=1)

    token_res = token_service.create_token(
        approver_id="approver-lead",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)

    # 1. Version mismatch
    with pytest.raises(ApprovalMismatchError, match="plan version"):
        approval_service.create_approval(
            request=ApprovalRequest(
                request_id=req_id,
                decision=ApprovalDecisionType.APPROVE,
                submitted_plan_hash=plan_hash,
                plan_version=2,  # Stored is 1!
            ),
            approver=identity,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.SANDBOX_CREATE],
            db_path=initialized_db_path,
        )

    # 2. Target environment mismatch
    with pytest.raises(ApprovalMismatchError, match="Target environment"):
        approval_service.create_approval(
            request=ApprovalRequest(
                request_id=req_id,
                decision=ApprovalDecisionType.APPROVE,
                submitted_plan_hash=plan_hash,
                plan_version=1,
            ),
            approver=identity,
            target_environment="cloud-production",  # Stored is local-sandbox!
            granted_scopes=[PermissionScope.SANDBOX_CREATE],
            db_path=initialized_db_path,
        )


def test_consume_approval_parameter_mismatches(
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify consume_approval_atomic rejects mismatches on request_id, version, env, or scopes."""
    req_id = "req-consume-mismatch"
    plan_hash = "7" * 64
    _setup_request_and_plan(initialized_db_path, req_id, plan_hash)

    token_res = token_service.create_token(
        approver_id="lead-mismatch",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.DATA_SEED_SYNTHETIC],
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

    # Mismatched request_id
    with pytest.raises(ApprovalMismatchError, match="Request ID"):
        approval_service.consume_approval_atomic(
            approval_id=record.approval_id,
            request_id="req-wrong",
            canonical_plan_hash=plan_hash,
            plan_version=1,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.SANDBOX_CREATE],
            execution_id="exec-1",
            db_path=initialized_db_path,
        )

    # Mismatched plan_version
    with pytest.raises(ApprovalMismatchError, match="Plan version"):
        approval_service.consume_approval_atomic(
            approval_id=record.approval_id,
            request_id=req_id,
            canonical_plan_hash=plan_hash,
            plan_version=99,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.SANDBOX_CREATE],
            execution_id="exec-1",
            db_path=initialized_db_path,
        )

    # Mismatched target_environment
    with pytest.raises(ApprovalMismatchError, match="Target environment"):
        approval_service.consume_approval_atomic(
            approval_id=record.approval_id,
            request_id=req_id,
            canonical_plan_hash=plan_hash,
            plan_version=1,
            target_environment="other-env",
            granted_scopes=[PermissionScope.SANDBOX_CREATE],
            execution_id="exec-1",
            db_path=initialized_db_path,
        )

    # Mismatched granted_scopes
    with pytest.raises(ApprovalMismatchError, match="Granted permission scopes"):
        approval_service.consume_approval_atomic(
            approval_id=record.approval_id,
            request_id=req_id,
            canonical_plan_hash=plan_hash,
            plan_version=1,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.DATA_SEED_SYNTHETIC],  # Mismatched!
            execution_id="exec-1",
            db_path=initialized_db_path,
        )
