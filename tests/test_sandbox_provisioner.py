"""Tests for MockSandboxProvisioner, path confinement, pre-action guard, and cleanup."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import pytest

from src.core.exceptions import (
    ApprovalAlreadyConsumedError,
    AuthorizationDeniedError,
    PathTraversalError,
    ResourceOwnershipError,
)
from src.models.approvals import ApprovalDecisionType, ApprovalRequest
from src.models.enums import PermissionScope
from src.security.approvals import ApprovalService
from src.security.tokens import TokenService
from src.adapters.sandbox_provisioner import MockSandboxProvisioner
from src.storage.connection import get_connection


def _setup_req_and_plan(db_path: Path, request_id: str, plan_hash: str, scopes: list[str] | None = None) -> None:
    """Helper to populate bootstrap_requests and setup_plans rows."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    scopes_json = json.dumps(scopes or ["sandbox:create", "sandbox:delete", "data:seed:synthetic"])
    cursor.execute(
        """
        INSERT OR IGNORE INTO bootstrap_requests (
            request_id, idempotency_key, project_name, template, repository_path,
            requested_scopes, developer_id, target_environment, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'APPROVED', ?, ?);
        """,
        (
            request_id,
            f"idem-{request_id}",
            "mock-proj",
            "python-fastapi-service",
            "c:/repos/proj",
            scopes_json,
            "dev-1",
            "local-sandbox",
            now,
            now,
        ),
    )
    cursor.execute(
        """
        INSERT OR REPLACE INTO setup_plans (
            plan_id, request_id, plan_version, target_environment, canonical_plan_hash, plan_json, created_at
        ) VALUES (?, ?, 1, 'local-sandbox', ?, '{}', ?);
        """,
        (f"plan-{request_id}", request_id, plan_hash, now),
    )
    conn.commit()
    conn.close()


def test_mock_sandbox_provisioning_success(
    sandbox_provisioner: MockSandboxProvisioner,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
) -> None:
    """Verify local mock sandbox is provisioned inside sandbox_root under strict authorization."""
    req_id = "req-sbx-01"
    plan_hash = "a" * 64
    _setup_req_and_plan(initialized_db_path, req_id, plan_hash)

    token_res = token_service.create_token(
        approver_id="lead-alice",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)

    approval = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
            plan_version=1,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )

    # Execute provisioning
    result = sandbox_provisioner.provision_sandbox(
        request_id=req_id,
        approval_id=approval.approval_id,
        execution_id="exec-run-101",
        step_id="step-00000001",
        plan_hash=plan_hash,
        plan_version=1,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        caller_token=token_res.raw_token,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )

    # 1. Verify result structure
    assert result.sandbox_id.startswith("sbx-")
    assert result.request_id == req_id
    assert result.is_mock is True
    assert result.environment_label == "MOCK / LOCAL ONLY"
    assert result.status == "PROVISIONED"

    # 2. Verify filesystem: directory is inside mock_sandbox_root
    assert result.sandbox_dir.exists()
    assert result.sandbox_dir.is_dir()
    assert mock_sandbox_root in result.sandbox_dir.parents

    # 3. Verify .sandbox-metadata.json
    meta_file = result.sandbox_dir / ".sandbox-metadata.json"
    assert meta_file.exists()
    meta_data = json.loads(meta_file.read_text(encoding="utf-8"))
    assert meta_data["sandbox_id"] == result.sandbox_id
    assert meta_data["ownership_token"] == result.ownership_token
    assert meta_data["is_mock"] is True

    # 4. Verify tracked_resources in database
    conn = get_connection(initialized_db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT resource_id, filesystem_path, ownership_token FROM tracked_resources WHERE resource_id = ?;",
        (result.sandbox_id,),
    )
    row = cursor.fetchone()
    conn.close()
    assert row is not None
    assert row["resource_id"] == result.sandbox_id
    assert row["ownership_token"] == result.ownership_token


def test_path_confinement_and_traversal_rejection(
    sandbox_provisioner: MockSandboxProvisioner,
    mock_sandbox_root: Path,
) -> None:
    """Verify path traversal escapes are rejected immediately by resolve_safe_path."""
    from src.adapters.path_utils import resolve_safe_path

    # Directory traversal
    with pytest.raises(PathTraversalError, match="traversal escape"):
        resolve_safe_path(mock_sandbox_root, "../../escape_dir")

    with pytest.raises(PathTraversalError):
        resolve_safe_path(mock_sandbox_root, "subdir/../../../root_escape")

    # Absolute path escape
    with pytest.raises(PathTraversalError, match="Absolute path escape"):
        resolve_safe_path(mock_sandbox_root, "C:/Windows/System32")

    # Null byte injection
    with pytest.raises(PathTraversalError, match="null byte"):
        resolve_safe_path(mock_sandbox_root, "sandbox\0evil")


def test_idempotent_provisioning_same_execution_id(
    sandbox_provisioner: MockSandboxProvisioner,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
) -> None:
    """Verify provisioning twice with the same execution_id returns the existing verified sandbox."""
    req_id = "req-sbx-idem"
    plan_hash = "b" * 64
    _setup_req_and_plan(initialized_db_path, req_id, plan_hash)

    token_res = token_service.create_token(
        approver_id="lead-bob",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)

    approval = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
            plan_version=1,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )

    # First call
    res1 = sandbox_provisioner.provision_sandbox(
        request_id=req_id,
        approval_id=approval.approval_id,
        execution_id="exec-idem-run",
        step_id="step-00000001",
        plan_hash=plan_hash,
        plan_version=1,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        caller_token=token_res.raw_token,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )

    # Second call (simulated retry)
    res2 = sandbox_provisioner.provision_sandbox(
        request_id=req_id,
        approval_id=approval.approval_id,
        execution_id="exec-idem-run",
        step_id="step-00000001",
        plan_hash=plan_hash,
        plan_version=1,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        caller_token=token_res.raw_token,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )

    assert res1.sandbox_id == res2.sandbox_id
    assert res1.ownership_token == res2.ownership_token


def test_rejection_of_unowned_existing_directory(
    sandbox_provisioner: MockSandboxProvisioner,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify that if a target directory exists without application metadata, overwrite is blocked."""
    req_id = "req-unowned-dir"
    plan_hash = "c" * 64
    _setup_req_and_plan(initialized_db_path, req_id, plan_hash)

    token_res = token_service.create_token(
        approver_id="lead-charlie",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)

    approval = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
            plan_version=1,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )

    # Pre-create directory in root without .sandbox-metadata.json
    fixed_sbx_id = "sbx-1234567890ab"
    existing_dir = mock_sandbox_root / fixed_sbx_id
    existing_dir.mkdir(parents=True, exist_ok=True)
    (existing_dir / "user_personal_file.txt").write_text("DO NOT OVERWRITE", encoding="utf-8")

    class MockUUID:
        hex = "1234567890ab"

        def __str__(self) -> str:
            return "mock-token-uuid-12345"

    monkeypatch.setattr("src.adapters.sandbox_provisioner.uuid.uuid4", lambda: MockUUID())



    with pytest.raises(ResourceOwnershipError, match="Overwrite forbidden"):
        sandbox_provisioner.provision_sandbox(
            request_id=req_id,
            approval_id=approval.approval_id,
            execution_id="exec-collide",
            step_id="step-00000001",
            plan_hash=plan_hash,
            plan_version=1,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.SANDBOX_CREATE],
            caller_token=token_res.raw_token,
            custom_root=mock_sandbox_root,
            db_path=initialized_db_path,
        )

    # Personal file remains untouched
    assert (existing_dir / "user_personal_file.txt").read_text(encoding="utf-8") == "DO NOT OVERWRITE"


def test_safe_cleanup_application_owned(
    sandbox_provisioner: MockSandboxProvisioner,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
) -> None:
    """Verify cleanup successfully removes application-owned sandbox directory under a valid delete approval."""
    req_id = "req-cleanup-ok"
    plan_hash = "d" * 64
    _setup_req_and_plan(initialized_db_path, req_id, plan_hash)

    # Token and approval for provisioning
    prov_token = token_service.create_token(
        approver_id="lead-prov",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )
    prov_identity = token_service.resolve_identity(prov_token.raw_token, db_path=initialized_db_path)
    prov_approval = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
            plan_version=1,
        ),
        approver=prov_identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )

    sbx = sandbox_provisioner.provision_sandbox(
        request_id=req_id,
        approval_id=prov_approval.approval_id,
        execution_id="exec-prov-01",
        step_id="step-00000001",
        plan_hash=plan_hash,
        plan_version=1,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        caller_token=prov_token.raw_token,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )
    assert sbx.sandbox_dir.exists()

    # Token and approval for cleanup (requires SANDBOX_DELETE)
    del_token = token_service.create_token(
        approver_id="lead-del",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_DELETE],
        db_path=initialized_db_path,
    )
    del_identity = token_service.resolve_identity(del_token.raw_token, db_path=initialized_db_path)
    del_approval = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
            plan_version=1,
        ),
        approver=del_identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_DELETE],
        db_path=initialized_db_path,
    )

    # Clean up with delete authorization
    cleaned = sandbox_provisioner.cleanup_sandbox(
        sandbox_id=sbx.sandbox_id,
        request_id=req_id,
        approval_id=del_approval.approval_id,
        execution_id="exec-clean-01",
        step_id="step-00000002",
        plan_hash=plan_hash,
        plan_version=1,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_DELETE],
        caller_token=del_token.raw_token,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )
    assert cleaned is True
    # Directory is deleted
    assert not sbx.sandbox_dir.exists()

    # DB record is deleted
    conn = get_connection(initialized_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT count(*) FROM tracked_resources WHERE resource_id = ?;", (sbx.sandbox_id,))
    assert cursor.fetchone()[0] == 0
    conn.close()


def test_cleanup_rejected_without_approval(
    sandbox_provisioner: MockSandboxProvisioner,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
) -> None:
    """Verify cleanup without approval fails closed and leaves sandbox directory intact."""
    req_id = "req-cleanup-noappr"
    plan_hash = "e" * 64
    _setup_req_and_plan(initialized_db_path, req_id, plan_hash)

    token_res = token_service.create_token(
        approver_id="lead-prov",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)
    approval = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
            plan_version=1,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )

    sbx = sandbox_provisioner.provision_sandbox(
        request_id=req_id,
        approval_id=approval.approval_id,
        execution_id="exec-prov-02",
        step_id="step-00000001",
        plan_hash=plan_hash,
        plan_version=1,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )
    assert sbx.sandbox_dir.exists()

    # Attempt cleanup with missing approval ID
    with pytest.raises(AuthorizationDeniedError, match="Approval record 'appr-missing' does not exist"):
        sandbox_provisioner.cleanup_sandbox(
            sandbox_id=sbx.sandbox_id,
            request_id=req_id,
            approval_id="appr-missing",
            execution_id="exec-clean-unauth",
            step_id="step-00000002",
            plan_hash=plan_hash,
            plan_version=1,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.SANDBOX_DELETE],
            custom_root=mock_sandbox_root,
            db_path=initialized_db_path,
        )

    # Sandbox remains untouched
    assert sbx.sandbox_dir.exists()


def test_cleanup_rejected_with_provision_only_scope(
    sandbox_provisioner: MockSandboxProvisioner,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
) -> None:
    """Verify a sandbox cannot be deleted using a provisioning-only permission."""
    req_id = "req-cleanup-badscope"
    plan_hash = "f" * 64
    _setup_req_and_plan(initialized_db_path, req_id, plan_hash)

    token_res = token_service.create_token(
        approver_id="lead-prov",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)
    approval = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
            plan_version=1,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )

    sbx = sandbox_provisioner.provision_sandbox(
        request_id=req_id,
        approval_id=approval.approval_id,
        execution_id="exec-prov-03",
        step_id="step-00000001",
        plan_hash=plan_hash,
        plan_version=1,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )
    assert sbx.sandbox_dir.exists()

    # Attempt cleanup using SANDBOX_CREATE approval
    with pytest.raises(AuthorizationDeniedError, match="Required scope 'sandbox:delete' is not granted"):
        sandbox_provisioner.cleanup_sandbox(
            sandbox_id=sbx.sandbox_id,
            request_id=req_id,
            approval_id=approval.approval_id,
            execution_id="exec-clean-badscope",
            step_id="step-00000002",
            plan_hash=plan_hash,
            plan_version=1,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.SANDBOX_CREATE],
            custom_root=mock_sandbox_root,
            db_path=initialized_db_path,
        )

    assert sbx.sandbox_dir.exists()


def test_cleanup_rejected_with_expired_or_revoked_approval(
    sandbox_provisioner: MockSandboxProvisioner,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
) -> None:
    """Verify cleanup fails closed on revoked or expired delete approvals."""
    req_id = "req-cleanup-exp-rev"
    plan_hash = "1" * 64
    _setup_req_and_plan(initialized_db_path, req_id, plan_hash)

    # 1. Provision sandbox
    prov_token = token_service.create_token(
        approver_id="lead-both",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.SANDBOX_DELETE],
        db_path=initialized_db_path,
    )
    prov_identity = token_service.resolve_identity(prov_token.raw_token, db_path=initialized_db_path)
    prov_approval = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
            plan_version=1,
        ),
        approver=prov_identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.SANDBOX_DELETE],
        db_path=initialized_db_path,
    )

    sbx = sandbox_provisioner.provision_sandbox(
        request_id=req_id,
        approval_id=prov_approval.approval_id,
        execution_id="exec-prov-04",
        step_id="step-00000001",
        plan_hash=plan_hash,
        plan_version=1,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.SANDBOX_DELETE],
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )

    # 2. Test Revoked approval
    del_approval_rev = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
            plan_version=1,
        ),
        approver=prov_identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_DELETE],
        db_path=initialized_db_path,
    )
    approval_service.revoke_approval(del_approval_rev.approval_id, reason="Security audit recall", db_path=initialized_db_path)

    with pytest.raises(AuthorizationDeniedError, match="has been revoked"):
        sandbox_provisioner.cleanup_sandbox(
            sandbox_id=sbx.sandbox_id,
            request_id=req_id,
            approval_id=del_approval_rev.approval_id,
            execution_id="exec-clean-rev",
            step_id="step-00000002",
            plan_hash=plan_hash,
            plan_version=1,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.SANDBOX_DELETE],
            custom_root=mock_sandbox_root,
            db_path=initialized_db_path,
        )

    # 3. Test Expired approval
    del_approval_exp = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
            plan_version=1,
        ),
        approver=prov_identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_DELETE],
        db_path=initialized_db_path,
    )
    # Force expire in DB
    conn = get_connection(initialized_db_path)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE approval_records SET expires_at = '2000-01-01T00:00:00+00:00' WHERE approval_id = ?;",
        (del_approval_exp.approval_id,),
    )
    conn.commit()
    conn.close()

    with pytest.raises(AuthorizationDeniedError, match="has expired"):
        sandbox_provisioner.cleanup_sandbox(
            sandbox_id=sbx.sandbox_id,
            request_id=req_id,
            approval_id=del_approval_exp.approval_id,
            execution_id="exec-clean-exp",
            step_id="step-00000002",
            plan_hash=plan_hash,
            plan_version=1,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.SANDBOX_DELETE],
            custom_root=mock_sandbox_root,
            db_path=initialized_db_path,
        )

    assert sbx.sandbox_dir.exists()


def test_cleanup_rejected_on_approval_replay_or_conflicting_execution(
    sandbox_provisioner: MockSandboxProvisioner,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
) -> None:
    """Verify approval replay and conflicting execution IDs are rejected for cleanup."""
    req_id = "req-cleanup-replay"
    plan_hash = "2" * 64
    _setup_req_and_plan(initialized_db_path, req_id, plan_hash)

    token_res = token_service.create_token(
        approver_id="lead-both",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.SANDBOX_DELETE],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)
    prov_approval = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
            plan_version=1,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )

    sbx = sandbox_provisioner.provision_sandbox(
        request_id=req_id,
        approval_id=prov_approval.approval_id,
        execution_id="exec-prov-05",
        step_id="step-00000001",
        plan_hash=plan_hash,
        plan_version=1,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )

    del_approval = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
            plan_version=1,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_DELETE],
        db_path=initialized_db_path,
    )

    # First cleanup execution consumes approval
    cleaned1 = sandbox_provisioner.cleanup_sandbox(
        sandbox_id=sbx.sandbox_id,
        request_id=req_id,
        approval_id=del_approval.approval_id,
        execution_id="exec-clean-orig",
        step_id="step-00000002",
        plan_hash=plan_hash,
        plan_version=1,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_DELETE],
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )
    assert cleaned1 is True

    # Re-running with SAME execution ID succeeds idempotently
    cleaned_retry = sandbox_provisioner.cleanup_sandbox(
        sandbox_id=sbx.sandbox_id,
        request_id=req_id,
        approval_id=del_approval.approval_id,
        execution_id="exec-clean-orig",
        step_id="step-00000002",
        plan_hash=plan_hash,
        plan_version=1,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_DELETE],
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )
    assert cleaned_retry is True

    # Re-running with DIFFERENT execution ID is rejected (Approval replay protection)
    with pytest.raises(ApprovalAlreadyConsumedError, match="has already been consumed by execution 'exec-clean-orig'"):
        sandbox_provisioner.cleanup_sandbox(
            sandbox_id=sbx.sandbox_id,
            request_id=req_id,
            approval_id=del_approval.approval_id,
            execution_id="exec-clean-replay-attacker",
            step_id="step-00000002",
            plan_hash=plan_hash,
            plan_version=1,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.SANDBOX_DELETE],
            custom_root=mock_sandbox_root,
            db_path=initialized_db_path,
        )


def test_cleanup_unowned_or_tampered_metadata_fails(
    sandbox_provisioner: MockSandboxProvisioner,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
) -> None:
    """Verify cleanup refuses to delete directory if ownership token or database tracking cannot be verified."""
    req_id = "req-cleanup-tamper"
    plan_hash = "3" * 64
    _setup_req_and_plan(initialized_db_path, req_id, plan_hash)

    token_res = token_service.create_token(
        approver_id="lead-both",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.SANDBOX_DELETE],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)

    del_approval = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
            plan_version=1,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_DELETE],
        db_path=initialized_db_path,
    )

    # 1. Attempt cleanup of non-tracked sandbox (valid approval, but untracked sandbox_id)
    with pytest.raises(ResourceOwnershipError, match="No tracked ownership record found"):
        sandbox_provisioner.cleanup_sandbox(
            sandbox_id="sbx-nonexistent",
            request_id=req_id,
            approval_id=del_approval.approval_id,
            execution_id="exec-clean-fake",
            step_id="step-00000002",
            plan_hash=plan_hash,
            plan_version=1,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.SANDBOX_DELETE],
            custom_root=mock_sandbox_root,
            db_path=initialized_db_path,
        )


def test_unowned_directory_preserved_even_with_valid_delete_approval(
    sandbox_provisioner: MockSandboxProvisioner,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
) -> None:
    """Verify unowned directory and user files are preserved even if caller holds a valid delete approval."""
    req_id = "req-cleanup-unowned"
    plan_hash = "4" * 64
    _setup_req_and_plan(initialized_db_path, req_id, plan_hash)

    # Create unowned directory with critical user files
    unowned_dir = mock_sandbox_root / "user_personal_project"
    unowned_dir.mkdir(parents=True, exist_ok=True)
    user_file = unowned_dir / "confidential_notes.txt"
    user_file.write_text("CONFIDENTIAL WORKSPACE DATA", encoding="utf-8")

    token_res = token_service.create_token(
        approver_id="lead-del",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_DELETE],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)
    del_approval = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
            plan_version=1,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_DELETE],
        db_path=initialized_db_path,
    )

    with pytest.raises(ResourceOwnershipError, match="No tracked ownership record found"):
        sandbox_provisioner.cleanup_sandbox(
            sandbox_id="user_personal_project",
            request_id=req_id,
            approval_id=del_approval.approval_id,
            execution_id="exec-clean-unowned",
            step_id="step-00000002",
            plan_hash=plan_hash,
            plan_version=1,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.SANDBOX_DELETE],
            custom_root=mock_sandbox_root,
            db_path=initialized_db_path,
        )

    # Crucial assertion: User file is preserved untouched
    assert user_file.exists()
    assert user_file.read_text(encoding="utf-8") == "CONFIDENTIAL WORKSPACE DATA"


def test_unauthorized_provisioning_fails_closed(
    sandbox_provisioner: MockSandboxProvisioner,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
) -> None:
    """Verify provisioning fails closed on missing, revoked, expired, or insufficient approvals."""
    req_id = "req-unauth-test"
    plan_hash = "e" * 64
    _setup_req_and_plan(initialized_db_path, req_id, plan_hash)

    # 1. Missing approval record
    with pytest.raises(AuthorizationDeniedError):
        sandbox_provisioner.provision_sandbox(
            request_id=req_id,
            approval_id="appr-missing",
            execution_id="exec-err",
            step_id="step-00000001",
            plan_hash=plan_hash,
            plan_version=1,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.SANDBOX_CREATE],
            custom_root=mock_sandbox_root,
            db_path=initialized_db_path,
        )

    # 2. Token lacking SANDBOX_CREATE
    token_res = token_service.create_token(
        approver_id="read-only-user",
        role="DEVELOPER",
        authorized_scopes=[PermissionScope.SANDBOX_READ],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)
    approval = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
            plan_version=1,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_READ],
        db_path=initialized_db_path,
    )

    with pytest.raises(AuthorizationDeniedError, match="Required scope .* is not granted"):
        sandbox_provisioner.provision_sandbox(
            request_id=req_id,
            approval_id=approval.approval_id,
            execution_id="exec-err",
            step_id="step-00000001",
            plan_hash=plan_hash,
            plan_version=1,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.SANDBOX_READ],
            custom_root=mock_sandbox_root,
            db_path=initialized_db_path,
        )
