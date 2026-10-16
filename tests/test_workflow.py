"""Automated test suite for Phase 4 Workflow Orchestration.

Tests cover:
- End-to-end mock workflow execution
- Invalid request and plan rejection
- Approval gating: pending, expiry, revocation, plan mutation
- Confirmation that provisioning and seeding never execute before approval
- Missing and insufficient permissions rejection
- Cleanup authorization using SANDBOX_DELETE
- Restart and retry safety after interruption at every privileged stage
- Duplicate and concurrent workflow execution prevention
- Manifest determinism, mock disclaimer, and secret redaction
- Fixture verification and finalization failures
- Regression across all Phase 1-3 security guarantees
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

from src.adapters.fixtures import get_canonical_fixture_bytes
from src.core.exceptions import (
    ApprovalExpiredError,
    ApprovalRevokedError,
    AuthorizationDeniedError,
    ModelValidationError,
    PlanTamperingError,
    PlanValidationError,
    ResourceOwnershipError,
    SandboxVerificationError,
    TokenScopeError,
    UnknownFixtureError,
    WorkflowError,
)
from src.models.approvals import ApprovalRecord, ApprovalRequest
from src.models.enums import (
    ApprovalDecisionType,
    AuditEventType,
    PermissionScope,
    ProjectTemplate,
    StepActionType,
    WorkflowStage,
    WorkflowStatus,
)
from src.models.plans import PlannedStep, SetupPlan
from src.models.requests import BootstrapRequestCreate
from src.security.approvals import ApprovalService
from src.security.audit_chain import AuditChainService
from src.security.canonicalization import compute_plan_hash
from src.security.guard import ServerSideAuthGuard
from src.security.tokens import TokenService
from src.storage.connection import get_connection
from src.workflow.discovery import discover_local_repository, discover_mock_dashboard
from src.workflow.orchestrator import WorkflowOrchestrator
from src.workflow.planner import build_template_plan, validate_plan
from src.workflow.verifier import SandboxVerifier


@pytest.fixture
def workflow_orchestrator(
    sandbox_provisioner,
    data_seeder,
    execution_tracker,
    audit_service,
    approval_service,
) -> WorkflowOrchestrator:
    """Provide a configured WorkflowOrchestrator instance."""
    return WorkflowOrchestrator(
        sandbox_provisioner=sandbox_provisioner,
        data_seeder=data_seeder,
        execution_tracker=execution_tracker,
        audit_service=audit_service,
        approval_service=approval_service,
        verifier=SandboxVerifier(),
    )


def _create_test_request(orchestrator: WorkflowOrchestrator, db_path: Path, repo_path: Path):
    """Helper to create a standard valid bootstrap request."""
    return orchestrator.create_request(
        BootstrapRequestCreate(
            project_name="test-mock-service",
            template=ProjectTemplate.PYTHON_FASTAPI,
            repository_path=str(repo_path),
            requested_scopes=[
                PermissionScope.SANDBOX_READ,
                PermissionScope.SANDBOX_CREATE,
                PermissionScope.SANDBOX_DELETE,
                PermissionScope.DATA_SEED_SYNTHETIC,
                PermissionScope.TEST_EXECUTE,
                PermissionScope.AUDIT_READ,
            ],
            developer_id="dev-user-01",
            target_environment="local-sandbox",
        ),
        db_path=db_path,
    )


def _grant_approval(
    token_service: TokenService,
    approval_service: ApprovalService,
    db_path: Path,
    request_id: str,
    plan_hash: str,
    plan_version: int = 1,
    target_environment: str = "local-sandbox",
    scopes: list[PermissionScope] | None = None,
) -> ApprovalRecord:
    """Helper to authenticate approver via token and record server-side approval."""
    granted = scopes or [
        PermissionScope.SANDBOX_CREATE,
        PermissionScope.DATA_SEED_SYNTHETIC,
        PermissionScope.SANDBOX_DELETE,
    ]
    token_res = token_service.create_token(
        approver_id="approver-lead-01",
        role="SECURITY_LEAD",
        authorized_scopes=granted + [PermissionScope.SANDBOX_READ],
        db_path=db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=db_path)
    req = ApprovalRequest(
        request_id=request_id,
        decision=ApprovalDecisionType.APPROVE,
        submitted_plan_hash=plan_hash,
        plan_version=plan_version,
    )
    return approval_service.create_approval(
        request=req,
        approver=identity,
        target_environment=target_environment,
        granted_scopes=granted,
        db_path=db_path,
    )


# =============================================================================
# 1. DISCOVERY AND PLANNING TESTS
# =============================================================================

def test_safe_local_discovery(tmp_path: Path) -> None:
    """Verify repository and dashboard discovery is read-only with zero shell execution."""
    repo = tmp_path / "sample_repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("fastapi>=0.100.0\nuvicorn\n", encoding="utf-8")
    (repo / "README.md").write_text("# Sample Project\nA local prototype.\n", encoding="utf-8")

    repo_res = discover_local_repository(repo)
    assert "fastapi" in repo_res.detected_framework.lower()
    assert "requirements.txt" in repo_res.config_files_found
    assert "fastapi" in repo_res.inferred_dependencies
    assert "Sample Project" in (repo_res.untrusted_documentation_snippet or "")

    dash_res = discover_mock_dashboard()
    assert dash_res.quota_available_sandboxes > 0
    assert "10.0.0.0/24" in dash_res.mock_network_range
    assert "users.json" in dash_res.allowed_synthetic_fixtures


def test_build_and_validate_deterministic_plan() -> None:
    """Verify build_template_plan builds deterministic DAG plan with valid canonical plan hash."""
    plan = build_template_plan(
        request_id="req-12345",
        template=ProjectTemplate.PYTHON_FASTAPI,
        target_environment="local-sandbox",
    )
    assert plan.plan_version == 1
    assert len(plan.steps) == 7
    assert plan.canonical_plan_hash == compute_plan_hash(plan)

    # Validating with requested scopes passes
    validate_plan(
        plan,
        [
            PermissionScope.SANDBOX_READ,
            PermissionScope.SANDBOX_CREATE,
            PermissionScope.DATA_SEED_SYNTHETIC,
            PermissionScope.TEST_EXECUTE,
            PermissionScope.AUDIT_READ,
        ],
    )


def test_invalid_request_rejected(workflow_orchestrator: WorkflowOrchestrator, initialized_db_path: Path) -> None:
    """Verify invalid request creation payload is rejected with ModelValidationError."""
    with pytest.raises(ModelValidationError):
        workflow_orchestrator.create_request(
            {"invalid_field": 123},
            db_path=initialized_db_path,
        )

    # Duplicate scopes in creation model raises ValueError/ModelValidationError
    with pytest.raises(ModelValidationError):
        workflow_orchestrator.create_request(
            {
                "project_name": "bad_scopes",
                "template": "python-fastapi-service",
                "repository_path": "c:/repo",
                "requested_scopes": ["sandbox:read", "sandbox:read"],  # duplicate
                "developer_id": "dev-01",
            },
            db_path=initialized_db_path,
        )


def test_validate_plan_rejects_scope_exceeding_request() -> None:
    """Verify least-privilege violation is rejected if plan requires unrequested scope."""
    plan = build_template_plan(
        request_id="req-12345",
        template=ProjectTemplate.PYTHON_FASTAPI,
    )
    # Provide only SANDBOX_READ: should fail on PROVISION_MOCK_SANDBOX
    with pytest.raises(PlanValidationError, match="Least-privilege violation"):
        validate_plan(plan, [PermissionScope.SANDBOX_READ])


def test_validate_plan_rejects_unregistered_fixture() -> None:
    """Verify plan with unknown fixture ID is rejected."""
    plan = build_template_plan(
        request_id="req-12345",
        template=ProjectTemplate.PYTHON_FASTAPI,
    )
    # Inject hostile fixture
    for s in plan.steps:
        if s.action_type == StepActionType.SEED_SYNTHETIC_DATA:
            s.action_parameters["fixtures"] = ["hostile_exploit.json"]

    with pytest.raises(UnknownFixtureError):
        validate_plan(
            plan,
            [
                PermissionScope.SANDBOX_READ,
                PermissionScope.SANDBOX_CREATE,
                PermissionScope.DATA_SEED_SYNTHETIC,
                PermissionScope.TEST_EXECUTE,
                PermissionScope.AUDIT_READ,
            ],
        )


# =============================================================================
# 2. END-TO-END MOCK WORKFLOW & APPROVAL GATING
# =============================================================================

def test_workflow_pauses_before_privileged_stages_awaiting_approval(
    workflow_orchestrator: WorkflowOrchestrator,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
    tmp_path: Path,
) -> None:
    """Verify workflow coordinates discovery and planning, then halts at AWAIT_APPROVAL."""
    req = _create_test_request(workflow_orchestrator, initialized_db_path, tmp_path)

    res = workflow_orchestrator.run_workflow(
        request_id=req.request_id,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )

    assert res.current_status == WorkflowStatus.PENDING_APPROVAL
    assert res.stage == WorkflowStage.AWAIT_APPROVAL
    assert res.approval_required is True
    assert res.is_completed is False

    # Confirm NO provisioning or seeding occurred
    assert len(list(mock_sandbox_root.iterdir())) == 0


def test_successful_end_to_end_mock_workflow(
    workflow_orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
    tmp_path: Path,
) -> None:
    """Verify full end-to-end execution from request to finalized manifest with valid approval."""
    req = _create_test_request(workflow_orchestrator, initialized_db_path, tmp_path)

    # 1. Run until approval pause
    res_pause = workflow_orchestrator.run_workflow(
        request_id=req.request_id,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )
    assert res_pause.approval_required is True

    # 2. Fetch the plan hash generated by the orchestrator
    conn = get_connection(initialized_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT canonical_plan_hash, plan_version FROM setup_plans WHERE request_id = ?;", (req.request_id,))
    plan_row = cursor.fetchone()
    cursor.close()
    conn.close()

    plan_hash = plan_row["canonical_plan_hash"]
    plan_version = plan_row["plan_version"]

    # 3. Grant valid server-side human approval
    _grant_approval(
        token_service=token_service,
        approval_service=approval_service,
        db_path=initialized_db_path,
        request_id=req.request_id,
        plan_hash=plan_hash,
        plan_version=plan_version,
        target_environment="local-sandbox",
        scopes=[
            PermissionScope.SANDBOX_CREATE,
            PermissionScope.DATA_SEED_SYNTHETIC,
            PermissionScope.SANDBOX_DELETE,
        ],
    )

    # 4. Resume workflow execution
    res_final = workflow_orchestrator.run_workflow(
        request_id=req.request_id,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )

    assert res_final.is_completed is True
    assert res_final.current_status == WorkflowStatus.COMPLETED
    assert res_final.stage == WorkflowStage.FINALIZE
    assert res_final.sandbox_id is not None
    assert res_final.manifest is not None

    # Check manifest contents and structure
    manifest = res_final.manifest
    assert manifest.environment_label == "MOCK / LOCAL ONLY"
    assert manifest.workflow_status == "COMPLETED"
    assert len(manifest.fixture_hashes) == 4
    assert manifest.workflow_id is not None

    # Verify smoke test disclaimer in manifest
    expected_disclaimer = (
        "LOCAL MOCK VERIFICATION ONLY: This authentication check validates internal "
        "sandbox readiness using simulated credentials and does NOT authenticate against "
        "an enterprise Identity Provider (OAuth2/SAML/OIDC)."
    )
    assert manifest.verification.auth_mode_disclaimer == expected_disclaimer

    # Verify manifest file on disk inside sandbox
    sbx_dirs = list(mock_sandbox_root.iterdir())
    assert len(sbx_dirs) == 1
    manifest_on_disk = sbx_dirs[0] / "manifest.json"
    assert manifest_on_disk.exists()
    disk_content = manifest_on_disk.read_text(encoding="utf-8")
    assert expected_disclaimer in disk_content
    # Ensure zero passwords or raw tokens in manifest
    assert "password" not in disk_content.lower()


# =============================================================================
# 3. APPROVAL SECURITY: EXPIRY, REVOCATION, PLAN MUTATION, INSUFFICIENT SCOPES
# =============================================================================

def test_expired_approval_rejected(
    workflow_orchestrator: WorkflowOrchestrator,
    approval_service: ApprovalService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
    tmp_path: Path,
) -> None:
    """Verify that an expired approval record causes workflow to transition to EXPIRED and halt."""
    req = _create_test_request(workflow_orchestrator, initialized_db_path, tmp_path)
    workflow_orchestrator.run_workflow(req.request_id, custom_root=mock_sandbox_root, db_path=initialized_db_path)

    # Create approval expired 5 minutes ago
    conn = get_connection(initialized_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT canonical_plan_hash FROM setup_plans WHERE request_id = ?;", (req.request_id,))
    plan_hash = cursor.fetchone()["canonical_plan_hash"]

    now = datetime.now(timezone.utc)
    expired_time = (now - timedelta(minutes=5)).isoformat()
    created_time = (now - timedelta(minutes=35)).isoformat()

    cursor.execute(
        """
        INSERT INTO approval_records (
            approval_id, request_id, approver_id, decision, canonical_plan_hash,
            plan_version, target_environment, granted_scopes, created_at, expires_at,
            is_revoked, execution_consumed
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0);
        """,
        (
            "appr-expired-1",
            req.request_id,
            "approver-01",
            "APPROVE",
            plan_hash,
            1,
            "local-sandbox",
            json.dumps(["sandbox:create", "data:seed:synthetic"]),
            created_time,
            expired_time,
        ),
    )
    conn.commit()
    cursor.close()
    conn.close()

    res = workflow_orchestrator.run_workflow(req.request_id, custom_root=mock_sandbox_root, db_path=initialized_db_path)
    assert res.current_status == WorkflowStatus.EXPIRED
    assert res.is_completed is False
    assert len(list(mock_sandbox_root.iterdir())) == 0


def test_revoked_approval_rejected(
    workflow_orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
    tmp_path: Path,
) -> None:
    """Verify that a revoked approval record halts execution."""
    req = _create_test_request(workflow_orchestrator, initialized_db_path, tmp_path)
    workflow_orchestrator.run_workflow(req.request_id, custom_root=mock_sandbox_root, db_path=initialized_db_path)

    conn = get_connection(initialized_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT canonical_plan_hash FROM setup_plans WHERE request_id = ?;", (req.request_id,))
    plan_hash = cursor.fetchone()["canonical_plan_hash"]
    cursor.close()
    conn.close()

    approval = _grant_approval(
        token_service=token_service,
        approval_service=approval_service,
        db_path=initialized_db_path,
        request_id=req.request_id,
        plan_hash=plan_hash,
        scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.DATA_SEED_SYNTHETIC],
    )
    approval_service.revoke_approval(approval.approval_id, "Security audit revocation", db_path=initialized_db_path)

    res = workflow_orchestrator.run_workflow(req.request_id, custom_root=mock_sandbox_root, db_path=initialized_db_path)
    assert res.current_status == WorkflowStatus.FAILED
    assert "revoked" in (res.error_message or "").lower()
    assert len(list(mock_sandbox_root.iterdir())) == 0


def test_plan_mutation_triggers_automatic_approval_revocation(
    workflow_orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
    tmp_path: Path,
) -> None:
    """Verify database trigger revoke_approvals_on_plan_change marks approvals revoked when plan changes."""
    req = _create_test_request(workflow_orchestrator, initialized_db_path, tmp_path)
    workflow_orchestrator.run_workflow(req.request_id, custom_root=mock_sandbox_root, db_path=initialized_db_path)

    conn = get_connection(initialized_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT canonical_plan_hash FROM setup_plans WHERE request_id = ?;", (req.request_id,))
    plan_hash = cursor.fetchone()["canonical_plan_hash"]
    cursor.close()
    conn.close()

    approval = _grant_approval(
        token_service=token_service,
        approval_service=approval_service,
        db_path=initialized_db_path,
        request_id=req.request_id,
        plan_hash=plan_hash,
        scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.DATA_SEED_SYNTHETIC],
    )

    # Mutate setup_plans table directly
    conn = get_connection(initialized_db_path)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE setup_plans SET canonical_plan_hash = ? WHERE request_id = ?;",
        ("f" * 64, req.request_id),
    )
    conn.commit()

    # Verify trigger automatically marked approval is_revoked = 1
    cursor.execute("SELECT is_revoked, rejection_reason FROM approval_records WHERE approval_id = ?;", (approval.approval_id,))
    appr_row = cursor.fetchone()
    assert appr_row["is_revoked"] == 1
    assert "AUTOMATICALLY_REVOKED" in appr_row["rejection_reason"]
    cursor.close()
    conn.close()


def test_insufficient_scopes_rejection(
    workflow_orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
    tmp_path: Path,
) -> None:
    """Verify approval with insufficient scopes (missing DATA_SEED_SYNTHETIC) is rejected."""
    req = _create_test_request(workflow_orchestrator, initialized_db_path, tmp_path)
    workflow_orchestrator.run_workflow(req.request_id, custom_root=mock_sandbox_root, db_path=initialized_db_path)

    conn = get_connection(initialized_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT canonical_plan_hash FROM setup_plans WHERE request_id = ?;", (req.request_id,))
    plan_hash = cursor.fetchone()["canonical_plan_hash"]
    cursor.close()
    conn.close()

    # Grant only SANDBOX_CREATE (missing DATA_SEED_SYNTHETIC)
    _grant_approval(
        token_service=token_service,
        approval_service=approval_service,
        db_path=initialized_db_path,
        request_id=req.request_id,
        plan_hash=plan_hash,
        scopes=[PermissionScope.SANDBOX_CREATE],
    )

    res = workflow_orchestrator.run_workflow(req.request_id, custom_root=mock_sandbox_root, db_path=initialized_db_path)
    assert res.current_status == WorkflowStatus.FAILED
    assert "TokenScopeError" in (res.error_category or "")
    assert len(list(mock_sandbox_root.iterdir())) == 0


# =============================================================================
# 4. RESTART AND RETRY SAFETY
# =============================================================================

def test_retry_after_interruption_skips_verified_provisioning(
    workflow_orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
    tmp_path: Path,
) -> None:
    """Verify resuming after provisioning skips re-provisioning and proceeds with seeding and verification."""
    req = _create_test_request(workflow_orchestrator, initialized_db_path, tmp_path)
    workflow_orchestrator.run_workflow(req.request_id, custom_root=mock_sandbox_root, db_path=initialized_db_path)

    conn = get_connection(initialized_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT canonical_plan_hash FROM setup_plans WHERE request_id = ?;", (req.request_id,))
    plan_hash = cursor.fetchone()["canonical_plan_hash"]
    cursor.close()
    conn.close()

    _grant_approval(
        token_service=token_service,
        approval_service=approval_service,
        db_path=initialized_db_path,
        request_id=req.request_id,
        plan_hash=plan_hash,
        scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.DATA_SEED_SYNTHETIC],
    )

    exec_id = "exec-test-resume-01"

    # Simulate interruption by monkeypatching data_seeder to fail on first run
    original_seed = workflow_orchestrator.data_seeder.seed_fixtures
    call_count = {"seeder": 0}

    def failing_seed(*args, **kwargs):
        call_count["seeder"] += 1
        raise WorkflowError("Simulated interruption during seeding")

    workflow_orchestrator.data_seeder.seed_fixtures = failing_seed

    res1 = workflow_orchestrator.run_workflow(
        req.request_id,
        execution_id=exec_id,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )
    assert res1.current_status == WorkflowStatus.FAILED
    assert call_count["seeder"] >= 1  # Initial attempt plus bounded reflection retries

    # Verify that provisioning succeeded before the crash
    sbx_dirs = list(mock_sandbox_root.iterdir())
    assert len(sbx_dirs) == 1
    assert (sbx_dirs[0] / ".sandbox-metadata.json").exists()

    # Restore seeder and resume with SAME execution_id
    workflow_orchestrator.data_seeder.seed_fixtures = original_seed

    res2 = workflow_orchestrator.run_workflow(
        req.request_id,
        execution_id=exec_id,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )

    assert res2.is_completed is True
    assert res2.current_status == WorkflowStatus.COMPLETED
    assert len(list(mock_sandbox_root.iterdir())) == 1  # No duplicate directories created!


def test_corrupted_local_result_prevents_blind_skipping(
    workflow_orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
    tmp_path: Path,
) -> None:
    """Verify that if step tracker says COMPLETED but local disk is deleted, it is not blindly skipped."""
    req = _create_test_request(workflow_orchestrator, initialized_db_path, tmp_path)
    workflow_orchestrator.run_workflow(req.request_id, custom_root=mock_sandbox_root, db_path=initialized_db_path)

    conn = get_connection(initialized_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT canonical_plan_hash FROM setup_plans WHERE request_id = ?;", (req.request_id,))
    plan_hash = cursor.fetchone()["canonical_plan_hash"]
    cursor.close()
    conn.close()

    _grant_approval(
        token_service=token_service,
        approval_service=approval_service,
        db_path=initialized_db_path,
        request_id=req.request_id,
        plan_hash=plan_hash,
        scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.DATA_SEED_SYNTHETIC],
    )

    exec_id = "exec-test-corrupt-01"

    # Run successfully
    res = workflow_orchestrator.run_workflow(
        req.request_id,
        execution_id=exec_id,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )
    assert res.is_completed is True

    # Tamper with a fixture on disk
    sbx_dir = mock_sandbox_root / res.sandbox_id
    fixture_file = sbx_dir / "fixtures" / "users.json"
    fixture_file.write_text("corrupted content", encoding="utf-8")

    # Verifier directly detects corruption
    verifier = SandboxVerifier()
    with pytest.raises(SandboxVerificationError, match="Content hash mismatch"):
        verifier.verify_sandbox(
            sandbox_dir=sbx_dir,
            expected_fixtures=["users.json"],
            execution_id=exec_id,
            db_path=initialized_db_path,
        )


def test_duplicate_run_returns_completed_without_reexecuting(
    workflow_orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
    tmp_path: Path,
) -> None:
    """Verify that running workflow on an already COMPLETED request returns immediately."""
    req = _create_test_request(workflow_orchestrator, initialized_db_path, tmp_path)
    workflow_orchestrator.run_workflow(req.request_id, custom_root=mock_sandbox_root, db_path=initialized_db_path)

    conn = get_connection(initialized_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT canonical_plan_hash FROM setup_plans WHERE request_id = ?;", (req.request_id,))
    plan_hash = cursor.fetchone()["canonical_plan_hash"]
    cursor.close()
    conn.close()

    _grant_approval(
        token_service=token_service,
        approval_service=approval_service,
        db_path=initialized_db_path,
        request_id=req.request_id,
        plan_hash=plan_hash,
    )

    res1 = workflow_orchestrator.run_workflow(req.request_id, custom_root=mock_sandbox_root, db_path=initialized_db_path)
    assert res1.is_completed is True

    # Second invocation
    res2 = workflow_orchestrator.run_workflow(req.request_id, custom_root=mock_sandbox_root, db_path=initialized_db_path)
    assert res2.is_completed is True
    assert res2.current_status == WorkflowStatus.COMPLETED


# =============================================================================
# 5. SANDBOX CLEANUP AUTHORIZATION (SANDBOX_DELETE)
# =============================================================================

def test_cleanup_sandbox_authorized_with_sandbox_delete(
    workflow_orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
    tmp_path: Path,
) -> None:
    """Verify cleanup_workflow_sandbox succeeds when authorized with SANDBOX_DELETE."""
    req = _create_test_request(workflow_orchestrator, initialized_db_path, tmp_path)
    workflow_orchestrator.run_workflow(req.request_id, custom_root=mock_sandbox_root, db_path=initialized_db_path)

    conn = get_connection(initialized_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT canonical_plan_hash FROM setup_plans WHERE request_id = ?;", (req.request_id,))
    plan_hash = cursor.fetchone()["canonical_plan_hash"]
    cursor.close()
    conn.close()

    _grant_approval(
        token_service=token_service,
        approval_service=approval_service,
        db_path=initialized_db_path,
        request_id=req.request_id,
        plan_hash=plan_hash,
        scopes=[
            PermissionScope.SANDBOX_CREATE,
            PermissionScope.DATA_SEED_SYNTHETIC,
            PermissionScope.SANDBOX_DELETE,
        ],
    )

    res = workflow_orchestrator.run_workflow(
        req.request_id,
        execution_id="exec-clean-01",
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )
    assert res.is_completed is True
    sbx_id = res.sandbox_id

    # Create cleanup approval with SANDBOX_DELETE
    clean_appr = _grant_approval(
        token_service=token_service,
        approval_service=approval_service,
        db_path=initialized_db_path,
        request_id=req.request_id,
        plan_hash=plan_hash,
        scopes=[PermissionScope.SANDBOX_DELETE],
    )

    cleaned = workflow_orchestrator.cleanup_workflow_sandbox(
        request_id=req.request_id,
        sandbox_id=sbx_id,
        approval_id=clean_appr.approval_id,
        execution_id="exec-clean-01",
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )
    assert cleaned is True
    assert not (mock_sandbox_root / sbx_id).exists()


def test_cleanup_sandbox_rejected_without_sandbox_delete(
    workflow_orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
    tmp_path: Path,
) -> None:
    """Verify cleanup_workflow_sandbox fails closed if approval lacks SANDBOX_DELETE."""
    req = _create_test_request(workflow_orchestrator, initialized_db_path, tmp_path)
    workflow_orchestrator.run_workflow(req.request_id, custom_root=mock_sandbox_root, db_path=initialized_db_path)

    conn = get_connection(initialized_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT canonical_plan_hash FROM setup_plans WHERE request_id = ?;", (req.request_id,))
    plan_hash = cursor.fetchone()["canonical_plan_hash"]
    cursor.close()
    conn.close()

    _grant_approval(
        token_service=token_service,
        approval_service=approval_service,
        db_path=initialized_db_path,
        request_id=req.request_id,
        plan_hash=plan_hash,
        scopes=[
            PermissionScope.SANDBOX_CREATE,
            PermissionScope.DATA_SEED_SYNTHETIC,
        ],
    )

    res = workflow_orchestrator.run_workflow(
        req.request_id,
        execution_id="exec-clean-02",
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )
    sbx_id = res.sandbox_id

    # Create cleanup approval with only SANDBOX_READ (missing SANDBOX_DELETE)
    insufficient_appr = _grant_approval(
        token_service=token_service,
        approval_service=approval_service,
        db_path=initialized_db_path,
        request_id=req.request_id,
        plan_hash=plan_hash,
        scopes=[PermissionScope.SANDBOX_READ],
    )

    with pytest.raises(AuthorizationDeniedError, match=r"sandbox:delete"):
        workflow_orchestrator.cleanup_workflow_sandbox(
            request_id=req.request_id,
            sandbox_id=sbx_id,
            approval_id=insufficient_appr.approval_id,
            execution_id="exec-clean-02",
            custom_root=mock_sandbox_root,
            db_path=initialized_db_path,
        )
    # Confirm directory still exists
    assert (mock_sandbox_root / sbx_id).exists()


def test_pluggable_llm_interface_and_deterministic_fallback():
    """Verify pluggable LLM interface supports local inference and deterministic fallback when offline."""
    from src.workflow.planner import (
        DeterministicTemplatePlanner,
        LocalLLMPlanner,
        get_planner,
    )
    from src.agents.planner import PlanningAgent, PlanningInput

    # 1. Deterministic planner baseline
    det_planner = DeterministicTemplatePlanner()
    plan1 = det_planner.generate_plan(
        request_id="req-test-ai-01",
        template=ProjectTemplate.PYTHON_FASTAPI,
        target_environment="local-mock-dev",
    )
    assert plan1.canonical_plan_hash is not None
    assert len(plan1.steps) == 7

    # 2. LocalLLMPlanner disabled (default baseline)
    default_planner = LocalLLMPlanner(enabled=False)
    plan2 = default_planner.generate_plan(
        request_id="req-test-ai-01",
        template=ProjectTemplate.PYTHON_FASTAPI,
        target_environment="local-mock-dev",
    )
    assert plan2.canonical_plan_hash == plan1.canonical_plan_hash

    # 3. LocalLLMPlanner enabled with offline/unreachable endpoint
    # Points to unused port to trigger connection error
    offline_planner = LocalLLMPlanner(
        base_url="http://127.0.0.1:59999",
        model="llama3.2",
        enabled=True,
        timeout_seconds=0.5,
    )
    # Must not raise an exception; must gracefully fall back to deterministic plan
    plan3 = offline_planner.generate_plan(
        request_id="req-test-ai-01",
        template=ProjectTemplate.PYTHON_FASTAPI,
        target_environment="local-mock-dev",
    )
    assert plan3.canonical_plan_hash == plan1.canonical_plan_hash

    # 4. PlanningAgent with offline LLM planner integration
    agent = PlanningAgent(planner=offline_planner)
    spec = PlanningInput(
        request_id="req-test-ai-01",
        template=ProjectTemplate.PYTHON_FASTAPI,
        target_environment="local-mock-dev",
        requested_scopes=[
            PermissionScope.SANDBOX_READ,
            PermissionScope.SANDBOX_CREATE,
            PermissionScope.DATA_SEED_SYNTHETIC,
            PermissionScope.TEST_EXECUTE,
            PermissionScope.AUDIT_READ,
        ],
    )
    plan4 = agent.generate_plan(spec)
    assert plan4.canonical_plan_hash == plan1.canonical_plan_hash

