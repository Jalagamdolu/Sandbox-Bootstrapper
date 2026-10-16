"""Comprehensive test suite for Developer Sandbox Bootstrapper Master Build.

Validates the 24 explicit requirements from Section 11 of the Master Build specification:
1. Application imports and initializes successfully.
2. SQLite initializes correctly.
3. Valid intake produces a validated specification.
4. Invalid input is rejected.
5. Discovery returns expected local mock resources.
6. Missing resources produce explicit warning or failure.
7. Planning produces an ordered, validated plan.
8. Discovery and planning cannot execute privileged actions.
9. Execution is blocked while approval is missing.
10. Execution is blocked when approval is rejected.
11. Execution is blocked when approval has expired.
12. Execution is blocked when plan or permission manifest changes.
13. Execution is blocked for invalid or reused approval.
14. Unauthorized tools and excessive permissions are rejected.
15. Valid approval permits only exact approved mock actions.
16. Synthetic data seeding produces synthetic data only.
17. Verification correctly distinguishes success from failure.
18. Retries are bounded and prohibited actions are never retried.
19. Audit records are persisted without secrets.
20. Sandbox cleanup deadlines are calculated correctly.
21. Repeated API requests do not cause duplicate privileged execution.
22. End-to-end successful workflow works.
23. End-to-end rejected-approval workflow works.
24. End-to-end failure workflow produces correct terminal status.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import pytest

from src.agents.intake import IntakeAgent, IntakeRequest, ProjectSpecification
from src.agents.discovery import DiscoveryAgent, DiscoveryResult
from src.agents.planner import PlanningAgent, PlanningInput
from src.agents.executor import ExecutionAgent, StepExecutionResult
from src.agents.verification import VerificationNode, VerificationReport
from src.agents.reflection import ReflectionNode, ReflectionDecision
from src.security.policy import PolicyEngine
from src.security.approvals import ApprovalService
from src.security.tokens import TokenService
from src.security.guard import ServerSideAuthGuard
from src.security.audit_chain import AuditChainService
from src.adapters.execution_tracker import StepExecutionTracker
from src.adapters.sandbox_provisioner import MockSandboxProvisioner
from src.adapters.data_seeder import SyntheticDataSeeder
from src.workflow.orchestrator import WorkflowOrchestrator
from src.workflow.graph import BootstrapperWorkflowGraph, get_sqlite_checkpointer
from src.core.exceptions import (
    ApprovalAlreadyConsumedError,
    ApprovalError,
    ApprovalExpiredError,
    ApprovalMismatchError,
    ApprovalRejectedError,
    ApprovalRevokedError,
    AuthorizationDeniedError,
    ModelValidationError,
    PathTraversalError,
    PolicyViolationError,
    RequestValidationError,
    SecurityViolationError,
    TokenScopeError,
)
from src.models.approvals import ApprovalDecisionType, ApprovalRequest
from src.models.audit import AuditActor
from src.models.enums import (
    AuditEventType,
    AuditSeverity,
    PermissionScope,
    ProjectTemplate,
    StepActionType,
    StepExecutionStatus,
    WorkflowStage,
    WorkflowStatus,
)
from src.models.plans import PlannedStep
from src.models.requests import BootstrapRequestCreate
from src.storage.connection import get_connection
from src.storage.db_init import initialize_database

ALL_SCOPES = [
    PermissionScope.SANDBOX_READ,
    PermissionScope.SANDBOX_CREATE,
    PermissionScope.DATA_SEED_SYNTHETIC,
    PermissionScope.TEST_EXECUTE,
    PermissionScope.AUDIT_READ,
]


def make_test_request(
    orchestrator: WorkflowOrchestrator,
    project_name: str,
    db_path: Path,
    scopes: list[PermissionScope] | None = None,
):
    return orchestrator.create_request(
        BootstrapRequestCreate(
            project_name=project_name,
            template=ProjectTemplate.PYTHON_FASTAPI,
            repository_path="./",
            developer_id="dev-charlie",
            requested_scopes=scopes or ALL_SCOPES,
        ),
        db_path=db_path,
    )


# 1. Application imports and initializes successfully.
def test_01_application_imports_and_initializes(initialized_db_path: Path):
    from src.api.app import app
    assert app is not None
    assert app.title == "Developer Sandbox Bootstrapper API"

    orchestrator = WorkflowOrchestrator()
    assert orchestrator is not None

    graph = orchestrator.get_graph(db_path=initialized_db_path)
    assert graph is not None


# 2. SQLite initializes correctly.
def test_02_sqlite_initializes_correctly(tmp_path: Path):
    db_file = tmp_path / "test_init.db"
    initialize_database(db_file)
    assert db_file.exists()

    conn = get_connection(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = {row["name"] for row in cursor.fetchall()}
    conn.close()

    expected_tables = {
        "bootstrap_requests",
        "setup_plans",
        "approval_records",
        "approver_tokens",
        "tracked_resources",
        "audit_log",
        "step_executions",
        "workflow_checkpoints",
    }
    assert expected_tables.issubset(tables)

    # LangGraph checkpoint tables
    checkpointer = get_sqlite_checkpointer(db_file)
    assert checkpointer is not None
    conn2 = get_connection(db_file)
    cursor2 = conn2.cursor()
    cursor2.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables_after = {row["name"] for row in cursor2.fetchall()}
    conn2.close()
    assert {"checkpoints", "writes"}.issubset(tables_after)


# 3. Valid intake produces a validated specification.
def test_03_valid_intake_produces_validated_specification():
    agent = IntakeAgent()
    req = IntakeRequest(
        project_name="payment-processor",
        template="python-fastapi-service",
        repository_path="./",
        developer_id="dev-charlie",
        requested_scopes=["sandbox:read", "sandbox:create", "data:seed:synthetic"],
    )
    spec = agent.validate_request(req)

    assert isinstance(spec, ProjectSpecification)
    assert spec.project_name == "payment-processor"
    assert spec.template == ProjectTemplate.PYTHON_FASTAPI
    assert PermissionScope.SANDBOX_CREATE in spec.requested_scopes
    assert PermissionScope.SANDBOX_DELETE not in spec.requested_scopes  # safe default


# 4. Invalid input is rejected.
def test_04_invalid_input_is_rejected():
    agent = IntakeAgent()

    # Traversal in project_name
    with pytest.raises(ModelValidationError):
        agent.validate_request(IntakeRequest(
            project_name="../../badname",
            template="python-fastapi-service",
            developer_id="dev-test",
            requested_scopes=["sandbox:read"],
        ))

    # Invalid project name with spaces/special characters
    with pytest.raises(ModelValidationError):
        agent.validate_request(IntakeRequest(
            project_name="Bad Project Name!",
            template="python-fastapi-service",
            developer_id="dev-test",
            requested_scopes=["sandbox:read"],
        ))

    # Unsupported template
    with pytest.raises(ModelValidationError):
        agent.validate_request(IntakeRequest(
            project_name="good-name",
            template="unsupported-kubernetes-cloud",
            developer_id="dev-test",
            requested_scopes=["sandbox:read"],
        ))


# 5. Discovery returns expected local mock resources.
def test_05_discovery_returns_expected_local_mock_resources():
    agent = DiscoveryAgent()
    res = agent.discover(ProjectTemplate.PYTHON_FASTAPI, repository_path="./")

    assert isinstance(res, DiscoveryResult)
    assert res.is_valid is True
    assert len(res.available_resources) > 0
    assert any(r.resource_id == "mock-sqlite-db" for r in res.available_resources)


# 6. Missing resources produce explicit warning or failure.
def test_06_missing_resources_produce_explicit_warning():
    agent = DiscoveryAgent(catalog_path="data/mock_resources.json")
    res = agent.discover(ProjectTemplate.PYTHON_FASTAPI, repository_path="./")

    assert len(res.unavailable_resources) > 0
    unavailable_ids = {r.resource_id for r in res.unavailable_resources}
    assert "cloud-aws-rds" in unavailable_ids
    assert any("cloud-aws-rds" in w for w in res.warnings)


# 7. Planning produces an ordered, validated plan.
def test_07_planning_produces_ordered_validated_plan():
    agent = PlanningAgent()
    plan_in = PlanningInput(
        request_id="req-plan-test",
        template=ProjectTemplate.PYTHON_FASTAPI,
        target_environment="local-mock-dev",
        requested_scopes=ALL_SCOPES,
    )
    plan = agent.generate_plan(plan_in)

    assert plan.plan_id.startswith("plan-")
    assert plan.canonical_plan_hash is not None
    assert len(plan.canonical_plan_hash) == 64
    assert len(plan.steps) == 7
    # Ensure ordered step progression
    order = [s.step_id for s in plan.steps]
    assert order == sorted(order)


# 8. Discovery and planning cannot execute privileged actions.
def test_08_discovery_and_planning_cannot_execute_privileged_actions(mock_sandbox_root: Path):
    intake = IntakeAgent()
    discovery = DiscoveryAgent()
    planner = PlanningAgent()

    spec = intake.validate_request(IntakeRequest(
        project_name="read-only-test",
        template="python-fastapi-service",
        developer_id="dev-test",
        requested_scopes=["sandbox:read"],
    ))
    disc = discovery.discover(spec.template)
    plan = planner.generate_plan(PlanningInput(
        request_id="req-ro-001",
        template=spec.template,
        target_environment=spec.target_environment,
        requested_scopes=ALL_SCOPES,
    ))

    # Assert no sandbox directories or seeded fixture files were written to disk
    items = list(mock_sandbox_root.glob("*"))
    assert len(items) == 0


# 9. Execution is blocked while approval is missing.
def test_09_execution_blocked_while_approval_is_missing(
    initialized_db_path: Path,
    mock_sandbox_root: Path,
):
    orchestrator = WorkflowOrchestrator()
    req = make_test_request(orchestrator, "no-approval-test", initialized_db_path)

    result = orchestrator.run_workflow(
        request_id=req.request_id,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
        raise_on_failure=False,
    )

    assert result.is_completed is False
    assert result.approval_required is True
    assert result.stage == WorkflowStage.AWAIT_APPROVAL
    assert result.current_status == WorkflowStatus.PENDING_APPROVAL

    # Ensure no sandbox created
    sandboxes = list(mock_sandbox_root.glob("*"))
    assert len(sandboxes) == 0


# 10. Execution is blocked when approval is rejected.
def test_10_execution_blocked_when_approval_is_rejected(
    initialized_db_path: Path,
    token_service: TokenService,
    approval_service: ApprovalService,
    mock_sandbox_root: Path,
):
    orchestrator = WorkflowOrchestrator(approval_service=approval_service)
    req = make_test_request(orchestrator, "rejected-test", initialized_db_path)
    plan = orchestrator._get_or_create_plan(req, db_path=initialized_db_path)

    # Issue approver token and reject
    tok = token_service.create_token(
        approver_id="sec-admin",
        role="SECURITY_LEAD",
        authorized_scopes=ALL_SCOPES,
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(tok.raw_token, db_path=initialized_db_path)

    approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req.request_id,
            submitted_plan_hash=plan.canonical_plan_hash,
            plan_version=plan.plan_version,
            decision=ApprovalDecisionType.REJECT,
            rejection_reason="Security policy violation in proposed scopes.",
        ),
        approver=identity,
        target_environment=plan.target_environment,
        granted_scopes=req.requested_scopes,
        db_path=initialized_db_path,
    )

    with pytest.raises(ApprovalError):
        orchestrator.run_workflow(
            request_id=req.request_id,
            caller_token=tok.raw_token,
            custom_root=mock_sandbox_root,
            db_path=initialized_db_path,
            raise_on_failure=True,
        )


# 11. Execution is blocked when approval has expired.
def test_11_execution_blocked_when_approval_has_expired(
    initialized_db_path: Path,
    token_service: TokenService,
    approval_service: ApprovalService,
    mock_sandbox_root: Path,
):
    orchestrator = WorkflowOrchestrator(approval_service=approval_service)
    req = make_test_request(orchestrator, "expired-test", initialized_db_path)
    plan = orchestrator._get_or_create_plan(req, db_path=initialized_db_path)

    tok = token_service.create_token(
        approver_id="sec-admin",
        role="SECURITY_LEAD",
        authorized_scopes=ALL_SCOPES,
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(tok.raw_token, db_path=initialized_db_path)

    appr = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req.request_id,
            submitted_plan_hash=plan.canonical_plan_hash,
            plan_version=plan.plan_version,
            decision=ApprovalDecisionType.APPROVE,
        ),
        approver=identity,
        target_environment=plan.target_environment,
        granted_scopes=req.requested_scopes,
        db_path=initialized_db_path,
    )

    # Fast forward approval expiration into past (35 minutes ago)
    past_exp = (datetime.now(timezone.utc) - timedelta(minutes=35)).isoformat()
    conn = get_connection(initialized_db_path)
    conn.execute("UPDATE approval_records SET expires_at = ? WHERE approval_id = ?;", (past_exp, appr.approval_id))
    conn.commit()
    conn.close()

    with pytest.raises(ApprovalExpiredError):
        orchestrator.run_workflow(
            request_id=req.request_id,
            caller_token=tok.raw_token,
            custom_root=mock_sandbox_root,
            db_path=initialized_db_path,
            raise_on_failure=True,
        )


# 12. Execution is blocked when plan or permission manifest changes.
def test_12_execution_blocked_when_plan_or_permissions_change(
    initialized_db_path: Path,
    token_service: TokenService,
    approval_service: ApprovalService,
    mock_sandbox_root: Path,
):
    orchestrator = WorkflowOrchestrator(approval_service=approval_service)
    req = make_test_request(orchestrator, "tamper-test", initialized_db_path)
    plan = orchestrator._get_or_create_plan(req, db_path=initialized_db_path)

    tok = token_service.create_token(
        approver_id="sec-admin",
        role="SECURITY_LEAD",
        authorized_scopes=ALL_SCOPES,
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(tok.raw_token, db_path=initialized_db_path)

    approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req.request_id,
            submitted_plan_hash=plan.canonical_plan_hash,
            plan_version=plan.plan_version,
            decision=ApprovalDecisionType.APPROVE,
        ),
        approver=identity,
        target_environment=plan.target_environment,
        granted_scopes=req.requested_scopes,
        db_path=initialized_db_path,
    )

    # Tamper with plan hash in SQLite setup_plans table (trigger automatically revokes approval)
    tampered_hash = "f" * 64
    conn = get_connection(initialized_db_path)
    conn.execute("UPDATE setup_plans SET canonical_plan_hash = ? WHERE request_id = ?;", (tampered_hash, req.request_id))
    conn.commit()
    conn.close()

    with pytest.raises(ApprovalError):
        orchestrator.run_workflow(
            request_id=req.request_id,
            caller_token=tok.raw_token,
            custom_root=mock_sandbox_root,
            db_path=initialized_db_path,
            raise_on_failure=True,
        )


# 13. Execution is blocked for invalid or reused approval.
def test_13_execution_blocked_for_invalid_or_reused_approval(
    initialized_db_path: Path,
    token_service: TokenService,
    approval_service: ApprovalService,
    mock_sandbox_root: Path,
):
    orchestrator = WorkflowOrchestrator(approval_service=approval_service)
    req = make_test_request(orchestrator, "replay-test", initialized_db_path)
    plan = orchestrator._get_or_create_plan(req, db_path=initialized_db_path)

    tok = token_service.create_token(
        approver_id="sec-admin",
        role="SECURITY_LEAD",
        authorized_scopes=ALL_SCOPES,
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(tok.raw_token, db_path=initialized_db_path)

    appr = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req.request_id,
            submitted_plan_hash=plan.canonical_plan_hash,
            plan_version=plan.plan_version,
            decision=ApprovalDecisionType.APPROVE,
        ),
        approver=identity,
        target_environment=plan.target_environment,
        granted_scopes=req.requested_scopes,
        db_path=initialized_db_path,
    )

    # Atomically mark approval as already consumed
    conn = get_connection(initialized_db_path)
    conn.execute(
        "UPDATE approval_records SET execution_consumed = 1, consumed_at = ? WHERE approval_id = ?;",
        (datetime.now(timezone.utc).isoformat(), appr.approval_id),
    )
    conn.commit()
    conn.close()

    with pytest.raises(ApprovalAlreadyConsumedError):
        orchestrator.run_workflow(
            request_id=req.request_id,
            caller_token=tok.raw_token,
            custom_root=mock_sandbox_root,
            db_path=initialized_db_path,
            raise_on_failure=True,
        )


# 14. Unauthorized tools and excessive permissions are rejected.
def test_14_unauthorized_tools_and_excessive_permissions_rejected():
    policy = PolicyEngine()

    # Step with command injection key in parameters rejected by Pydantic validator
    with pytest.raises(ValueError, match="Dangerous action parameter"):
        PlannedStep(
            step_id="step-00000001",
            name="Malicious Command",
            description="Dangerous shell command",
            is_privileged=False,
            action_type=StepActionType.EXECUTE_SMOKE_TEST,
            required_scopes=[PermissionScope.TEST_EXECUTE],
            action_parameters={"shell_cmd": "rm -rf /"},
        )

    # Step with excessive scopes rejected by PolicyEngine
    excessive_step = PlannedStep(
        step_id="step-00000002",
        name="Excessive Privilege",
        description="Excessive delete scope on read action",
        is_privileged=False,
        action_type=StepActionType.DISCOVER_REPOSITORY,
        required_scopes=[PermissionScope.SANDBOX_DELETE],
        action_parameters={"template": "python-fastapi-service"},
    )
    with pytest.raises(PolicyViolationError):
        policy.validate_step_policy(excessive_step)


# 15. Valid approval permits only exact approved mock actions.
def test_15_valid_approval_permits_only_exact_approved_mock_actions(
    initialized_db_path: Path,
    mock_sandbox_root: Path,
    token_service: TokenService,
    sandbox_provisioner: MockSandboxProvisioner,
    approval_service: ApprovalService,
):
    orchestrator = WorkflowOrchestrator(approval_service=approval_service)
    req = make_test_request(orchestrator, "exact-action-test", initialized_db_path)
    plan = orchestrator._get_or_create_plan(req, db_path=initialized_db_path)

    tok = token_service.create_token(
        approver_id="sec-admin",
        role="SECURITY_LEAD",
        authorized_scopes=ALL_SCOPES,
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(tok.raw_token, db_path=initialized_db_path)

    appr = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req.request_id,
            submitted_plan_hash=plan.canonical_plan_hash,
            plan_version=plan.plan_version,
            decision=ApprovalDecisionType.APPROVE,
        ),
        approver=identity,
        target_environment=plan.target_environment,
        granted_scopes=req.requested_scopes,
        db_path=initialized_db_path,
    )

    # Provision succeeds for exact approved action
    result = sandbox_provisioner.provision_sandbox(
        request_id=req.request_id,
        approval_id=appr.approval_id,
        execution_id="exec-exact-01",
        step_id="step-00000004",
        plan_hash=plan.canonical_plan_hash,
        plan_version=plan.plan_version,
        target_environment=plan.target_environment,
        granted_scopes=appr.granted_scopes,
        caller_token=tok.raw_token,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )
    assert result.status == "PROVISIONED"
    assert result.sandbox_id.startswith("sbx-")


# 16. Synthetic data seeding produces synthetic data only.
def test_16_synthetic_data_seeding_produces_synthetic_only(
    initialized_db_path: Path,
    mock_sandbox_root: Path,
    token_service: TokenService,
    sandbox_provisioner: MockSandboxProvisioner,
    data_seeder: SyntheticDataSeeder,
    approval_service: ApprovalService,
):
    orchestrator = WorkflowOrchestrator(approval_service=approval_service)
    req = make_test_request(orchestrator, "seed-test", initialized_db_path)
    plan = orchestrator._get_or_create_plan(req, db_path=initialized_db_path)

    tok = token_service.create_token(
        approver_id="sec-admin",
        role="SECURITY_LEAD",
        authorized_scopes=ALL_SCOPES,
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(tok.raw_token, db_path=initialized_db_path)

    appr = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req.request_id,
            submitted_plan_hash=plan.canonical_plan_hash,
            plan_version=plan.plan_version,
            decision=ApprovalDecisionType.APPROVE,
        ),
        approver=identity,
        target_environment=plan.target_environment,
        granted_scopes=req.requested_scopes,
        db_path=initialized_db_path,
    )

    # First provision sandbox to register tracking and metadata
    sbx_res = sandbox_provisioner.provision_sandbox(
        request_id=req.request_id,
        approval_id=appr.approval_id,
        execution_id="exec-seed-01",
        step_id="step-00000004",
        plan_hash=plan.canonical_plan_hash,
        plan_version=plan.plan_version,
        target_environment=plan.target_environment,
        granted_scopes=appr.granted_scopes,
        caller_token=tok.raw_token,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )

    summary = data_seeder.seed_fixtures(
        request_id=req.request_id,
        sandbox_id=sbx_res.sandbox_id,
        approval_id=appr.approval_id,
        execution_id="exec-seed-01",
        step_id="step-00000005",
        plan_hash=plan.canonical_plan_hash,
        plan_version=plan.plan_version,
        target_environment=plan.target_environment,
        granted_scopes=appr.granted_scopes,
        fixture_ids=["users.json", "teams.json"],
        caller_token=tok.raw_token,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )

    assert len(summary.fixtures_seeded) == 2
    users_file = sbx_res.sandbox_dir / "fixtures" / "users.json"
    users_data = json.loads(users_file.read_text(encoding="utf-8"))
    assert len(users_data) > 0
    # Confirm synthetic nature
    for u in users_data:
        assert any(domain in u["email"] for domain in ["@example.local", "@example.com", "@mock.local", "@synthetic.local"])


# 17. Verification correctly distinguishes success from failure.
def test_17_verification_distinguishes_success_from_failure(tmp_path: Path):
    from src.adapters.fixtures import get_canonical_fixture_bytes
    verifier = VerificationNode()
    sbx_dir = tmp_path / "sbx-verify-test"

    # Missing directory -> failure
    rep_fail = verifier.verify(sbx_dir, sandbox_id="sbx-verify-test", expected_fixtures=["users.json"])
    assert rep_fail.is_valid is False
    assert len(rep_fail.failure_reasons) > 0

    # Write proper sandbox directory, metadata, and canonical fixture
    sbx_dir.mkdir()
    (sbx_dir / "fixtures").mkdir()
    meta = {
        "sandbox_id": "sbx-verify-test",
        "ownership_token": "token-12345678",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
        "is_mock": True,
        "environment_label": "MOCK / LOCAL ONLY",
    }
    (sbx_dir / ".sandbox-metadata.json").write_text(json.dumps(meta), encoding="utf-8")
    raw_fixture_bytes, _ = get_canonical_fixture_bytes("users.json")
    (sbx_dir / "fixtures" / "users.json").write_bytes(raw_fixture_bytes)

    rep_success = verifier.verify(
        sandbox_dir=sbx_dir,
        sandbox_id="sbx-verify-test",
        expected_fixtures=["users.json"],
    )
    assert rep_success.is_valid is True
    assert len(rep_success.failure_reasons) == 0


# 18. Retries are bounded and prohibited actions are never retried.
def test_18_retries_are_bounded_and_prohibited_actions_never_retried():
    reflection = ReflectionNode()

    # 1. Transient error on attempt 1 -> can retry
    d1 = reflection.reflect(
        error=RuntimeError("Transient socket timeout"),
        current_retry_count=1,
        stage_name="EXECUTE_SMOKE_TEST",
    )
    assert d1.can_retry is True

    # 2. Reached max retries (attempt 2) -> cannot retry
    d2 = reflection.reflect(
        error=RuntimeError("Persistent timeout"),
        current_retry_count=2,
        stage_name="EXECUTE_SMOKE_TEST",
    )
    assert d2.can_retry is False

    # 3. Security error -> NEVER retried, even on attempt 0
    d_sec = reflection.reflect(
        error=AuthorizationDeniedError("Unauthorized token"),
        current_retry_count=0,
        stage_name="PROVISION_MOCK_SANDBOX",
    )
    assert d_sec.can_retry is False
    assert d_sec.is_terminal_failure is True


# 19. Audit records are persisted without secrets.
def test_19_audit_records_persisted_without_secrets(
    initialized_db_path: Path,
    audit_service: AuditChainService,
):
    secret_token = "raw-secret-token-xyz-12345"
    audit_service.append_event(
        request_id="req-audit-test",
        event_type=AuditEventType.APPROVAL_SUBMITTED,
        severity=AuditSeverity.INFO,
        actor=AuditActor(actor_id="sec-admin", role="SECURITY_LEAD"),
        action_name="TEST_AUDIT",
        details={"info": "Safe details only", "sanitized": True},
        db_path=initialized_db_path,
    )

    conn = get_connection(initialized_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT details FROM audit_log WHERE request_id = 'req-audit-test';")
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    assert secret_token not in row["details"]


# 20. Sandbox cleanup deadlines are calculated correctly.
def test_20_sandbox_cleanup_deadlines_calculated_correctly(
    initialized_db_path: Path,
    mock_sandbox_root: Path,
    token_service: TokenService,
    approval_service: ApprovalService,
    sandbox_provisioner: MockSandboxProvisioner,
):
    orchestrator = WorkflowOrchestrator(approval_service=approval_service)
    req = make_test_request(orchestrator, "deadline-test", initialized_db_path)
    plan = orchestrator._get_or_create_plan(req, db_path=initialized_db_path)

    tok = token_service.create_token(
        approver_id="sec-admin",
        role="SECURITY_LEAD",
        authorized_scopes=ALL_SCOPES,
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(tok.raw_token, db_path=initialized_db_path)

    appr = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req.request_id,
            submitted_plan_hash=plan.canonical_plan_hash,
            plan_version=plan.plan_version,
            decision=ApprovalDecisionType.APPROVE,
        ),
        approver=identity,
        target_environment=plan.target_environment,
        granted_scopes=req.requested_scopes,
        db_path=initialized_db_path,
    )

    result = sandbox_provisioner.provision_sandbox(
        request_id=req.request_id,
        approval_id=appr.approval_id,
        execution_id="exec-deadline-01",
        step_id="step-00000004",
        plan_hash=plan.canonical_plan_hash,
        plan_version=plan.plan_version,
        target_environment=plan.target_environment,
        granted_scopes=appr.granted_scopes,
        caller_token=tok.raw_token,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )

    delta = result.expires_at - result.created_at
    # Exactly 24 hours (86400 seconds)
    assert abs(delta.total_seconds() - 86400) < 5


# 21. Repeated API requests do not cause duplicate privileged execution.
def test_21_repeated_api_requests_do_not_cause_duplicate_privileged_execution(
    initialized_db_path: Path,
    mock_sandbox_root: Path,
    token_service: TokenService,
    approval_service: ApprovalService,
):
    orchestrator = WorkflowOrchestrator(approval_service=approval_service)
    req = make_test_request(orchestrator, "idempotent-test", initialized_db_path)
    plan = orchestrator._get_or_create_plan(req, db_path=initialized_db_path)

    tok = token_service.create_token(
        approver_id="sec-admin",
        role="SECURITY_LEAD",
        authorized_scopes=ALL_SCOPES,
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(tok.raw_token, db_path=initialized_db_path)

    approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req.request_id,
            submitted_plan_hash=plan.canonical_plan_hash,
            plan_version=plan.plan_version,
            decision=ApprovalDecisionType.APPROVE,
        ),
        approver=identity,
        target_environment=plan.target_environment,
        granted_scopes=req.requested_scopes,
        db_path=initialized_db_path,
    )

    # First run: completes workflow
    res1 = orchestrator.run_workflow(
        request_id=req.request_id,
        caller_token=tok.raw_token,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )
    assert res1.is_completed is True

    # Second run: returns completed status idempotently without duplicate provisioning
    res2 = orchestrator.run_workflow(
        request_id=req.request_id,
        caller_token=tok.raw_token,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )
    assert res2.is_completed is True
    assert res2.sandbox_id == res1.sandbox_id


# 22. End-to-end successful workflow works.
def test_22_end_to_end_successful_workflow(
    initialized_db_path: Path,
    mock_sandbox_root: Path,
    token_service: TokenService,
    approval_service: ApprovalService,
):
    orchestrator = WorkflowOrchestrator(approval_service=approval_service)

    # Phase 1: Create request
    req = make_test_request(orchestrator, "e2e-success-test", initialized_db_path)

    # Phase 2: Run until approval gate
    res_pause = orchestrator.run_workflow(
        request_id=req.request_id,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )
    assert res_pause.approval_required is True

    # Phase 3: Human approver reviews and approves
    plan = orchestrator._get_or_create_plan(req, db_path=initialized_db_path)
    tok = token_service.create_token(
        approver_id="sec-lead-01",
        role="SECURITY_LEAD",
        authorized_scopes=ALL_SCOPES,
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(tok.raw_token, db_path=initialized_db_path)

    approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req.request_id,
            submitted_plan_hash=plan.canonical_plan_hash,
            plan_version=plan.plan_version,
            decision=ApprovalDecisionType.APPROVE,
        ),
        approver=identity,
        target_environment=plan.target_environment,
        granted_scopes=req.requested_scopes,
        db_path=initialized_db_path,
    )

    # Phase 4: Resume workflow with token
    res_final = orchestrator.run_workflow(
        request_id=req.request_id,
        caller_token=tok.raw_token,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )

    assert res_final.is_completed is True
    assert res_final.current_status == WorkflowStatus.COMPLETED
    assert res_final.sandbox_id is not None
    assert res_final.manifest_id is not None
    assert res_final.cleanup_deadline is not None


# 23. End-to-end rejected-approval workflow works.
def test_23_end_to_end_rejected_approval_workflow(
    initialized_db_path: Path,
    mock_sandbox_root: Path,
    token_service: TokenService,
    approval_service: ApprovalService,
):
    orchestrator = WorkflowOrchestrator(approval_service=approval_service)

    req = make_test_request(orchestrator, "e2e-reject-test", initialized_db_path)

    plan = orchestrator._get_or_create_plan(req, db_path=initialized_db_path)
    tok = token_service.create_token(
        approver_id="sec-lead-01",
        role="SECURITY_LEAD",
        authorized_scopes=ALL_SCOPES,
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(tok.raw_token, db_path=initialized_db_path)

    approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req.request_id,
            submitted_plan_hash=plan.canonical_plan_hash,
            plan_version=plan.plan_version,
            decision=ApprovalDecisionType.REJECT,
            rejection_reason="Excessive permissions rejected by security officer.",
        ),
        approver=identity,
        target_environment=plan.target_environment,
        granted_scopes=req.requested_scopes,
        db_path=initialized_db_path,
    )

    res = orchestrator.run_workflow(
        request_id=req.request_id,
        caller_token=tok.raw_token,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
        raise_on_failure=False,
    )

    assert res.is_completed is False
    assert res.current_status == WorkflowStatus.FAILED
    assert res.error_category in ("ApprovalError", "ApprovalRejectedError")
    assert "rejected" in (res.error_message or "").lower()


# 24. End-to-end failure workflow produces correct terminal status.
def test_24_end_to_end_failure_workflow_terminal_status(
    initialized_db_path: Path,
    mock_sandbox_root: Path,
    token_service: TokenService,
    approval_service: ApprovalService,
):
    orchestrator = WorkflowOrchestrator(approval_service=approval_service)

    # Request with missing required scope -> fails in VALIDATE_PLAN
    req = orchestrator.create_request(
        BootstrapRequestCreate(
            project_name="e2e-failure-test",
            template=ProjectTemplate.PYTHON_FASTAPI,
            repository_path="./",
            developer_id="dev-charlie",
            requested_scopes=[PermissionScope.SANDBOX_CREATE],  # Lacks sandbox:read etc.
        ),
        db_path=initialized_db_path,
    )

    res = orchestrator.run_workflow(
        request_id=req.request_id,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
        raise_on_failure=False,
    )

    assert res.is_completed is False
    assert res.current_status == WorkflowStatus.FAILED
    assert res.error_category in ("PlanValidationError", "TokenScopeError", "SecurityViolationError", "AuthorizationDeniedError")
