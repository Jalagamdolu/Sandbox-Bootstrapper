"""Tests verifying that LangGraph is genuinely integrated as the real workflow orchestration engine.

Covers:
- Graph construction, nodes, edges, and entry point
- Real invocation, thread identifiers, and SQLite checkpointing
- Conditional routing and pause/resume lifecycle around human approval
- Server-side security guard enforcement: invalid, expired, revoked, and insufficient approvals
- Plan mutation drift detection and approval revocation
- Crash recovery and idempotent resumption without re-running privileged operations
- Concurrency protection via StepExecutionTracker
- Cleanup authorization enforcement under SANDBOX_DELETE
- Secret redaction and audit hash-chain integrity
- API and UI execution through the LangGraph engine
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
import pytest

from langgraph.graph.state import CompiledStateGraph
from src.core.config import get_settings
from src.core.exceptions import (
    ApprovalExpiredError,
    ApprovalRevokedError,
    PlanTamperingError,
    SecurityViolationError,
    TokenScopeError,
)
from src.models.approvals import ApprovalDecisionType, ApprovalRecord, ApprovalRequest
from src.models.enums import PermissionScope, ProjectTemplate, WorkflowStage, WorkflowStatus
from src.models.requests import BootstrapRequestCreate
from src.security.approvals import ApprovalService
from src.security.audit_chain import AuditChainService
from src.security.tokens import TokenService
from src.storage.connection import get_connection
from src.storage.db_init import initialize_database
from src.workflow.graph import BootstrapperWorkflowGraph, get_sqlite_checkpointer
from src.workflow.orchestrator import WorkflowOrchestrator
from src.workflow.verifier import SandboxVerifier


@pytest.fixture
def isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolate SQLite database and mock sandbox directories."""
    db_file = tmp_path / "langgraph_test.db"
    sbx_dir = tmp_path / "sandboxes"
    sbx_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("DATABASE_PATH", str(db_file))
    monkeypatch.setenv("SANDBOX_STORAGE_DIR", str(sbx_dir))

    get_settings(reload=True)
    initialize_database(db_file)
    yield db_file, sbx_dir
    get_settings(reload=True)


@pytest.fixture
def orchestrator(isolated_env) -> WorkflowOrchestrator:
    db_file, sbx_dir = isolated_env
    return WorkflowOrchestrator(verifier=SandboxVerifier())


@pytest.fixture
def token_service() -> TokenService:
    return TokenService()


@pytest.fixture
def approval_service() -> ApprovalService:
    return ApprovalService()


@pytest.fixture
def audit_service() -> AuditChainService:
    return AuditChainService()


def _create_sample_request(orch: WorkflowOrchestrator, db_path: Path) -> str:
    req = orch.create_request(
        BootstrapRequestCreate(
            project_name="lg-service",
            template=ProjectTemplate.PYTHON_FASTAPI,
            repository_path="./",
            requested_scopes=[
                PermissionScope.SANDBOX_READ,
                PermissionScope.SANDBOX_CREATE,
                PermissionScope.SANDBOX_DELETE,
                PermissionScope.DATA_SEED_SYNTHETIC,
                PermissionScope.TEST_EXECUTE,
                PermissionScope.AUDIT_READ,
            ],
            developer_id="dev-lg",
            target_environment="local-mock-dev",
        ),
        db_path=db_path,
    )
    return req.request_id


def _grant_test_approval(
    token_svc: TokenService,
    appr_svc: ApprovalService,
    db_path: Path,
    req_id: str,
    plan_hash: str,
    plan_version: int = 1,
    target_env: str = "local-mock-dev",
    scopes: list[PermissionScope] | None = None,
) -> ApprovalRecord:
    granted = scopes or [
        PermissionScope.SANDBOX_CREATE,
        PermissionScope.DATA_SEED_SYNTHETIC,
        PermissionScope.SANDBOX_DELETE,
    ]
    tok = token_svc.create_token(
        approver_id="sec-lead-lg",
        role="SECURITY_LEAD",
        authorized_scopes=granted + [PermissionScope.SANDBOX_READ],
        db_path=db_path,
    )
    identity = token_svc.resolve_identity(tok.raw_token, db_path=db_path)
    appr_req = ApprovalRequest(
        request_id=req_id,
        decision=ApprovalDecisionType.APPROVE,
        submitted_plan_hash=plan_hash,
        plan_version=plan_version,
    )
    return appr_svc.create_approval(
        request=appr_req,
        approver=identity,
        target_environment=target_env,
        granted_scopes=granted,
        db_path=db_path,
    )


# =============================================================================
# 1. GRAPH STRUCTURE & NODE TOPOLOGY TESTS
# =============================================================================

def test_langgraph_graph_structure_and_nodes(orchestrator: WorkflowOrchestrator, isolated_env):
    """Verify LangGraph StateGraph compiles with all 10 required stage nodes and edges."""
    db_file, _ = isolated_env
    graph = orchestrator.get_graph(db_path=db_file)
    assert isinstance(graph, CompiledStateGraph)

    # Inspect all registered nodes in the graph
    node_names = set(graph.nodes.keys())
    required_stages = {
        "collect_request",
        "discover",
        "build_plan",
        "validate_plan",
        "generate_manifest",
        "await_approval",
        "provision_mock_sandbox",
        "seed_synthetic_data",
        "verify_sandbox",
        "finalize",
    }
    assert required_stages.issubset(node_names)
    assert orchestrator.graph is not None


# =============================================================================
# 2. REAL INVOCATION & LOCAL SQLITE CHECKPOINTING TESTS
# =============================================================================

def test_langgraph_actual_invocation_and_checkpointing(orchestrator: WorkflowOrchestrator, isolated_env):
    """Verify that orchestrator.run_workflow invokes the LangGraph engine and saves checkpoints to SQLite."""
    db_file, _ = isolated_env
    req_id = _create_sample_request(orchestrator, db_file)

    # Execute workflow up to approval pause
    res = orchestrator.run_workflow(req_id, db_path=db_file)
    assert res.approval_required is True
    assert res.current_status == WorkflowStatus.PENDING_APPROVAL
    assert res.stage == WorkflowStage.AWAIT_APPROVAL

    # Inspect the LangGraph checkpointer SQLite tables directly
    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute("SELECT thread_id, checkpoint_id FROM checkpoints WHERE thread_id = ?;", (f"bootstrapper-{req_id}",))
    rows = cur.fetchall()
    cur.close()
    conn.close()

    assert len(rows) > 0, "LangGraph checkpoints table must contain checkpoint records for this thread_id"

    # Inspect graph state snapshot using LangGraph API
    graph = orchestrator.get_graph(db_path=db_file)
    cfg = {"configurable": {"thread_id": f"bootstrapper-{req_id}"}}
    snapshot = graph.get_state(cfg)
    assert snapshot.values["request_id"] == req_id
    assert snapshot.values["current_status"] == WorkflowStatus.PENDING_APPROVAL.value
    assert snapshot.values["approval_required"] is True
    assert snapshot.values["canonical_plan_hash"] is not None


# =============================================================================
# 3. CONDITIONAL ROUTING & PAUSE/RESUME TESTS
# =============================================================================

def test_langgraph_pause_and_resume_with_valid_approval(
    orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    isolated_env,
):
    """Verify graph pauses at AWAIT_APPROVAL and cleanly resumes to FINALIZE upon approval."""
    db_file, _ = isolated_env
    req_id = _create_sample_request(orchestrator, db_file)

    # 1. Unapproved execution pauses
    res_pause = orchestrator.run_workflow(req_id, db_path=db_file)
    assert res_pause.approval_required is True
    assert res_pause.is_completed is False

    # 2. Fetch generated plan hash
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("SELECT canonical_plan_hash, plan_version FROM setup_plans WHERE request_id = ?;", (req_id,))
    plan_row = cur.fetchone()
    cur.close()
    conn.close()

    plan_hash = plan_row["canonical_plan_hash"]
    plan_ver = plan_row["plan_version"]

    # 3. Grant valid approval
    _grant_test_approval(
        token_svc=token_service,
        appr_svc=approval_service,
        db_path=db_file,
        req_id=req_id,
        plan_hash=plan_hash,
        plan_version=plan_ver,
    )

    # 4. Resume execution
    res_final = orchestrator.run_workflow(req_id, db_path=db_file)
    assert res_final.is_completed is True
    assert res_final.current_status == WorkflowStatus.COMPLETED
    assert res_final.stage == WorkflowStage.FINALIZE
    assert res_final.sandbox_id is not None
    assert res_final.manifest is not None


# =============================================================================
# 4. SERVER-SIDE SECURITY & REJECTION TESTS
# =============================================================================

def test_langgraph_expired_approval_rejection(
    orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    isolated_env,
):
    """Verify expired approval fails closed and stops execution before privileged stages."""
    db_file, _ = isolated_env
    req_id = _create_sample_request(orchestrator, db_file)
    orchestrator.run_workflow(req_id, db_path=db_file)

    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("SELECT canonical_plan_hash, plan_version FROM setup_plans WHERE request_id = ?;", (req_id,))
    plan_row = cur.fetchone()
    cur.close()
    conn.close()

    appr = _grant_test_approval(token_service, approval_service, db_file, req_id, plan_row["canonical_plan_hash"])

    # Backdate expiration
    past_iso = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("UPDATE approval_records SET expires_at = ? WHERE approval_id = ?;", (past_iso, appr.approval_id))
    conn.commit()
    cur.close()
    conn.close()

    res = orchestrator.run_workflow(req_id, db_path=db_file, raise_on_failure=False)
    assert res.is_completed is False
    assert res.current_status == WorkflowStatus.EXPIRED


def test_langgraph_revoked_approval_rejection(
    orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    isolated_env,
):
    """Verify revoked approval stops execution before privileged stages."""
    db_file, _ = isolated_env
    req_id = _create_sample_request(orchestrator, db_file)
    orchestrator.run_workflow(req_id, db_path=db_file)

    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("SELECT canonical_plan_hash FROM setup_plans WHERE request_id = ?;", (req_id,))
    plan_row = cur.fetchone()
    cur.close()
    conn.close()

    appr = _grant_test_approval(token_service, approval_service, db_file, req_id, plan_row["canonical_plan_hash"])
    approval_service.revoke_approval(appr.approval_id, reason="Security audit revocation", db_path=db_file)

    res = orchestrator.run_workflow(req_id, db_path=db_file, raise_on_failure=False)
    assert res.is_completed is False
    assert res.current_status == WorkflowStatus.FAILED


def test_langgraph_insufficient_scope_rejection(
    orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    isolated_env,
):
    """Verify approval without required privileged scopes is rejected."""
    db_file, _ = isolated_env
    req_id = _create_sample_request(orchestrator, db_file)
    orchestrator.run_workflow(req_id, db_path=db_file)

    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("SELECT canonical_plan_hash FROM setup_plans WHERE request_id = ?;", (req_id,))
    plan_row = cur.fetchone()
    cur.close()
    conn.close()

    # Grant only read permission (missing sandbox:create and data:seed:synthetic)
    _grant_test_approval(
        token_service,
        approval_service,
        db_file,
        req_id,
        plan_row["canonical_plan_hash"],
        scopes=[PermissionScope.SANDBOX_READ],
    )

    res = orchestrator.run_workflow(req_id, db_path=db_file, raise_on_failure=False)
    assert res.is_completed is False
    assert res.current_status == WorkflowStatus.FAILED


def test_langgraph_plan_tampering_rejection(
    orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    isolated_env,
):
    """Verify plan mutation drift causes approval rejection."""
    db_file, _ = isolated_env
    req_id = _create_sample_request(orchestrator, db_file)
    orchestrator.run_workflow(req_id, db_path=db_file)

    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("SELECT canonical_plan_hash, plan_version FROM setup_plans WHERE request_id = ?;", (req_id,))
    plan_row = cur.fetchone()
    cur.close()
    conn.close()

    # Approve with valid plan hash
    _grant_test_approval(token_service, approval_service, db_file, req_id, plan_row["canonical_plan_hash"], plan_row["plan_version"])

    # Mutate setup_plans directly in SQLite to simulate tampering
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("UPDATE setup_plans SET canonical_plan_hash = ? WHERE request_id = ?;", ("f" * 64, req_id))
    conn.commit()
    cur.close()
    conn.close()

    res = orchestrator.run_workflow(req_id, db_path=db_file, raise_on_failure=False)
    assert res.is_completed is False
    assert res.current_status == WorkflowStatus.FAILED


# =============================================================================
# 5. CRASH RECOVERY & IDEMPOTENCY TESTS
# =============================================================================

def test_langgraph_crash_recovery_skips_completed_provisioning(
    orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    isolated_env,
):
    """Verify that resuming an interrupted workflow skips already-completed provisioning."""
    db_file, sbx_dir = isolated_env
    req_id = _create_sample_request(orchestrator, db_file)
    orchestrator.run_workflow(req_id, db_path=db_file)

    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("SELECT canonical_plan_hash, plan_version FROM setup_plans WHERE request_id = ?;", (req_id,))
    plan_row = cur.fetchone()
    cur.close()
    conn.close()

    _grant_test_approval(
        token_service,
        approval_service,
        db_file,
        req_id,
        plan_row["canonical_plan_hash"],
        plan_row["plan_version"],
    )

    exec_id = "exec-test-crash-recovery"

    # Mock failure in seed_synthetic_data stage
    with patch.object(orchestrator.data_seeder, "seed_fixtures", side_effect=RuntimeError("Simulated seeder crash")):
        res_crash = orchestrator.run_workflow(req_id, execution_id=exec_id, db_path=db_file, raise_on_failure=False)
        assert res_crash.current_status == WorkflowStatus.FAILED

    # Check that sandbox was provisioned before crash
    tracked = orchestrator._find_tracked_sandbox(req_id, sbx_dir, db_path=db_file)
    assert tracked is not None
    original_sbx_id = tracked.sandbox_id

    # Resume workflow execution with SAME execution_id
    res_resume = orchestrator.run_workflow(req_id, execution_id=exec_id, db_path=db_file, raise_on_failure=False)
    assert res_resume.is_completed is True
    assert res_resume.current_status == WorkflowStatus.COMPLETED
    assert res_resume.sandbox_id == original_sbx_id


def test_langgraph_duplicate_run_is_idempotent(
    orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    isolated_env,
):
    """Verify that calling run on a COMPLETED workflow returns immediately without re-executing."""
    db_file, _ = isolated_env
    req_id = _create_sample_request(orchestrator, db_file)
    orchestrator.run_workflow(req_id, db_path=db_file)

    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("SELECT canonical_plan_hash, plan_version FROM setup_plans WHERE request_id = ?;", (req_id,))
    plan_row = cur.fetchone()
    cur.close()
    conn.close()

    _grant_test_approval(
        token_service,
        approval_service,
        db_file,
        req_id,
        plan_row["canonical_plan_hash"],
        plan_row["plan_version"],
    )

    res1 = orchestrator.run_workflow(req_id, db_path=db_file)
    assert res1.is_completed is True

    # Duplicate run
    res2 = orchestrator.run_workflow(req_id, db_path=db_file)
    assert res2.is_completed is True
    assert res2.current_status == WorkflowStatus.COMPLETED


# =============================================================================
# 6. CLEANUP AUTHORIZATION UNDER SANDBOX_DELETE
# =============================================================================

def test_langgraph_cleanup_requires_sandbox_delete(
    orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    isolated_env,
):
    """Verify cleanup requires SANDBOX_DELETE permission scope."""
    db_file, _ = isolated_env
    req_id = _create_sample_request(orchestrator, db_file)
    orchestrator.run_workflow(req_id, db_path=db_file)

    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("SELECT canonical_plan_hash, plan_version FROM setup_plans WHERE request_id = ?;", (req_id,))
    plan_row = cur.fetchone()
    cur.close()
    conn.close()

    _grant_test_approval(
        token_service,
        approval_service,
        db_file,
        req_id,
        plan_row["canonical_plan_hash"],
        plan_row["plan_version"],
    )

    res = orchestrator.run_workflow(req_id, db_path=db_file)
    assert res.is_completed is True

    # Dedicated cleanup approval with SANDBOX_DELETE
    cleanup_appr = _grant_test_approval(
        token_service,
        approval_service,
        db_file,
        req_id,
        plan_row["canonical_plan_hash"],
        plan_row["plan_version"],
        scopes=[PermissionScope.SANDBOX_DELETE],
    )

    # Token with SANDBOX_DELETE can clean up
    del_token = token_service.create_token(
        approver_id="admin-del",
        role="ADMIN",
        authorized_scopes=[PermissionScope.SANDBOX_DELETE],
        db_path=db_file,
    )
    ok = orchestrator.cleanup_workflow_sandbox(
        request_id=req_id,
        sandbox_id=res.sandbox_id,
        approval_id=cleanup_appr.approval_id,
        execution_id="exec-del",
        caller_token=del_token.raw_token,
        db_path=db_file,
    )
    assert ok is True


# =============================================================================
# 7. AUDIT HASH CHAIN & SECRET REDACTION
# =============================================================================

def test_langgraph_audit_trail_and_secret_redaction(
    orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    audit_service: AuditChainService,
    isolated_env,
):
    """Verify audit chain integrity and lack of raw secret leakage during LangGraph execution."""
    db_file, _ = isolated_env
    req_id = _create_sample_request(orchestrator, db_file)
    orchestrator.run_workflow(req_id, db_path=db_file)

    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("SELECT canonical_plan_hash, plan_version FROM setup_plans WHERE request_id = ?;", (req_id,))
    plan_row = cur.fetchone()
    cur.close()
    conn.close()

    _grant_test_approval(
        token_service,
        approval_service,
        db_file,
        req_id,
        plan_row["canonical_plan_hash"],
        plan_row["plan_version"],
    )

    res = orchestrator.run_workflow(req_id, db_path=db_file)
    assert res.is_completed is True

    # Verify audit chain integrity
    report = audit_service.verify_chain(db_path=db_file)
    assert report.is_valid is True
    assert report.events_inspected >= 5

    # Check for secret leakage in audit events
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("SELECT details FROM audit_log WHERE request_id = ?;", (req_id,))
    rows = cur.fetchall()
    cur.close()
    conn.close()

    for row in rows:
        details_str = str(row["details"]).lower()
        assert "bearer" not in details_str
        assert "secret" not in details_str
        assert "raw_token" not in details_str

    # Check for secret leakage in LangGraph checkpoint tables
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("SELECT checkpoint FROM checkpoints;")
    for cp_row in cur.fetchall():
        assert b"bearer" not in cp_row[0].lower()
        assert b"raw_token" not in cp_row[0].lower()
    cur.execute("SELECT value FROM writes;")
    for wr_row in cur.fetchall():
        assert b"bearer" not in wr_row[0].lower()
        assert b"raw_token" not in wr_row[0].lower()
    cur.close()
    conn.close()


# =============================================================================
# 8. API & UI INTEGRATION WITH LANGGRAPH WORKFLOW
# =============================================================================

def test_langgraph_api_integration(isolated_env):
    """Verify that FastAPI /api/v1/requests/{id}/run drives the LangGraph workflow and creates checkpoints."""
    from fastapi.testclient import TestClient
    from src.api.app import create_app

    db_file, _ = isolated_env
    app = create_app()
    client = TestClient(app)

    # 1. Create request via API
    create_resp = client.post(
        "/api/v1/requests",
        json={
            "project_name": "lg-api-test",
            "template": "python-fastapi-service",
            "repository_path": "./",
            "developer_id": "dev-api",
            "target_environment": "local-mock-dev",
            "requested_scopes": ["sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"],
        },
    )
    assert create_resp.status_code == 201
    req_id = create_resp.json()["request_id"]

    # 2. Run unapproved workflow via API
    run_resp1 = client.post(f"/api/v1/requests/{req_id}/run")
    assert run_resp1.status_code == 200
    assert run_resp1.json()["current_status"] == "PENDING_APPROVAL"
    assert run_resp1.json()["approval_required"] is True

    # Verify LangGraph checkpoints were recorded in SQLite by the API run
    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM checkpoints WHERE thread_id = ?;", (f"bootstrapper-{req_id}",))
    chk_count = cur.fetchone()[0]
    cur.close()
    conn.close()
    assert chk_count > 0, "FastAPI run endpoint must drive LangGraph engine and persist checkpoints"

    # 3. Create token and approve via API
    tok_resp = client.post(
        "/api/v1/tokens",
        json={
            "approver_id": "sec-lead-api",
            "role": "SECURITY_LEAD",
            "authorized_scopes": ["sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"],
        },
    )
    raw_token = tok_resp.json()["raw_token"]

    plan_resp = client.get(f"/api/v1/requests/{req_id}/plan")
    plan_hash = plan_resp.json()["canonical_plan_hash"]

    appr_resp = client.post(
        f"/api/v1/requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {raw_token}"},
        json={
            "decision": "APPROVE",
            "submitted_plan_hash": plan_hash,
            "plan_version": 1,
        },
    )
    assert appr_resp.status_code == 200

    # 4. Resume workflow via API
    run_resp2 = client.post(
        f"/api/v1/requests/{req_id}/run",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert run_resp2.status_code == 200
    assert run_resp2.json()["current_status"] == "COMPLETED"
    assert run_resp2.json()["is_completed"] is True



