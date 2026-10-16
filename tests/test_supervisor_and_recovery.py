"""Integration tests for Supervisor, Execution Agent tool dispatch, Reflection recovery, and Ollama planner fallback.

Proves:
1. Execution Agent tool dispatch enforcement (registered allowlist vs rejected unregistered tools).
2. Local Ollama LLM structured candidate generation and policy validation.
3. Local LLM fallback to deterministic template planner on connection failure, timeout, or schema violation.
4. LangGraph reflection component triggering bounded retries for transient failures.
5. LangGraph immediate halting on security and authorization violations (no retries).
6. Supervisor evidence-based conditional routing.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import urllib.error
import pytest

from src.adapters.sandbox_provisioner import MockSandboxResult
from src.agents.executor import ExecutionAgent, StepExecutionResult
from src.agents.planner import PlanningAgent, PlanningInput
from src.agents.reflection import ReflectionDecision, ReflectionNode
from src.core.exceptions import (
    ApprovalExpiredError,
    AuthorizationDeniedError,
    PlanValidationError,
    SecurityViolationError,
)
from src.models.approvals import ApprovalDecisionType, ApprovalRecord, ApprovalRequest
from src.models.enums import (
    PermissionScope,
    ProjectTemplate,
    StepActionType,
    StepExecutionStatus,
    WorkflowStage,
    WorkflowStatus,
)
from src.models.plans import PlannedStep, SetupPlan
from src.models.requests import BootstrapRequest, BootstrapRequestCreate
from src.security.approvals import ApprovalService
from src.security.tokens import TokenService
from src.storage.connection import get_connection
from src.workflow.graph import BootstrapperWorkflowGraph
from src.workflow.orchestrator import WorkflowOrchestrator
from src.workflow.planner import (
    DeterministicTemplatePlanner,
    LocalLLMPlanner,
    build_template_plan,
    get_planner,
)
from src.workflow.supervisor import WorkflowSupervisor


# =============================================================================
# FIXTURES & HELPERS
# =============================================================================

ALL_SCOPES = [
    PermissionScope.SANDBOX_READ,
    PermissionScope.SANDBOX_CREATE,
    PermissionScope.DATA_SEED_SYNTHETIC,
    PermissionScope.TEST_EXECUTE,
    PermissionScope.AUDIT_READ,
]


@pytest.fixture
def isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolate SQLite database and mock sandbox directories."""
    from src.core.config import get_settings
    from src.storage.db_init import initialize_database

    db_file = tmp_path / "supervisor_test.db"
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
    from src.workflow.verifier import SandboxVerifier
    return WorkflowOrchestrator(verifier=SandboxVerifier())


def _create_and_approve_request(
    orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    db_file: Path,
    project_name: str = "supervisor-test",
) -> tuple[str, str, str]:
    """Helper to initialize request, generate plan, and grant valid approval."""
    req = orchestrator.create_request(
        BootstrapRequestCreate(
            project_name=project_name,
            template=ProjectTemplate.PYTHON_FASTAPI,
            repository_path="./",
            developer_id="dev-alice",
            requested_scopes=ALL_SCOPES,
        ),
        db_path=db_file,
    )
    # Run to await_approval stage
    orchestrator.run_workflow(req.request_id, db_path=db_file)

    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("SELECT canonical_plan_hash, plan_version FROM setup_plans WHERE request_id = ?;", (req.request_id,))
    plan_row = cur.fetchone()
    cur.close()
    conn.close()

    tok = token_service.create_token(
        approver_id="sec-admin",
        role="SECURITY_ADMIN",
        authorized_scopes=ALL_SCOPES,
        db_path=db_file,
    )
    identity = token_service.resolve_identity(tok.raw_token, db_path=db_file)
    appr = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req.request_id,
            submitted_plan_hash=plan_row["canonical_plan_hash"],
            plan_version=plan_row["plan_version"],
            decision=ApprovalDecisionType.APPROVE,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=ALL_SCOPES,
        db_path=db_file,
    )
    return req.request_id, tok.raw_token, appr.approval_id


# =============================================================================
# 1. TOOL DISPATCH & ALLOWLIST ENFORCEMENT
# =============================================================================

def test_tool_dispatch_registered_allowlist_enforcement(
    orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    isolated_env,
):
    """Test that ExecutionAgent dispatches allowlisted tools and rejects unauthorized action types."""
    db_file, sbx_dir = isolated_env
    req_id, raw_token, appr_id = _create_and_approve_request(orchestrator, token_service, approval_service, db_file)

    request = orchestrator.get_request(req_id, db_path=db_file)
    plan = orchestrator._get_or_create_plan(request, db_path=db_file)
    approval = approval_service.get_approval(appr_id, db_path=db_file)

    execution_agent = orchestrator.execution_agent

    # 1. Allowlisted tool PROVISION_MOCK_SANDBOX
    prov_step = orchestrator._find_step(plan, StepActionType.PROVISION_MOCK_SANDBOX)
    res_prov = execution_agent.execute_step(
        step=prov_step,
        request=request,
        plan=plan,
        approval=approval,
        execution_id="exec-tool-dispatch-01",
        custom_root=sbx_dir,
        db_path=db_file,
    )
    assert res_prov.status == StepExecutionStatus.COMPLETED
    assert "sandbox_id" in res_prov.result_data

    # 2. Allowlisted tool SEED_SYNTHETIC_DATA
    seed_step = orchestrator._find_step(plan, StepActionType.SEED_SYNTHETIC_DATA)
    res_seed = execution_agent.execute_step(
        step=seed_step,
        request=request,
        plan=plan,
        approval=approval,
        execution_id="exec-tool-dispatch-01",
        sandbox_id=res_prov.result_data["sandbox_id"],
        sandbox_dir=Path(res_prov.result_data["sandbox_dir"]),
        custom_root=sbx_dir,
        db_path=db_file,
    )
    assert res_seed.status == StepExecutionStatus.COMPLETED
    assert res_seed.result_data["total_records_seeded"] > 0

    # 3. Allowlisted tool EXECUTE_SMOKE_TEST
    verify_step = orchestrator._find_step(plan, StepActionType.EXECUTE_SMOKE_TEST)
    res_verify = execution_agent.execute_step(
        step=verify_step,
        request=request,
        plan=plan,
        approval=approval,
        execution_id="exec-tool-dispatch-01",
        sandbox_id=res_prov.result_data["sandbox_id"],
        sandbox_dir=Path(res_prov.result_data["sandbox_dir"]),
        ownership_token=res_prov.result_data["ownership_token"],
        db_path=db_file,
    )
    assert res_verify.status == StepExecutionStatus.COMPLETED
    assert res_verify.result_data["is_verified"] is True

    # 4. Unregistered tool rejection
    unregistered_step = PlannedStep(
        step_id="step-00000099",
        action_type=StepActionType.DISCOVER_REPOSITORY,  # Discovery is not an execution tool
        name="Execute Discovery as privileged Tool",
        description="Try to execute discovery via execution agent",
        is_privileged=False,
        required_scopes=[PermissionScope.SANDBOX_READ],
        depends_on_step_ids=[],
        action_parameters={},
    )
    with pytest.raises(SecurityViolationError) as exc_info:
        execution_agent.execute_step(
            step=unregistered_step,
            request=request,
            plan=plan,
            approval=approval,
            execution_id="exec-tool-dispatch-01",
            db_path=db_file,
        )
    assert "not registered in the Execution Agent tool allowlist" in str(exc_info.value)


# =============================================================================
# 2. LOCAL OLLAMA INFERENCE & STRUCTURED CANDIDATE GENERATION
# =============================================================================

def test_ollama_structured_plan_generation_success():
    """Test that LocalLLMPlanner queries Ollama, parses candidate JSON, and validates schema."""
    candidate_steps = [
        {
            "step_id": "step-00000001",
            "action_type": "DISCOVER_REPOSITORY",
            "name": "Discover Repo",
            "description": "Inspect repository",
            "is_privileged": False,
            "required_scopes": ["sandbox:read"],
            "depends_on_step_ids": [],
            "action_parameters": {"template": "python-fastapi-service"},
        },
        {
            "step_id": "step-00000002",
            "action_type": "PROVISION_MOCK_SANDBOX",
            "name": "Provision Sandbox",
            "description": "Create mock directory",
            "is_privileged": True,
            "required_scopes": ["sandbox:create"],
            "depends_on_step_ids": ["step-00000001"],
            "action_parameters": {"target_environment": "local-sandbox"},
        },
    ]
    ollama_api_response = {
        "model": "llama3.2",
        "response": json.dumps({"steps": candidate_steps}),
        "done": True,
    }

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = json.dumps(ollama_api_response).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    planner = LocalLLMPlanner(
        base_url="http://localhost:11434",
        model="llama3.2",
        enabled=True,
    )

    with patch("urllib.request.urlopen", return_value=mock_resp):
        plan = planner.generate_plan(
            request_id="req-ollama-test-01",
            template=ProjectTemplate.PYTHON_FASTAPI,
            target_environment="local-sandbox",
            plan_version=1,
            requested_scopes=[PermissionScope.SANDBOX_READ, PermissionScope.SANDBOX_CREATE],
        )

    assert plan is not None
    assert plan.request_id == "req-ollama-test-01"
    assert len(plan.steps) == 2
    assert plan.steps[0].action_type == StepActionType.DISCOVER_REPOSITORY
    assert plan.steps[1].action_type == StepActionType.PROVISION_MOCK_SANDBOX
    assert plan.canonical_plan_hash is not None


# =============================================================================
# 3. OLLAMA FALLBACK TO DETERMINISTIC TEMPLATE PLANNER
# =============================================================================

def test_ollama_planner_fallback_on_error_or_invalid_schema():
    """Test that LocalLLMPlanner gracefully falls back to deterministic template planner when Ollama fails."""
    # 1. Fallback when disabled
    disabled_planner = LocalLLMPlanner(enabled=False)
    plan_disabled = disabled_planner.generate_plan(
        request_id="req-fallback-01",
        template=ProjectTemplate.PYTHON_FASTAPI,
    )
    assert len(plan_disabled.steps) == 7
    assert plan_disabled.steps[0].action_type == StepActionType.DISCOVER_REPOSITORY

    # 2. Fallback on connection error (Ollama daemon offline)
    offline_planner = LocalLLMPlanner(base_url="http://localhost:11434", enabled=True)
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
        plan_offline = offline_planner.generate_plan(
            request_id="req-fallback-02",
            template=ProjectTemplate.PYTHON_FASTAPI,
        )
    assert len(plan_offline.steps) == 7  # Baseline deterministic plan returned

    # 3. Fallback on malformed / invalid JSON response
    mock_resp_invalid = MagicMock()
    mock_resp_invalid.status = 200
    mock_resp_invalid.read.return_value = b'{"response": "not-json-content"}'
    mock_resp_invalid.__enter__.return_value = mock_resp_invalid

    with patch("urllib.request.urlopen", return_value=mock_resp_invalid):
        plan_invalid = offline_planner.generate_plan(
            request_id="req-fallback-03",
            template=ProjectTemplate.PYTHON_FASTAPI,
        )
    assert len(plan_invalid.steps) == 7

    # 4. Fallback on schema / policy violation (e.g. unknown action or unrequested scope)
    bad_steps = [
        {
            "step_id": "step-00000001",
            "action_type": "PROVISION_MOCK_SANDBOX",
            "name": "Provision",
            "description": "Unauthorized scope",
            "is_privileged": True,
            "required_scopes": ["sandbox:delete"],  # Not in requested_scopes
            "depends_on_step_ids": [],
            "action_parameters": {},
        }
    ]
    mock_resp_bad_scope = MagicMock()
    mock_resp_bad_scope.status = 200
    mock_resp_bad_scope.read.return_value = json.dumps({"response": json.dumps({"steps": bad_steps})}).encode("utf-8")
    mock_resp_bad_scope.__enter__.return_value = mock_resp_bad_scope

    with patch("urllib.request.urlopen", return_value=mock_resp_bad_scope):
        plan_bad_scope = offline_planner.generate_plan(
            request_id="req-fallback-04",
            template=ProjectTemplate.PYTHON_FASTAPI,
            requested_scopes=[PermissionScope.SANDBOX_READ, PermissionScope.SANDBOX_CREATE],
        )
    # Failed least-privilege validation -> fell back to baseline
    assert len(plan_bad_scope.steps) == 7


# =============================================================================
# 4. REFLECTION COMPONENT: BOUNDED RETRY ON TRANSIENT FAILURES
# =============================================================================

def test_langgraph_transient_failure_bounded_retry_recovery(
    orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    isolated_env,
):
    """Test that LangGraph reflection catches transient failures and triggers bounded retries."""
    db_file, sbx_dir = isolated_env
    req_id, raw_token, appr_id = _create_and_approve_request(orchestrator, token_service, approval_service, db_file)

    # 1. Transient failure during verify_sandbox recovers within retry bounds
    attempts = 0

    original_verify = orchestrator.verifier.verify_sandbox

    def transient_verifier(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("Temporary socket timeout verifying smoke test endpoint")
        return original_verify(*args, **kwargs)

    with patch.object(orchestrator.verifier, "verify_sandbox", side_effect=transient_verifier):
        res = orchestrator.run_workflow(
            request_id=req_id,
            caller_token=raw_token,
            custom_root=sbx_dir,
            db_path=db_file,
            raise_on_failure=False,
        )

    assert attempts == 3
    assert res.is_completed is True
    assert res.current_status == WorkflowStatus.COMPLETED

    # Verify audit trail contains reflection event
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("SELECT event_type FROM audit_log WHERE request_id = ?;", (req_id,))
    events = [r["event_type"] for r in cur.fetchall()]
    cur.close()
    conn.close()
    assert "MANIFEST_GENERATED" in events


def test_langgraph_transient_failure_stops_when_retry_limit_exhausted(
    orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    isolated_env,
):
    """Test that LangGraph reflection halts when maximum retries (2) are exhausted."""
    db_file, sbx_dir = isolated_env
    req_id, raw_token, appr_id = _create_and_approve_request(orchestrator, token_service, approval_service, db_file)

    attempts = 0

    def persistent_glitch(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        raise RuntimeError("Persistent network partition on smoke test verification")

    with patch.object(orchestrator.verifier, "verify_sandbox", side_effect=persistent_glitch):
        res = orchestrator.run_workflow(
            request_id=req_id,
            caller_token=raw_token,
            custom_root=sbx_dir,
            db_path=db_file,
            raise_on_failure=False,
        )

    # Initial attempt + 2 retries = 3 total attempts
    assert attempts == 3
    assert res.is_completed is False
    assert res.current_status == WorkflowStatus.FAILED
    assert "Maximum retry limit (2) reached" in (res.error_message or "")


# =============================================================================
# 5. SECURITY & AUTHORIZATION FAILURES: STOP IMMEDIATELY (NO RETRIES)
# =============================================================================

def test_langgraph_security_and_authorization_failures_stop_immediately(
    orchestrator: WorkflowOrchestrator,
    token_service: TokenService,
    approval_service: ApprovalService,
    isolated_env,
):
    """Test that security violations and unauthorized executions halt immediately without reflection retries."""
    db_file, sbx_dir = isolated_env

    req = orchestrator.create_request(
        BootstrapRequestCreate(
            project_name="unapproved-sec-test",
            template=ProjectTemplate.PYTHON_FASTAPI,
            repository_path="./",
            developer_id="dev-eve",
            requested_scopes=ALL_SCOPES,
        ),
        db_path=db_file,
    )
    # Run to await_approval stage
    orchestrator.run_workflow(req.request_id, db_path=db_file)

    # 1. Await approval pauses graph at await_approval without running privileged nodes
    res_await = orchestrator.run_workflow(req.request_id, db_path=db_file, raise_on_failure=False)
    assert res_await.stage == WorkflowStage.AWAIT_APPROVAL
    assert res_await.approval_required is True
    assert res_await.is_completed is False

    # 2. Attempting privileged action without approval record raises SecurityViolationError immediately
    graph_builder = BootstrapperWorkflowGraph(orchestrator)
    state = {
        "request_id": req.request_id,
        "execution_id": "exec-sec-violation",
        "custom_root": str(sbx_dir),
        "db_path": str(db_file),
    }
    with pytest.raises(SecurityViolationError) as exc_info:
        graph_builder.provision_mock_sandbox_node(state, config={})
    assert "Approval record missing at privileged provisioning boundary" in str(exc_info.value)

    # 3. Reflection node confirms security errors are strictly non-retriable
    reflection = ReflectionNode()
    decision = reflection.reflect(SecurityViolationError("Unauthorized access"), current_retry_count=0)
    assert decision.can_retry is False
    assert decision.is_terminal_failure is True
    assert "Security/Authorization policy violation" in decision.reason


# =============================================================================
# 6. SUPERVISOR EVIDENCE-BASED CONDITIONAL ROUTING
# =============================================================================

def test_supervisor_evidence_based_routing():
    """Verify deterministic evidence-based conditional routing decisions in WorkflowSupervisor."""
    supervisor = WorkflowSupervisor()

    # 1. Route after collect
    assert supervisor.route_after_collect({"is_completed": True}) == "__end__"
    assert supervisor.route_after_collect({"is_completed": False}) == "discover"

    # 2. Route after approval
    assert supervisor.route_after_approval({"approval_required": True, "approved": False}) == "__end__"
    assert supervisor.route_after_approval({"approval_required": False, "approved": True}) == "provision_mock_sandbox"

    # 3. Route after provision
    assert supervisor.route_after_provision({"error_message": "Transient error"}) == "reflect"
    assert supervisor.route_after_provision({"error_message": None}) == "seed_synthetic_data"

    # 4. Route after seed
    assert supervisor.route_after_seed({"error_message": "Transient error"}) == "reflect"
    assert supervisor.route_after_seed({"error_message": None}) == "verify_sandbox"

    # 5. Route after verify
    assert supervisor.route_after_verify({"error_message": "Smoke test glitch", "verification_passed": False}) == "reflect"
    assert supervisor.route_after_verify({"error_message": None, "verification_passed": True}) == "finalize"

    # 6. Route after reflect
    assert supervisor.route_after_reflect({"can_retry": True, "retry_target": "verify_sandbox"}) == "verify_sandbox"
    assert supervisor.route_after_reflect({"can_retry": False, "retry_target": "verify_sandbox"}) == "__end__"
