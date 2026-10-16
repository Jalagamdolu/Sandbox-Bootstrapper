"""LangGraph workflow definition for the Developer Sandbox Bootstrapper.

Integrates StateGraph with typed workflow state, durable local SQLite checkpointing,
server-side security checks, and 10 coordinated lifecycle stages.
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, Optional, TypedDict

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langchain_core.runnables import RunnableConfig

from src.core.exceptions import (
    ApprovalExpiredError,
    ApprovalRevokedError,
    AuthorizationDeniedError,
    PathTraversalError,
    PlanTamperingError,
    SecurityViolationError,
    TokenScopeError,
)
from src.models.audit import AuditActor
from src.models.enums import (
    AuditEventType,
    AuditSeverity,
    StepActionType,
    StepExecutionStatus,
    WorkflowStage,
    WorkflowStatus,
)
from src.storage.connection import resolve_db_path
from src.workflow.discovery import discover_local_repository, discover_mock_dashboard
from src.workflow.planner import validate_plan
from src.workflow.supervisor import WorkflowSupervisor
from src.agents.reflection import ReflectionNode


class WorkflowGraphState(TypedDict, total=False):
    """Typed dictionary representing the LangGraph workflow state."""

    request_id: str
    execution_id: str
    current_status: str
    stage: str
    is_completed: bool
    approval_required: bool
    custom_root: Optional[str]
    db_path: Optional[str]

    # Discovery
    detected_framework: Optional[str]
    config_files_found: list[str]
    mock_network: Optional[str]

    # Planning
    plan_id: Optional[str]
    plan_version: Optional[int]
    canonical_plan_hash: Optional[str]
    step_count: Optional[int]

    # Approval
    approval_id: Optional[str]
    approver_id: Optional[str]
    approved: bool

    # Sandbox & Seeding
    sandbox_id: Optional[str]
    sandbox_dir: Optional[str]
    ownership_token: Optional[str]
    cleanup_deadline: Optional[str]
    expected_fixtures: list[str]
    seeded_fixtures: list[str]

    # Verification & Finalization
    verification_passed: bool
    fixtures_verified: list[str]
    manifest_sha256: Optional[str]
    step_results: dict[str, str]

    # Error status & Reflection
    error_message: Optional[str]
    error_category: Optional[str]
    retry_count: int
    can_retry: bool
    retry_target: Optional[str]
    is_terminal_failure: bool


def get_sqlite_checkpointer(db_path: Path | str | None = None) -> SqliteSaver:
    """Create and initialize a durable SQLite checkpointer for LangGraph."""
    target_path = resolve_db_path(db_path)
    if str(target_path) == ":memory:":
        conn = sqlite3.connect("file:mem_lg_checkpoints?mode=memory&cache=shared", uri=True, check_same_thread=False)
    else:
        conn = sqlite3.connect(str(target_path), check_same_thread=False)

    checkpointer = SqliteSaver(conn)
    checkpointer.setup()
    return checkpointer


class BootstrapperWorkflowGraph:
    """Encapsulates LangGraph graph construction and node execution."""

    def __init__(self, orchestrator: Any) -> None:
        self.orchestrator = orchestrator
        self.supervisor = WorkflowSupervisor()
        self.reflection_node = ReflectionNode()

    def collect_request_node(self, state: WorkflowGraphState) -> dict[str, Any]:
        """STAGE 1: COLLECT_REQUEST."""
        req_id = state["request_id"]
        db_path = state.get("db_path")
        request = self.orchestrator.get_request(req_id, db_path=db_path)

        if request.status == WorkflowStatus.COMPLETED:
            return {
                "stage": WorkflowStage.FINALIZE.value,
                "current_status": WorkflowStatus.COMPLETED.value,
                "is_completed": True,
                "approval_required": False,
            }

        return {
            "stage": WorkflowStage.COLLECT_REQUEST.value,
            "current_status": request.status.value,
            "is_completed": False,
        }

    def route_after_collect(self, state: WorkflowGraphState) -> str:
        """Route to END if already completed, else continue to DISCOVER via Supervisor."""
        return self.supervisor.route_after_collect(state)

    def discover_node(self, state: WorkflowGraphState) -> dict[str, Any]:
        """STAGE 2: DISCOVER."""
        req_id = state["request_id"]
        db_path = state.get("db_path")
        exec_id = state.get("execution_id", "")
        request = self.orchestrator.get_request(req_id, db_path=db_path)

        self.orchestrator._update_request_status(request.request_id, WorkflowStatus.DISCOVERY_IN_PROGRESS, db_path=db_path)
        repo_discovery = discover_local_repository(request.repository_path)
        dash_discovery = discover_mock_dashboard()

        self.orchestrator.audit_service.append_event(
            request_id=request.request_id,
            event_type=AuditEventType.DISCOVERY_COMPLETED,
            severity=AuditSeverity.INFO,
            actor=AuditActor(actor_id=request.developer_id, role="DEVELOPER"),
            action_name="DISCOVER",
            details={
                "framework": repo_discovery.detected_framework,
                "config_files": repo_discovery.config_files_found,
                "mock_network": dash_discovery.mock_network_range,
            },
            state_before=WorkflowStatus.DRAFT,
            state_after=WorkflowStatus.DISCOVERY_IN_PROGRESS,
            db_path=db_path,
        )
        self.orchestrator._save_checkpoint(
            request.request_id,
            WorkflowStatus.DISCOVERY_IN_PROGRESS,
            WorkflowStage.DISCOVER,
            {"framework": repo_discovery.detected_framework, "execution_id": exec_id},
            db_path=db_path,
        )
        return {
            "stage": WorkflowStage.DISCOVER.value,
            "current_status": WorkflowStatus.DISCOVERY_IN_PROGRESS.value,
            "detected_framework": repo_discovery.detected_framework,
            "config_files_found": repo_discovery.config_files_found,
            "mock_network": dash_discovery.mock_network_range,
        }

    def build_plan_node(self, state: WorkflowGraphState) -> dict[str, Any]:
        """STAGE 3: BUILD_PLAN."""
        req_id = state["request_id"]
        db_path = state.get("db_path")
        exec_id = state.get("execution_id", "")
        request = self.orchestrator.get_request(req_id, db_path=db_path)

        self.orchestrator._update_request_status(request.request_id, WorkflowStatus.PLANNING, db_path=db_path)
        plan = self.orchestrator._get_or_create_plan(request, db_path=db_path)

        self.orchestrator.audit_service.append_event(
            request_id=request.request_id,
            event_type=AuditEventType.PLAN_GENERATED,
            severity=AuditSeverity.INFO,
            actor=AuditActor(actor_id="planner", role="SYSTEM"),
            action_name="BUILD_PLAN",
            details={
                "plan_id": plan.plan_id,
                "plan_version": plan.plan_version,
                "canonical_plan_hash": plan.canonical_plan_hash,
                "step_count": len(plan.steps),
            },
            state_before=WorkflowStatus.DISCOVERY_IN_PROGRESS,
            state_after=WorkflowStatus.PLANNING,
            db_path=db_path,
        )
        self.orchestrator._save_checkpoint(
            request.request_id,
            WorkflowStatus.PLANNING,
            WorkflowStage.BUILD_PLAN,
            {"plan_id": plan.plan_id, "canonical_plan_hash": plan.canonical_plan_hash, "execution_id": exec_id},
            db_path=db_path,
        )
        return {
            "stage": WorkflowStage.BUILD_PLAN.value,
            "current_status": WorkflowStatus.PLANNING.value,
            "plan_id": plan.plan_id,
            "plan_version": plan.plan_version,
            "canonical_plan_hash": plan.canonical_plan_hash,
            "step_count": len(plan.steps),
        }

    def validate_plan_node(self, state: WorkflowGraphState) -> dict[str, Any]:
        """STAGE 4: VALIDATE_PLAN."""
        req_id = state["request_id"]
        db_path = state.get("db_path")
        exec_id = state.get("execution_id", "")
        request = self.orchestrator.get_request(req_id, db_path=db_path)
        plan = self.orchestrator._get_or_create_plan(request, db_path=db_path)

        validate_plan(plan, request.requested_scopes)
        self.orchestrator._save_checkpoint(
            request.request_id,
            WorkflowStatus.PLANNING,
            WorkflowStage.VALIDATE_PLAN,
            {"validation": "PASSED", "execution_id": exec_id},
            db_path=db_path,
        )
        return {"stage": WorkflowStage.VALIDATE_PLAN.value}

    def generate_manifest_node(self, state: WorkflowGraphState) -> dict[str, Any]:
        """STAGE 5: GENERATE_MANIFEST (Draft)."""
        req_id = state["request_id"]
        db_path = state.get("db_path")
        exec_id = state.get("execution_id", "")
        request = self.orchestrator.get_request(req_id, db_path=db_path)
        plan = self.orchestrator._get_or_create_plan(request, db_path=db_path)

        self.orchestrator._update_request_status(request.request_id, WorkflowStatus.PENDING_APPROVAL, db_path=db_path)
        self.orchestrator.audit_service.append_event(
            request_id=request.request_id,
            event_type=AuditEventType.APPROVAL_REQUESTED,
            severity=AuditSeverity.INFO,
            actor=AuditActor(actor_id=request.developer_id, role="DEVELOPER"),
            action_name="GENERATE_MANIFEST",
            details={
                "plan_hash": plan.canonical_plan_hash,
                "target_environment": plan.target_environment,
            },
            state_before=WorkflowStatus.PLANNING,
            state_after=WorkflowStatus.PENDING_APPROVAL,
            db_path=db_path,
        )
        self.orchestrator._save_checkpoint(
            request.request_id,
            WorkflowStatus.PENDING_APPROVAL,
            WorkflowStage.GENERATE_MANIFEST,
            {"plan_hash": plan.canonical_plan_hash, "execution_id": exec_id},
            db_path=db_path,
        )
        return {
            "stage": WorkflowStage.GENERATE_MANIFEST.value,
            "current_status": WorkflowStatus.PENDING_APPROVAL.value,
        }

    def await_approval_node(self, state: WorkflowGraphState) -> dict[str, Any]:
        """STAGE 6: AWAIT_APPROVAL."""
        req_id = state["request_id"]
        db_path = state.get("db_path")
        exec_id = state.get("execution_id", "")
        request = self.orchestrator.get_request(req_id, db_path=db_path)
        plan = self.orchestrator._get_or_create_plan(request, db_path=db_path)

        approval_record = self.orchestrator._check_approval(request, plan, db_path=db_path)

        if approval_record is None:
            return {
                "stage": WorkflowStage.AWAIT_APPROVAL.value,
                "current_status": WorkflowStatus.PENDING_APPROVAL.value,
                "approval_required": True,
                "approved": False,
                "error_message": "Workflow paused awaiting human approval.",
            }

        self.orchestrator._update_request_status(request.request_id, WorkflowStatus.APPROVED, db_path=db_path)
        self.orchestrator._save_checkpoint(
            request.request_id,
            WorkflowStatus.APPROVED,
            WorkflowStage.AWAIT_APPROVAL,
            {"approval_id": approval_record.approval_id, "execution_id": exec_id},
            db_path=db_path,
        )
        return {
            "stage": WorkflowStage.AWAIT_APPROVAL.value,
            "current_status": WorkflowStatus.APPROVED.value,
            "approval_required": False,
            "approved": True,
            "approval_id": approval_record.approval_id,
            "approver_id": approval_record.approver_id,
            "error_message": None,
        }

    def route_after_approval(self, state: WorkflowGraphState) -> str:
        """Route to END if approval is required/unapproved, else proceed to PROVISION via Supervisor."""
        return self.supervisor.route_after_approval(state)

    def route_after_provision(self, state: WorkflowGraphState) -> str:
        """Route to reflect if provisioning had transient failure, else seed via Supervisor."""
        return self.supervisor.route_after_provision(state)

    def route_after_seed(self, state: WorkflowGraphState) -> str:
        """Route to reflect if seeding had transient failure, else verify via Supervisor."""
        return self.supervisor.route_after_seed(state)

    def route_after_verify(self, state: WorkflowGraphState) -> str:
        """Route to finalize if verification passed, else reflect via Supervisor."""
        return self.supervisor.route_after_verify(state)

    def route_after_reflect(self, state: WorkflowGraphState) -> str:
        """Route back to retry target if can_retry, else terminate at END via Supervisor."""
        return self.supervisor.route_after_reflect(state)

    def provision_mock_sandbox_node(self, state: WorkflowGraphState, config: RunnableConfig) -> dict[str, Any]:
        """STAGE 7: PROVISION_MOCK_SANDBOX (dispatches via Execution Agent)."""
        req_id = state["request_id"]
        db_path = state.get("db_path")
        exec_id = state.get("execution_id", "")
        configurable = config.get("configurable", {}) if config else {}
        caller_token = configurable.get("caller_token")
        custom_root = state.get("custom_root")
        request = self.orchestrator.get_request(req_id, db_path=db_path)
        plan = self.orchestrator._get_or_create_plan(request, db_path=db_path)
        approval_record = self.orchestrator._check_approval(request, plan, db_path=db_path)
        if approval_record is None:
            raise SecurityViolationError("Approval record missing at privileged provisioning boundary.")

        step = self.orchestrator._find_step(plan, StepActionType.PROVISION_MOCK_SANDBOX)
        if step is None:
            raise SecurityViolationError("Provisioning step missing in plan.")

        self.orchestrator._update_request_status(request.request_id, WorkflowStatus.PROVISIONING, db_path=db_path)

        try:
            exec_res = self.orchestrator.execution_agent.execute_step(
                step=step,
                request=request,
                plan=plan,
                approval=approval_record,
                execution_id=exec_id,
                caller_token=caller_token,
                custom_root=Path(custom_root) if custom_root else None,
                db_path=db_path,
            )
            if exec_res.status == StepExecutionStatus.FAILED:
                return {
                    "stage": WorkflowStage.PROVISION_MOCK_SANDBOX.value,
                    "error_message": exec_res.error_message or "Provisioning failed",
                    "error_category": "TransientExecutionError",
                    "retry_target": "provision_mock_sandbox",
                }

            res_data = exec_res.result_data
            sandbox_id = res_data.get("sandbox_id")
            sandbox_dir = res_data.get("sandbox_dir")
            ownership_token = res_data.get("ownership_token")
            cleanup_deadline = res_data.get("cleanup_deadline")

            if "skipped_as_already_completed" in res_data or not sandbox_id:
                from src.core.config import get_settings
                settings = get_settings()
                sandbox_root = Path(custom_root or settings.sandbox_storage_dir).resolve()
                tracked = self.orchestrator._find_tracked_sandbox(
                    request.request_id,
                    sandbox_root,
                    db_path=db_path,
                )
                if tracked:
                    sandbox_id = tracked.sandbox_id
                    sandbox_dir = str(tracked.sandbox_dir)
                    ownership_token = tracked.ownership_token
                    cleanup_deadline = tracked.expires_at.isoformat() if hasattr(tracked, "expires_at") else None

            self.orchestrator._save_checkpoint(
                request.request_id,
                WorkflowStatus.PROVISIONED,
                WorkflowStage.PROVISION_MOCK_SANDBOX,
                {"sandbox_id": sandbox_id, "execution_id": exec_id},
                db_path=db_path,
            )
            return {
                "stage": WorkflowStage.PROVISION_MOCK_SANDBOX.value,
                "current_status": WorkflowStatus.PROVISIONED.value,
                "sandbox_id": sandbox_id,
                "sandbox_dir": str(sandbox_dir),
                "ownership_token": ownership_token,
                "cleanup_deadline": cleanup_deadline,
                "error_message": None,
                "error_category": None,
            }
        except (
            AuthorizationDeniedError,
            ApprovalExpiredError,
            ApprovalRevokedError,
            SecurityViolationError,
            PlanTamperingError,
            TokenScopeError,
            PathTraversalError,
        ):
            # Security violations stop immediately
            raise
        except Exception as exc:
            err_lower = str(exc).lower()
            if any(kw in err_lower for kw in ReflectionNode.NON_RETRIABLE_KEYWORDS):
                raise
            return {
                "stage": WorkflowStage.PROVISION_MOCK_SANDBOX.value,
                "error_message": str(exc),
                "error_category": exc.__class__.__name__,
                "retry_target": "provision_mock_sandbox",
            }

    def seed_synthetic_data_node(self, state: WorkflowGraphState, config: RunnableConfig) -> dict[str, Any]:
        """STAGE 8: SEED_SYNTHETIC_DATA (dispatches via Execution Agent)."""
        req_id = state["request_id"]
        db_path = state.get("db_path")
        exec_id = state.get("execution_id", "")
        configurable = config.get("configurable", {}) if config else {}
        caller_token = configurable.get("caller_token")
        custom_root = state.get("custom_root")
        request = self.orchestrator.get_request(req_id, db_path=db_path)
        plan = self.orchestrator._get_or_create_plan(request, db_path=db_path)
        approval_record = self.orchestrator._check_approval(request, plan, db_path=db_path)
        if approval_record is None:
            raise SecurityViolationError("Approval record missing at privileged data seeding boundary.")

        sandbox_id = state.get("sandbox_id")
        sandbox_dir_str = state.get("sandbox_dir")
        if not sandbox_id or not sandbox_dir_str:
            from src.core.config import get_settings
            settings = get_settings()
            sandbox_root = Path(custom_root or settings.sandbox_storage_dir).resolve()
            tracked = self.orchestrator._find_tracked_sandbox(
                request.request_id,
                sandbox_root,
                db_path=db_path,
            )
            if tracked:
                sandbox_id = tracked.sandbox_id
                sandbox_dir_str = str(tracked.sandbox_dir)

        sandbox_dir = Path(sandbox_dir_str)

        step = self.orchestrator._find_step(plan, StepActionType.SEED_SYNTHETIC_DATA)
        if step is None:
            raise SecurityViolationError("Seeding step missing in plan.")

        expected_fixtures = (
            step.action_parameters.get("fixtures", ["users.json", "teams.json", "projects.json", "configs.json"])
            if step
            else ["users.json", "teams.json", "projects.json", "configs.json"]
        )

        self.orchestrator._update_request_status(request.request_id, WorkflowStatus.SEEDING, db_path=db_path)

        try:
            exec_res = self.orchestrator.execution_agent.execute_step(
                step=step,
                request=request,
                plan=plan,
                approval=approval_record,
                execution_id=exec_id,
                sandbox_id=sandbox_id,
                sandbox_dir=sandbox_dir,
                caller_token=caller_token,
                custom_root=Path(custom_root) if custom_root else None,
                db_path=db_path,
            )
            if exec_res.status == StepExecutionStatus.FAILED:
                return {
                    "stage": WorkflowStage.SEED_SYNTHETIC_DATA.value,
                    "error_message": exec_res.error_message or "Seeding failed",
                    "error_category": "TransientExecutionError",
                    "retry_target": "seed_synthetic_data",
                }

            self.orchestrator._save_checkpoint(
                request.request_id,
                WorkflowStatus.SEEDED,
                WorkflowStage.SEED_SYNTHETIC_DATA,
                {"sandbox_id": sandbox_id, "fixtures": expected_fixtures, "execution_id": exec_id},
                db_path=db_path,
            )
            return {
                "stage": WorkflowStage.SEED_SYNTHETIC_DATA.value,
                "current_status": WorkflowStatus.SEEDED.value,
                "expected_fixtures": expected_fixtures,
                "seeded_fixtures": expected_fixtures,
                "error_message": None,
                "error_category": None,
            }
        except (
            AuthorizationDeniedError,
            ApprovalExpiredError,
            ApprovalRevokedError,
            SecurityViolationError,
            PlanTamperingError,
            TokenScopeError,
            PathTraversalError,
        ):
            # Security violations stop immediately
            raise
        except Exception as exc:
            err_lower = str(exc).lower()
            if any(kw in err_lower for kw in ReflectionNode.NON_RETRIABLE_KEYWORDS):
                raise
            return {
                "stage": WorkflowStage.SEED_SYNTHETIC_DATA.value,
                "error_message": str(exc),
                "error_category": exc.__class__.__name__,
                "retry_target": "seed_synthetic_data",
            }

    def verify_sandbox_node(self, state: WorkflowGraphState) -> dict[str, Any]:
        """STAGE 9: VERIFY_SANDBOX."""
        req_id = state["request_id"]
        db_path = state.get("db_path")
        exec_id = state.get("execution_id", "")
        request = self.orchestrator.get_request(req_id, db_path=db_path)

        sandbox_id = state.get("sandbox_id")
        sandbox_dir_str = state.get("sandbox_dir")
        ownership_token = state.get("ownership_token")
        if not sandbox_id or not sandbox_dir_str or not ownership_token:
            from src.core.config import get_settings
            settings = get_settings()
            sandbox_root = Path(state.get("custom_root") or settings.sandbox_storage_dir).resolve()
            tracked = self.orchestrator._find_tracked_sandbox(
                request.request_id,
                sandbox_root,
                db_path=db_path,
            )
            if tracked:
                sandbox_id = tracked.sandbox_id
                sandbox_dir_str = str(tracked.sandbox_dir)
                ownership_token = tracked.ownership_token

        sandbox_dir = Path(sandbox_dir_str)
        expected_fixtures = state.get(
            "expected_fixtures", ["users.json", "teams.json", "projects.json", "configs.json"]
        )

        self.orchestrator._update_request_status(request.request_id, WorkflowStatus.VERIFYING, db_path=db_path)

        try:
            verification_result = self.orchestrator.verifier.verify_sandbox(
                sandbox_dir=sandbox_dir,
                expected_fixtures=expected_fixtures,
                execution_id=exec_id,
                expected_sandbox_id=sandbox_id,
                expected_ownership_token=ownership_token,
                db_path=db_path,
            )

            self.orchestrator.audit_service.append_event(
                request_id=request.request_id,
                event_type=AuditEventType.SMOKE_TEST_VERIFIED,
                severity=AuditSeverity.INFO,
                actor=AuditActor(actor_id=request.developer_id, role="DEVELOPER"),
                action_name="VERIFY_SANDBOX",
                details={
                    "sandbox_id": sandbox_id,
                    "fixtures_verified": list(verification_result.fixture_hashes.keys()),
                    "disclaimer": verification_result.smoke_test_evidence.auth_mode_disclaimer,
                },
                state_before=WorkflowStatus.VERIFYING,
                state_after=WorkflowStatus.VERIFYING,
                db_path=db_path,
            )
            self.orchestrator._save_checkpoint(
                request.request_id,
                WorkflowStatus.VERIFYING,
                WorkflowStage.VERIFY_SANDBOX,
                {
                    "sandbox_id": sandbox_id,
                    "fixtures_verified": list(verification_result.fixture_hashes.keys()),
                    "execution_id": exec_id,
                },
                db_path=db_path,
            )
            return {
                "stage": WorkflowStage.VERIFY_SANDBOX.value,
                "current_status": WorkflowStatus.VERIFYING.value,
                "verification_passed": True,
                "fixtures_verified": list(verification_result.fixture_hashes.keys()),
                "step_results": verification_result.step_executions,
                "error_message": None,
                "error_category": None,
            }
        except (
            AuthorizationDeniedError,
            ApprovalExpiredError,
            ApprovalRevokedError,
            SecurityViolationError,
            PlanTamperingError,
            TokenScopeError,
            PathTraversalError,
        ):
            # Security violations stop immediately
            raise
        except Exception as exc:
            err_lower = str(exc).lower()
            if any(kw in err_lower for kw in ReflectionNode.NON_RETRIABLE_KEYWORDS):
                raise
            return {
                "stage": WorkflowStage.VERIFY_SANDBOX.value,
                "verification_passed": False,
                "error_message": str(exc),
                "error_category": exc.__class__.__name__,
                "retry_target": "verify_sandbox",
            }

    def reflect_node(self, state: WorkflowGraphState) -> dict[str, Any]:
        """STAGE: REFLECT (Deterministic failure reflection and bounded retry)."""
        req_id = state["request_id"]
        db_path = state.get("db_path")
        exec_id = state.get("execution_id", "")
        error_msg = state.get("error_message") or "Unknown execution error"
        stage_name = state.get("stage", "EXECUTION")
        retry_count = state.get("retry_count", 0)

        decision = self.reflection_node.reflect(
            error=error_msg,
            current_retry_count=retry_count,
            stage_name=stage_name,
        )

        if decision.can_retry:
            return {
                "retry_count": decision.current_retry_count,
                "can_retry": True,
                "is_terminal_failure": False,
                "error_message": None,
                "error_category": None,
                "retry_target": state.get("retry_target"),
            }
        else:
            self.orchestrator._update_request_status(req_id, WorkflowStatus.FAILED, db_path=db_path)
            stage_enum = WorkflowStage.VERIFY_SANDBOX
            for s in WorkflowStage:
                if s.value == stage_name:
                    stage_enum = s
                    break

            self.orchestrator._save_checkpoint(
                req_id,
                WorkflowStatus.FAILED,
                stage_enum,
                {"error_message": decision.reason, "execution_id": exec_id, "retry_count": retry_count},
                db_path=db_path,
            )
            try:
                self.orchestrator.audit_service.append_event(
                    request_id=req_id,
                    event_type=AuditEventType.STEP_FAILED,
                    severity=AuditSeverity.WARNING,
                    actor=AuditActor(actor_id="reflection", role="SYSTEM"),
                    action_name=f"FAIL_{stage_name}",
                    details={"reason": decision.reason, "retry_count": retry_count},
                    state_before=None,
                    state_after=WorkflowStatus.FAILED,
                    db_path=db_path,
                )
            except Exception:
                pass
            return {
                "current_status": WorkflowStatus.FAILED.value,
                "can_retry": False,
                "is_terminal_failure": True,
                "error_message": decision.reason,
                "error_category": decision.failure_category,
            }

    def finalize_node(self, state: WorkflowGraphState) -> dict[str, Any]:
        """STAGE 10: FINALIZE."""
        req_id = state["request_id"]
        db_path = state.get("db_path")
        exec_id = state.get("execution_id", "")
        request = self.orchestrator.get_request(req_id, db_path=db_path)
        plan = self.orchestrator._get_or_create_plan(request, db_path=db_path)
        approval_record = self.orchestrator._check_approval(request, plan, db_path=db_path)
        if approval_record is None:
            raise SecurityViolationError("Approval record missing at finalization boundary.")

        sandbox_id = state["sandbox_id"]
        sandbox_dir = Path(state["sandbox_dir"])
        expected_fixtures = state.get(
            "expected_fixtures", ["users.json", "teams.json", "projects.json", "configs.json"]
        )

        verification_result = self.orchestrator.verifier.verify_sandbox(
            sandbox_dir=sandbox_dir,
            expected_fixtures=expected_fixtures,
            execution_id=exec_id,
            expected_sandbox_id=sandbox_id,
            expected_ownership_token=state["ownership_token"],
            db_path=db_path,
        )

        manifest = self.orchestrator._build_and_persist_manifest(
            request=request,
            plan=plan,
            approval_record=approval_record,
            sandbox_id=sandbox_id,
            sandbox_dir=sandbox_dir,
            verification_result=verification_result,
            expected_fixtures=expected_fixtures,
            execution_id=exec_id,
            db_path=db_path,
        )

        self.orchestrator._update_request_status(request.request_id, WorkflowStatus.COMPLETED, db_path=db_path)
        self.orchestrator.audit_service.append_event(
            request_id=request.request_id,
            event_type=AuditEventType.MANIFEST_GENERATED,
            severity=AuditSeverity.INFO,
            actor=AuditActor(actor_id=request.developer_id, role="DEVELOPER"),
            action_name="FINALIZE",
            details={
                "manifest_sha256": manifest.integrity.manifest_sha256,
                "plan_hash": plan.canonical_plan_hash,
                "approval_id": approval_record.approval_id,
            },
            state_before=WorkflowStatus.VERIFYING,
            state_after=WorkflowStatus.COMPLETED,
            db_path=db_path,
        )
        self.orchestrator._save_checkpoint(
            request.request_id,
            WorkflowStatus.COMPLETED,
            WorkflowStage.FINALIZE,
            {"manifest_sha256": manifest.integrity.manifest_sha256, "execution_id": exec_id},
            db_path=db_path,
        )
        return {
            "stage": WorkflowStage.FINALIZE.value,
            "current_status": WorkflowStatus.COMPLETED.value,
            "is_completed": True,
            "approval_required": False,
            "manifest_sha256": manifest.integrity.manifest_sha256,
            "step_results": verification_result.step_executions,
        }

    def build_graph(self, checkpointer: Any | None = None) -> CompiledStateGraph:
        """Construct, connect, and compile the 10-stage LangGraph StateGraph with supervisor routing."""
        builder = StateGraph(WorkflowGraphState)

        builder.add_node("collect_request", self.collect_request_node)
        builder.add_node("discover", self.discover_node)
        builder.add_node("build_plan", self.build_plan_node)
        builder.add_node("validate_plan", self.validate_plan_node)
        builder.add_node("generate_manifest", self.generate_manifest_node)
        builder.add_node("await_approval", self.await_approval_node)
        builder.add_node("provision_mock_sandbox", self.provision_mock_sandbox_node)
        builder.add_node("seed_synthetic_data", self.seed_synthetic_data_node)
        builder.add_node("verify_sandbox", self.verify_sandbox_node)
        builder.add_node("reflect", self.reflect_node)
        builder.add_node("finalize", self.finalize_node)

        builder.add_edge(START, "collect_request")
        builder.add_conditional_edges(
            "collect_request",
            self.route_after_collect,
            {"discover": "discover", END: END},
        )
        builder.add_edge("discover", "build_plan")
        builder.add_edge("build_plan", "validate_plan")
        builder.add_edge("validate_plan", "generate_manifest")
        builder.add_edge("generate_manifest", "await_approval")
        builder.add_conditional_edges(
            "await_approval",
            self.route_after_approval,
            {"provision_mock_sandbox": "provision_mock_sandbox", END: END},
        )
        builder.add_conditional_edges(
            "provision_mock_sandbox",
            self.route_after_provision,
            {"seed_synthetic_data": "seed_synthetic_data", "reflect": "reflect"},
        )
        builder.add_conditional_edges(
            "seed_synthetic_data",
            self.route_after_seed,
            {"verify_sandbox": "verify_sandbox", "reflect": "reflect"},
        )
        builder.add_conditional_edges(
            "verify_sandbox",
            self.route_after_verify,
            {"finalize": "finalize", "reflect": "reflect"},
        )
        builder.add_conditional_edges(
            "reflect",
            self.route_after_reflect,
            {
                "provision_mock_sandbox": "provision_mock_sandbox",
                "seed_synthetic_data": "seed_synthetic_data",
                "verify_sandbox": "verify_sandbox",
                END: END,
            },
        )
        builder.add_edge("finalize", END)

        return builder.compile(checkpointer=checkpointer)
