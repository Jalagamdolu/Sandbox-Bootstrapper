"""Execution Agent for Developer Sandbox Bootstrapper.

Responsible for executing ONLY approved plan actions using explicitly registered,
allowlisted local mock tools. Enforces pre-action authorization and tracking.
Never runs arbitrary shell commands, dynamic code, or unregistered tools.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, Optional
from pydantic import BaseModel, ConfigDict

from src.adapters.data_seeder import SyntheticDataSeeder
from src.adapters.execution_tracker import StepExecutionTracker
from src.adapters.sandbox_provisioner import MockSandboxProvisioner, MockSandboxResult
from src.core.exceptions import (
    ApprovalExpiredError,
    ApprovalRevokedError,
    AuthorizationDeniedError,
    PathTraversalError,
    PlanTamperingError,
    SecurityViolationError,
    TokenScopeError,
)
from src.models.approvals import ApprovalRecord
from src.models.enums import PermissionScope, StepActionType, StepExecutionStatus
from src.models.plans import PlannedStep, SetupPlan
from src.models.requests import BootstrapRequest
from src.security.guard import ServerSideAuthGuard
from src.workflow.verifier import SandboxVerificationResult, SandboxVerifier


class StepExecutionResult(BaseModel):
    """Result of executing an approved step."""

    model_config = ConfigDict(extra="forbid")

    step_id: str
    action_type: StepActionType
    status: StepExecutionStatus
    result_data: dict[str, Any] = {}
    error_message: Optional[str] = None


class ExecutionAgent:
    """Agent 4: Safely dispatches approved plan steps exclusively through registered mock tools."""

    def __init__(
        self,
        provisioner: MockSandboxProvisioner | None = None,
        seeder: SyntheticDataSeeder | None = None,
        verifier: SandboxVerifier | None = None,
        tracker: StepExecutionTracker | None = None,
        auth_guard: ServerSideAuthGuard | None = None,
    ) -> None:
        self.provisioner = provisioner or MockSandboxProvisioner()
        self.seeder = seeder or SyntheticDataSeeder()
        self.verifier = verifier or SandboxVerifier()
        self.tracker = tracker or StepExecutionTracker()
        self.auth_guard = auth_guard or ServerSideAuthGuard()

        # Explicit tool allowlist registry
        self._tool_registry: Dict[StepActionType, Callable[..., Any]] = {
            StepActionType.PROVISION_MOCK_SANDBOX: self._execute_provision,
            StepActionType.SEED_SYNTHETIC_DATA: self._execute_seed,
            StepActionType.EXECUTE_SMOKE_TEST: self._execute_verify,
        }

    def execute_step(
        self,
        step: PlannedStep,
        request: BootstrapRequest,
        plan: SetupPlan,
        approval: ApprovalRecord,
        execution_id: str,
        sandbox_id: str | None = None,
        sandbox_dir: Path | None = None,
        ownership_token: str | None = None,
        caller_token: str | None = None,
        custom_root: Path | str | None = None,
        db_path: Path | str | None = None,
    ) -> StepExecutionResult:
        """
        Execute an approved step via the registered tool.

        Rejects unknown actions, validates authorization, and durably records results.
        """
        # 1. Tool allowlist check
        handler = self._tool_registry.get(step.action_type)
        if handler is None:
            raise SecurityViolationError(
                f"Action '{step.action_type}' is not registered in the Execution Agent tool allowlist."
            )

        # 2. Check if already completed (durable idempotency)
        existing = self.tracker.get_step_execution(execution_id, step.step_id, db_path=db_path)
        if existing and existing.status in (StepExecutionStatus.COMPLETED, StepExecutionStatus.SUCCEEDED):
            return StepExecutionResult(
                step_id=step.step_id,
                action_type=step.action_type,
                status=StepExecutionStatus.COMPLETED,
                result_data={"skipped_as_already_completed": True},
            )

        # 3. Dispatch to registered handler
        try:
            res_data = handler(
                step=step,
                request=request,
                plan=plan,
                approval=approval,
                execution_id=execution_id,
                sandbox_id=sandbox_id,
                sandbox_dir=sandbox_dir,
                ownership_token=ownership_token,
                caller_token=caller_token,
                custom_root=custom_root,
                db_path=db_path,
            )
            return StepExecutionResult(
                step_id=step.step_id,
                action_type=step.action_type,
                status=StepExecutionStatus.COMPLETED,
                result_data=res_data,
            )
        except (
            AuthorizationDeniedError,
            ApprovalExpiredError,
            ApprovalRevokedError,
            SecurityViolationError,
            PlanTamperingError,
            TokenScopeError,
            PathTraversalError,
        ):
            # Security and authorization violations stop immediately
            raise
        except Exception as exc:
            return StepExecutionResult(
                step_id=step.step_id,
                action_type=step.action_type,
                status=StepExecutionStatus.FAILED,
                error_message=str(exc),
            )

    def _execute_provision(self, **kwargs: Any) -> dict[str, Any]:
        """Execute local mock sandbox directory provisioning."""
        step: PlannedStep = kwargs["step"]
        request: BootstrapRequest = kwargs["request"]
        plan: SetupPlan = kwargs["plan"]
        approval: ApprovalRecord = kwargs["approval"]
        execution_id: str = kwargs["execution_id"]
        caller_token: str | None = kwargs.get("caller_token")
        custom_root: Path | str | None = kwargs.get("custom_root")
        db_path: Path | str | None = kwargs.get("db_path")

        result: MockSandboxResult = self.provisioner.provision_sandbox(
            request_id=request.request_id,
            approval_id=approval.approval_id,
            execution_id=execution_id,
            step_id=step.step_id,
            plan_hash=plan.canonical_plan_hash,
            plan_version=plan.plan_version,
            target_environment=plan.target_environment,
            granted_scopes=approval.granted_scopes,
            caller_token=caller_token,
            custom_root=custom_root,
            db_path=db_path,
        )
        return {
            "sandbox_id": result.sandbox_id,
            "sandbox_dir": str(result.sandbox_dir),
            "ownership_token": result.ownership_token,
            "cleanup_deadline": result.expires_at.isoformat(),
        }

    def _execute_seed(self, **kwargs: Any) -> dict[str, Any]:
        """Execute synthetic fixtures seeding into authorized sandbox."""
        step: PlannedStep = kwargs["step"]
        request: BootstrapRequest = kwargs["request"]
        plan: SetupPlan = kwargs["plan"]
        approval: ApprovalRecord = kwargs["approval"]
        execution_id: str = kwargs["execution_id"]
        sandbox_id: str = kwargs["sandbox_id"]
        caller_token: str | None = kwargs.get("caller_token")
        custom_root: Path | str | None = kwargs.get("custom_root")
        db_path: Path | str | None = kwargs.get("db_path")

        fixtures = step.action_parameters.get(
            "fixtures", ["users.json", "teams.json", "projects.json", "configs.json"]
        )
        summary = self.seeder.seed_fixtures(
            request_id=request.request_id,
            sandbox_id=sandbox_id,
            approval_id=approval.approval_id,
            execution_id=execution_id,
            step_id=step.step_id,
            plan_hash=plan.canonical_plan_hash,
            plan_version=plan.plan_version,
            target_environment=plan.target_environment,
            granted_scopes=approval.granted_scopes,
            fixture_ids=fixtures,
            caller_token=caller_token,
            custom_root=custom_root,
            db_path=db_path,
        )
        return {
            "total_bytes_written": summary.total_bytes_written,
            "total_records_seeded": len(summary.fixtures_seeded),
            "fixtures_seeded": [f.fixture_id for f in summary.fixtures_seeded],
        }

    def _execute_verify(self, **kwargs: Any) -> dict[str, Any]:
        """Execute local mock verification smoke tests."""
        step: PlannedStep = kwargs["step"]
        sandbox_dir: Path = kwargs["sandbox_dir"]
        sandbox_id: str = kwargs.get("sandbox_id", "")
        execution_id: str | None = kwargs.get("execution_id")
        ownership_token: str | None = kwargs.get("ownership_token")
        db_path: Path | str | None = kwargs.get("db_path")
        fixtures = step.action_parameters.get(
            "fixtures", ["users.json", "teams.json", "projects.json", "configs.json"]
        )
        res: SandboxVerificationResult = self.verifier.verify_sandbox(
            sandbox_dir=sandbox_dir,
            expected_fixtures=fixtures,
            execution_id=execution_id,
            expected_sandbox_id=sandbox_id,
            expected_ownership_token=ownership_token,
            db_path=db_path,
        )
        return {
            "is_verified": res.is_verified,
            "fixtures_verified": list(res.fixture_hashes.keys()),
            "step_executions": res.step_executions,
            "disclaimer": res.smoke_test_evidence.auth_mode_disclaimer,
        }
