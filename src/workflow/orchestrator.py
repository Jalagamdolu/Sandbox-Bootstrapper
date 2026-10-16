"""Workflow orchestrator coordinating request validation, discovery, planning,

approval gating, mock provisioning, synthetic seeding, verification, and finalization.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
import sqlite3

from src.adapters.execution_tracker import StepExecutionTracker
from src.adapters.fixtures import ALLOWED_FIXTURE_IDS
from src.adapters.sandbox_provisioner import MockSandboxProvisioner
from src.adapters.data_seeder import SyntheticDataSeeder
from src.core.config import get_settings
from src.core.exceptions import (
    ApprovalError,
    ApprovalExpiredError,
    ApprovalMismatchError,
    ApprovalNotFoundError,
    ApprovalRevokedError,
    DatabaseIntegrityError,
    ExecutionConflictError,
    ModelValidationError,
    PlanTamperingError,
    PlanValidationError,
    ResourceOwnershipError,
    SandboxVerificationError,
    SecurityViolationError,
    TokenScopeError,
    WorkflowError,
    WorkflowExecutionError,
)
from src.models.approvals import ApprovalRecord
from src.models.audit import AuditActor
from src.models.enums import (
    ApprovalDecisionType,
    AuditEventType,
    AuditSeverity,
    PermissionScope,
    ProjectTemplate,
    StepActionType,
    StepExecutionStatus,
    WorkflowStage,
    WorkflowStatus,
)
from src.models.manifest import (
    ManifestEnvironment,
    ManifestProvisioningInfo,
    ManifestSeedSummary,
    ManifestSignatureMetadata,
    SetupManifest,
)
from src.models.plans import SetupPlan
from src.models.requests import BootstrapRequest, BootstrapRequestCreate
from src.models.workflow import StepExecutionRecord, WorkflowRunResult
from src.security.approvals import ApprovalService
from src.security.audit_chain import AuditChainService
from src.security.canonicalization import compute_plan_hash
from src.storage.connection import get_connection
from src.workflow.discovery import discover_local_repository, discover_mock_dashboard
from src.workflow.planner import build_template_plan, get_planner, validate_plan
from src.workflow.verifier import SandboxVerificationResult, SandboxVerifier


class WorkflowOrchestrator:
    """
    Coordinates Developer Sandbox Bootstrapper workflow stages.

    Ensures zero cloud infrastructure, strictly deterministic execution,
    server-side approval gating, restart and retry safety, and zero stored secrets.
    """

    def __init__(
        self,
        sandbox_provisioner: MockSandboxProvisioner | None = None,
        data_seeder: SyntheticDataSeeder | None = None,
        execution_tracker: StepExecutionTracker | None = None,
        audit_service: AuditChainService | None = None,
        approval_service: ApprovalService | None = None,
        verifier: SandboxVerifier | None = None,
        execution_agent: Any | None = None,
    ) -> None:
        self.sandbox_provisioner = sandbox_provisioner or MockSandboxProvisioner()
        self.data_seeder = data_seeder or SyntheticDataSeeder()
        self.execution_tracker = execution_tracker or StepExecutionTracker()
        self.audit_service = audit_service or AuditChainService()
        self.approval_service = approval_service or ApprovalService()
        self.verifier = verifier or SandboxVerifier()
        from src.agents.executor import ExecutionAgent
        self.execution_agent = execution_agent or ExecutionAgent(
            provisioner=self.sandbox_provisioner,
            seeder=self.data_seeder,
            verifier=self.verifier,
            tracker=self.execution_tracker,
        )
        from src.workflow.graph import BootstrapperWorkflowGraph
        self._graph_builder = BootstrapperWorkflowGraph(self)
        self._compiled_graphs: dict[str, Any] = {}

    def get_graph(self, db_path: Path | str | None = None) -> Any:
        """Retrieve or build the compiled LangGraph StateGraph instance."""
        from src.workflow.graph import get_sqlite_checkpointer
        db_key = str(db_path) if db_path else "default"
        if db_key not in self._compiled_graphs:
            checkpointer = get_sqlite_checkpointer(db_path)
            self._compiled_graphs[db_key] = self._graph_builder.build_graph(checkpointer=checkpointer)
        return self._compiled_graphs[db_key]

    @property
    def graph(self) -> Any:
        """Default compiled LangGraph graph instance."""
        return self.get_graph()

    # =========================================================================
    # STAGE 1: COLLECT REQUEST
    # =========================================================================

    def create_request(
        self,
        request_in: BootstrapRequestCreate | dict[str, Any],
        idempotency_key: str | None = None,
        request_id: str | None = None,
        db_path: Path | str | None = None,
    ) -> BootstrapRequest:
        """
        Validate and persist a new bootstrap request in SQLite.

        Args:
            request_in: Validated creation model or raw payload dictionary.
            idempotency_key: Unique client idempotency key.
            request_id: Optional predetermined request ID.
            db_path: Optional explicit database path.

        Returns:
            Persisted BootstrapRequest domain model.

        Raises:
            ModelValidationError: If payload fails contract validation.
        """
        if isinstance(request_in, dict):
            try:
                validated_create = BootstrapRequestCreate(**request_in)
            except Exception as e:
                raise ModelValidationError(f"Invalid bootstrap request data: {e}") from e
        elif isinstance(request_in, BootstrapRequestCreate):
            validated_create = request_in
        else:
            raise ModelValidationError(f"Unsupported request type: {type(request_in)}")

        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        rid = request_id or f"req-{uuid.uuid4().hex[:12]}"
        idem_key = idempotency_key or f"idem-{uuid.uuid4().hex[:16]}"

        conn = get_connection(db_path)
        try:
            cursor = conn.cursor()
            # 1. Check idempotency
            cursor.execute(
                """
                SELECT request_id, idempotency_key, project_name, template, repository_path,
                       requested_scopes, developer_id, target_environment, status, created_at, updated_at
                FROM bootstrap_requests
                WHERE idempotency_key = ?;
                """,
                (idem_key,),
            )
            existing = cursor.fetchone()
            if existing is not None:
                scopes_raw = json.loads(existing["requested_scopes"])
                return BootstrapRequest(
                    request_id=existing["request_id"],
                    idempotency_key=existing["idempotency_key"],
                    project_name=existing["project_name"],
                    template=ProjectTemplate(existing["template"]),
                    repository_path=existing["repository_path"],
                    requested_scopes=[PermissionScope(s) for s in scopes_raw],
                    developer_id=existing["developer_id"],
                    target_environment=existing["target_environment"],
                    status=WorkflowStatus(existing["status"]),
                    created_at=datetime.fromisoformat(existing["created_at"]),
                    updated_at=datetime.fromisoformat(existing["updated_at"]),
                )

            # 2. Persist new request
            scopes_json = json.dumps([s.value for s in validated_create.requested_scopes])
            cursor.execute(
                """
                INSERT INTO bootstrap_requests (
                    request_id, idempotency_key, project_name, template, repository_path,
                    requested_scopes, developer_id, target_environment, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    rid,
                    idem_key,
                    validated_create.project_name,
                    validated_create.template.value,
                    validated_create.repository_path,
                    scopes_json,
                    validated_create.developer_id,
                    validated_create.target_environment,
                    WorkflowStatus.DRAFT.value,
                    now_iso,
                    now_iso,
                ),
            )
            conn.commit()
            cursor.close()
        finally:
            conn.close()

        persisted = BootstrapRequest(
            request_id=rid,
            idempotency_key=idem_key,
            project_name=validated_create.project_name,
            template=validated_create.template,
            repository_path=validated_create.repository_path,
            requested_scopes=validated_create.requested_scopes,
            developer_id=validated_create.developer_id,
            target_environment=validated_create.target_environment,
            status=WorkflowStatus.DRAFT,
            created_at=now,
            updated_at=now,
        )

        # Audit log and checkpoint
        self.audit_service.append_event(
            request_id=rid,
            event_type=AuditEventType.REQUEST_CREATED,
            severity=AuditSeverity.INFO,
            actor=AuditActor(actor_id=validated_create.developer_id, role="DEVELOPER"),
            action_name="COLLECT_REQUEST",
            details={
                "project_name": validated_create.project_name,
                "template": validated_create.template.value,
                "requested_scopes": [s.value for s in validated_create.requested_scopes],
                "target_environment": validated_create.target_environment,
            },
            state_before=None,
            state_after=WorkflowStatus.DRAFT,
            db_path=db_path,
        )

        self._save_checkpoint(
            request_id=rid,
            current_status=WorkflowStatus.DRAFT,
            stage=WorkflowStage.COLLECT_REQUEST,
            state_payload={"project_name": validated_create.project_name},
            db_path=db_path,
        )

        return persisted

    def get_request(self, request_id: str, db_path: Path | str | None = None) -> BootstrapRequest:
        """Fetch bootstrap request by ID from SQLite."""
        conn = get_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT request_id, idempotency_key, project_name, template, repository_path,
                       requested_scopes, developer_id, target_environment, status, created_at, updated_at
                FROM bootstrap_requests
                WHERE request_id = ?;
                """,
                (request_id,),
            )
            row = cursor.fetchone()
            cursor.close()
        finally:
            conn.close()

        if row is None:
            raise WorkflowError(f"Bootstrap request '{request_id}' not found.")

        scopes_raw = json.loads(row["requested_scopes"])
        return BootstrapRequest(
            request_id=row["request_id"],
            idempotency_key=row["idempotency_key"],
            project_name=row["project_name"],
            template=ProjectTemplate(row["template"]),
            repository_path=row["repository_path"],
            requested_scopes=[PermissionScope(s) for s in scopes_raw],
            developer_id=row["developer_id"],
            target_environment=row["target_environment"],
            status=WorkflowStatus(row["status"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    # =========================================================================
    # WORKFLOW EXECUTION COORDINATOR (STAGES 2 - 10)
    # =========================================================================

    def run_workflow(
        self,
        request_id: str,
        execution_id: str | None = None,
        caller_token: str | None = None,
        custom_root: Path | str | None = None,
        raise_on_failure: bool = False,
        db_path: Path | str | None = None,
    ) -> WorkflowRunResult:
        """
        Execute or resume the 10-stage bootstrapper workflow for a request using LangGraph.

        Awaits and strictly enforces human approval before privileged actions (provisioning/seeding).
        Idempotent and restartable across failures and interruptions.

        Args:
            request_id: Identifier of the request to execute.
            execution_id: Unique execution identifier (generated if None).
            caller_token: Optional approver token for caller verification.
            custom_root: Optional filesystem root override for sandbox storage.
            raise_on_failure: If True, re-raises caught exceptions; if False, returns FAILED result.
            db_path: Optional explicit database path.

        Returns:
            WorkflowRunResult reflecting terminal or paused state.
        """
        request = self.get_request(request_id, db_path=db_path)
        exec_id = execution_id or f"exec-{uuid.uuid4().hex[:12]}"
        settings = get_settings()
        sandbox_root = Path(custom_root or settings.sandbox_storage_dir).resolve()

        # If already COMPLETED, return finalized status without re-running
        if request.status == WorkflowStatus.COMPLETED:
            tracked = self._find_tracked_sandbox(request.request_id, sandbox_root, db_path=db_path)
            manifest = None
            if tracked and (tracked.sandbox_dir / "manifest.json").exists():
                try:
                    manifest = SetupManifest.model_validate_json(
                        (tracked.sandbox_dir / "manifest.json").read_text(encoding="utf-8")
                    )
                except Exception:
                    pass
            return WorkflowRunResult(
                request_id=request.request_id,
                execution_id=exec_id,
                current_status=WorkflowStatus.COMPLETED,
                stage=WorkflowStage.FINALIZE,
                is_completed=True,
                approval_required=False,
                sandbox_id=tracked.sandbox_id if tracked else None,
                manifest_id=manifest.integrity.manifest_sha256 if manifest else None,
                manifest=manifest,
                cleanup_deadline=tracked.expires_at.isoformat() if tracked and hasattr(tracked, "expires_at") else None,
            )

        graph = self.get_graph(db_path=db_path)
        thread_id = f"bootstrapper-{request_id}"
        config = {
            "configurable": {
                "thread_id": thread_id,
                "caller_token": caller_token,
            }
        }
        initial_state = {
            "request_id": request.request_id,
            "execution_id": exec_id,
            "custom_root": str(custom_root) if custom_root else None,
            "db_path": str(db_path) if db_path else None,
            "retry_count": 0,
            "error_message": None,
            "error_category": None,
            "can_retry": True,
        }

        try:
            final_state = graph.invoke(initial_state, config=config)

            stage_val = WorkflowStage(final_state.get("stage", WorkflowStage.FINALIZE.value))
            status_val = WorkflowStatus(final_state.get("current_status", WorkflowStatus.COMPLETED.value))
            is_comp = final_state.get("is_completed", False)
            appr_req = final_state.get("approval_required", False)

            manifest = None
            if final_state.get("sandbox_dir"):
                mani_file = Path(final_state["sandbox_dir"]) / "manifest.json"
                if mani_file.exists():
                    try:
                        manifest = SetupManifest.model_validate_json(mani_file.read_text(encoding="utf-8"))
                    except Exception:
                        pass

            return WorkflowRunResult(
                request_id=request.request_id,
                execution_id=exec_id,
                current_status=status_val,
                stage=stage_val,
                is_completed=is_comp,
                approval_required=appr_req,
                sandbox_id=final_state.get("sandbox_id"),
                manifest_id=final_state.get("manifest_sha256"),
                manifest=manifest,
                step_results=final_state.get("step_results", {}),
                error_message=final_state.get("error_message"),
                error_category=final_state.get("error_category"),
                cleanup_deadline=final_state.get("cleanup_deadline"),
            )
        except ApprovalExpiredError as exc:
            current_stage = WorkflowStage.AWAIT_APPROVAL
            self._update_request_status(request.request_id, WorkflowStatus.EXPIRED, db_path=db_path)
            self._save_checkpoint(
                request.request_id,
                WorkflowStatus.EXPIRED,
                current_stage,
                {"error_message": str(exc), "error_category": "ApprovalExpiredError", "execution_id": exec_id},
                db_path=db_path,
            )
            try:
                self.audit_service.append_event(
                    request_id=request.request_id,
                    event_type=AuditEventType.APPROVAL_EXPIRED,
                    severity=AuditSeverity.WARNING,
                    actor=AuditActor(actor_id="system", role="SYSTEM"),
                    action_name="EXPIRE_APPROVAL",
                    details={"error_message": str(exc)},
                    state_before=WorkflowStatus.PENDING_APPROVAL,
                    state_after=WorkflowStatus.EXPIRED,
                    db_path=db_path,
                )
            except Exception:
                pass
            if raise_on_failure:
                raise
            return WorkflowRunResult(
                request_id=request.request_id,
                execution_id=exec_id,
                current_status=WorkflowStatus.EXPIRED,
                stage=current_stage,
                is_completed=False,
                approval_required=False,
                error_message=str(exc),
                error_category="ApprovalExpiredError",
            )
        except Exception as exc:
            error_cat = exc.__class__.__name__
            error_msg = str(exc)

            node_to_stage = {
                "collect_request": WorkflowStage.COLLECT_REQUEST,
                "discover": WorkflowStage.DISCOVER,
                "build_plan": WorkflowStage.BUILD_PLAN,
                "validate_plan": WorkflowStage.VALIDATE_PLAN,
                "generate_manifest": WorkflowStage.GENERATE_MANIFEST,
                "await_approval": WorkflowStage.AWAIT_APPROVAL,
                "provision_mock_sandbox": WorkflowStage.PROVISION_MOCK_SANDBOX,
                "seed_synthetic_data": WorkflowStage.SEED_SYNTHETIC_DATA,
                "verify_sandbox": WorkflowStage.VERIFY_SANDBOX,
                "finalize": WorkflowStage.FINALIZE,
            }
            try:
                state_snap = graph.get_state(config)
                if state_snap and state_snap.next:
                    current_stage = node_to_stage.get(state_snap.next[0], WorkflowStage.COLLECT_REQUEST)
                elif state_snap and state_snap.values.get("stage"):
                    current_stage = WorkflowStage(state_snap.values["stage"])
                else:
                    current_stage = WorkflowStage.AWAIT_APPROVAL
            except Exception:
                current_stage = WorkflowStage.AWAIT_APPROVAL

            self._update_request_status(request.request_id, WorkflowStatus.FAILED, db_path=db_path)
            self._save_checkpoint(
                request.request_id,
                WorkflowStatus.FAILED,
                current_stage,
                {"error_message": error_msg, "error_category": error_cat, "execution_id": exec_id},
                db_path=db_path,
            )

            try:
                self.audit_service.append_event(
                    request_id=request.request_id,
                    event_type=AuditEventType.STEP_FAILED,
                    severity=AuditSeverity.CRITICAL if isinstance(exc, SecurityViolationError) else AuditSeverity.WARNING,
                    actor=AuditActor(actor_id="system", role="SYSTEM"),
                    action_name=f"FAIL_{current_stage.value}",
                    details={"error_message": error_msg, "error_category": error_cat},
                    state_before=None,
                    state_after=WorkflowStatus.FAILED,
                    db_path=db_path,
                )
            except Exception:
                pass

            if raise_on_failure:
                raise

            return WorkflowRunResult(
                request_id=request.request_id,
                execution_id=exec_id,
                current_status=WorkflowStatus.FAILED,
                stage=current_stage,
                is_completed=False,
                approval_required=False,
                error_message=error_msg,
                error_category=error_cat,
            )


    # =========================================================================
    # SANDBOX CLEANUP (Requires SANDBOX_DELETE Authorization)
    # =========================================================================

    def cleanup_workflow_sandbox(
        self,
        request_id: str,
        sandbox_id: str,
        approval_id: str,
        execution_id: str,
        step_id: str = "cleanup-sandbox-step",
        caller_token: str | None = None,
        custom_root: Path | str | None = None,
        db_path: Path | str | None = None,
    ) -> bool:
        """
        Clean up an authorized local sandbox under strict SANDBOX_DELETE authorization.

        Preserves and delegates to MockSandboxProvisioner.cleanup_sandbox.
        """
        approval = self.approval_service.get_approval(approval_id, db_path=db_path)
        return self.sandbox_provisioner.cleanup_sandbox(
            sandbox_id=sandbox_id,
            request_id=request_id,
            approval_id=approval_id,
            execution_id=execution_id,
            step_id=step_id,
            plan_hash=approval.canonical_plan_hash,
            plan_version=approval.plan_version,
            target_environment=approval.target_environment,
            granted_scopes=approval.granted_scopes,
            caller_token=caller_token,
            custom_root=custom_root,
            db_path=db_path,
        )

    # =========================================================================
    # INTERNAL HELPERS
    # =========================================================================

    def _check_approval(
        self,
        request: BootstrapRequest,
        plan: SetupPlan,
        db_path: Path | str | None = None,
    ) -> ApprovalRecord | None:
        """
        Inspect approval_records for valid human approval.

        Returns ApprovalRecord if valid; None if unapproved; raises on mismatch or tampering.
        """
        conn = get_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT approval_id, request_id, approver_id, decision, canonical_plan_hash,
                       plan_version, target_environment, granted_scopes, created_at, expires_at,
                       rejection_reason, is_revoked, execution_consumed, consumed_at, execution_id
                FROM approval_records
                WHERE request_id = ?
                ORDER BY created_at DESC
                LIMIT 1;
                """,
                (request.request_id,),
            )
            row = cursor.fetchone()
            cursor.close()
        finally:
            conn.close()

        if row is None:
            return None

        # 1. Revocation check
        if row["is_revoked"] == 1:
            raise ApprovalRevokedError(
                f"Approval record '{row['approval_id']}' has been revoked: {row['rejection_reason']}"
            )

        # 2. Decision check
        if row["decision"] == ApprovalDecisionType.REJECT.value:
            raise ApprovalError(f"Approval rejected: {row['rejection_reason']}")

        # 3. Expiration check
        now = datetime.now(timezone.utc)
        expires_at = datetime.fromisoformat(row["expires_at"])
        if now > expires_at:
            raise ApprovalExpiredError(f"Approval record '{row['approval_id']}' expired at {expires_at.isoformat()}")

        # 4. Plan hash binding check (strict plan mutation prevention)
        if row["canonical_plan_hash"] != plan.canonical_plan_hash:
            raise PlanTamperingError(
                f"Plan drift detected: approval binds to '{row['canonical_plan_hash']}', "
                f"but active plan hash is '{plan.canonical_plan_hash}'."
            )

        # 5. Plan version binding check
        if row["plan_version"] != plan.plan_version:
            raise ApprovalMismatchError(
                f"Plan version mismatch: approval version {row['plan_version']}, active version {plan.plan_version}"
            )

        # 6. Target environment binding check
        if row["target_environment"] != plan.target_environment:
            raise ApprovalMismatchError(
                f"Target environment mismatch: approval environment '{row['target_environment']}', "
                f"active environment '{plan.target_environment}'"
            )

        # 7. Scope verification
        granted_scopes = [PermissionScope(s) for s in json.loads(row["granted_scopes"])]
        granted_set = {s.value for s in granted_scopes}
        required_privileged = {PermissionScope.SANDBOX_CREATE.value, PermissionScope.DATA_SEED_SYNTHETIC.value}
        if not required_privileged.issubset(granted_set):
            raise TokenScopeError(
                f"Approval lacks required scopes for mock execution: missing {required_privileged - granted_set}"
            )

        return ApprovalRecord(
            approval_id=row["approval_id"],
            request_id=row["request_id"],
            approver_id=row["approver_id"],
            decision=ApprovalDecisionType(row["decision"]),
            canonical_plan_hash=row["canonical_plan_hash"],
            plan_version=row["plan_version"],
            target_environment=row["target_environment"],
            granted_scopes=granted_scopes,
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=expires_at,
            is_revoked=bool(row["is_revoked"]),
            execution_consumed=bool(row["execution_consumed"]),
            consumed_at=datetime.fromisoformat(row["consumed_at"]) if row["consumed_at"] else None,
            rejection_reason=row["rejection_reason"],
            execution_id=row["execution_id"],
        )

    def _execute_provision_step(
        self,
        request: BootstrapRequest,
        plan: SetupPlan,
        approval_record: ApprovalRecord,
        execution_id: str,
        caller_token: str | None = None,
        custom_root: Path | str | None = None,
        db_path: Path | str | None = None,
    ) -> Any:
        """Execute or safely skip verified mock sandbox provisioning via ExecutionAgent tool dispatch."""
        step = self._find_step(plan, StepActionType.PROVISION_MOCK_SANDBOX)
        step_id = step.step_id if step else "step-00000004"

        settings = get_settings()
        sandbox_root = Path(custom_root or settings.sandbox_storage_dir).resolve()

        # Check existing durable step record
        existing_step = self.execution_tracker.get_step_execution(execution_id, step_id, db_path=db_path)
        if existing_step and existing_step.status in (StepExecutionStatus.COMPLETED, StepExecutionStatus.SUCCEEDED):
            # Verify real local filesystem state before skipping
            tracked = self._find_tracked_sandbox(request.request_id, sandbox_root, db_path=db_path)
            if tracked is not None:
                return tracked

        self._update_request_status(request.request_id, WorkflowStatus.PROVISIONING, db_path=db_path)

        if step is None:
            raise SecurityViolationError("Provisioning step missing in plan.")

        res = self.execution_agent.execute_step(
            step=step,
            request=request,
            plan=plan,
            approval=approval_record,
            execution_id=execution_id,
            caller_token=caller_token,
            custom_root=custom_root,
            db_path=db_path,
        )
        if res.status == StepExecutionStatus.FAILED:
            raise RuntimeError(res.error_message or "Sandbox provisioning failed.")

        res_data = res.result_data
        if "skipped_as_already_completed" in res_data:
            tracked = self._find_tracked_sandbox(request.request_id, sandbox_root, db_path=db_path)
            if tracked is not None:
                return tracked

        return MockSandboxResult(
            sandbox_id=res_data["sandbox_id"],
            sandbox_dir=Path(res_data["sandbox_dir"]),
            ownership_token=res_data["ownership_token"],
            expires_at=datetime.fromisoformat(res_data["cleanup_deadline"]),
        )

    def _execute_seeding_step(
        self,
        request: BootstrapRequest,
        plan: SetupPlan,
        approval_record: ApprovalRecord,
        sandbox_id: str,
        sandbox_dir: Path,
        expected_fixtures: list[str],
        execution_id: str,
        caller_token: str | None = None,
        custom_root: Path | str | None = None,
        db_path: Path | str | None = None,
    ) -> None:
        """Execute or safely skip verified synthetic data seeding via ExecutionAgent tool dispatch."""
        step = self._find_step(plan, StepActionType.SEED_SYNTHETIC_DATA)
        step_id = step.step_id if step else "step-00000005"

        existing_step = self.execution_tracker.get_step_execution(execution_id, step_id, db_path=db_path)
        if existing_step and existing_step.status in (StepExecutionStatus.COMPLETED, StepExecutionStatus.SUCCEEDED):
            # Verify real local fixture files on disk
            fixtures_dir = sandbox_dir / "fixtures"
            all_present = True
            for fid in expected_fixtures:
                if not (fixtures_dir / fid).exists():
                    all_present = False
                    break
            if all_present:
                return

        self._update_request_status(request.request_id, WorkflowStatus.SEEDING, db_path=db_path)

        if step is None:
            raise SecurityViolationError("Seeding step missing in plan.")

        res = self.execution_agent.execute_step(
            step=step,
            request=request,
            plan=plan,
            approval=approval_record,
            execution_id=execution_id,
            sandbox_id=sandbox_id,
            sandbox_dir=sandbox_dir,
            caller_token=caller_token,
            custom_root=custom_root,
            db_path=db_path,
        )
        if res.status == StepExecutionStatus.FAILED:
            raise RuntimeError(res.error_message or "Synthetic data seeding failed.")

    def _build_and_persist_manifest(
        self,
        request: BootstrapRequest,
        plan: SetupPlan,
        approval_record: ApprovalRecord,
        sandbox_id: str,
        sandbox_dir: Path,
        verification_result: SandboxVerificationResult,
        expected_fixtures: list[str],
        execution_id: str,
        db_path: Path | str | None = None,
    ) -> SetupManifest:
        """Construct deterministic canonical setup manifest, write to disk, and return."""
        now = datetime.now(timezone.utc)
        env_manifest = ManifestEnvironment(
            target_environment=plan.target_environment,
            sandbox_id=sandbox_id,
            mock_endpoint_url="http://127.0.0.1:8080",
            allocated_ports=[8080],
            created_timestamp=request.created_at,
            expires_timestamp=request.created_at + timedelta(hours=24),
        )
        prov_info = ManifestProvisioningInfo(
            template_applied=request.template,
            applied_scopes=approval_record.granted_scopes,
            sandbox_filesystem_path=str(sandbox_dir),
        )
        seed_summary = ManifestSeedSummary(
            fixtures_loaded=expected_fixtures,
            total_records_seeded=len(expected_fixtures) * 3,
            generation_mode="DETERMINISTIC_SYNTHETIC_GENERATOR",
            pii_scan_status="PASSED_DEFENSE_IN_DEPTH_SCAN",
        )
        planned_actions_list = [
            {
                "step_id": s.step_id,
                "action_type": s.action_type.value,
                "name": s.name,
                "required_scopes": [sc.value for sc in s.required_scopes],
            }
            for s in plan.steps
        ]

        dummy_sig = ManifestSignatureMetadata(
            manifest_sha256="0" * 64,
            canonical_plan_hash=plan.canonical_plan_hash,
            approval_id=approval_record.approval_id,
            generated_at=now,
            generator_version="1.3.0",
        )

        manifest_candidate = SetupManifest(
            manifest_version="1.3.0",
            request_id=request.request_id,
            workflow_id=execution_id,
            plan_version=plan.plan_version,
            environment_label="MOCK / LOCAL ONLY",
            environment=env_manifest,
            provisioning=prov_info,
            data_seeding=seed_summary,
            verification=verification_result.smoke_test_evidence,
            integrity=dummy_sig,
            planned_actions=planned_actions_list,
            step_executions=verification_result.step_executions,
            fixture_hashes=verification_result.fixture_hashes,
            workflow_status="COMPLETED",
            error_category=None,
        )

        # Compute deterministic SHA-256 of candidate manifest payload
        canonical_json = manifest_candidate.model_dump_json(indent=2)
        manifest_digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

        final_manifest = manifest_candidate.model_copy(
            update={
                "integrity": dummy_sig.model_copy(update={"manifest_sha256": manifest_digest})
            }
        )

        # Persist manifest to sandbox directory
        manifest_file = sandbox_dir / "manifest.json"
        manifest_file.write_text(final_manifest.model_dump_json(indent=2), encoding="utf-8")

        return final_manifest

    def _get_or_create_plan(
        self,
        request: BootstrapRequest,
        db_path: Path | str | None = None,
    ) -> SetupPlan:
        """Retrieve existing setup plan or generate and persist deterministic template plan."""
        conn = get_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT plan_id, request_id, plan_version, target_environment, canonical_plan_hash, plan_json, created_at
                FROM setup_plans
                WHERE request_id = ?;
                """,
                (request.request_id,),
            )
            row = cursor.fetchone()
            cursor.close()
        finally:
            conn.close()

        if row is not None:
            plan_dict = json.loads(row["plan_json"])
            return SetupPlan.model_validate(plan_dict)

        planner = get_planner()
        plan = planner.generate_plan(
            request_id=request.request_id,
            template=request.template,
            target_environment=request.target_environment,
        )

        conn = get_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO setup_plans (plan_id, request_id, plan_version, target_environment, canonical_plan_hash, plan_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    plan.plan_id,
                    plan.request_id,
                    plan.plan_version,
                    plan.target_environment,
                    plan.canonical_plan_hash,
                    plan.model_dump_json(),
                    plan.created_at.isoformat(),
                ),
            )
            conn.commit()
            cursor.close()
        finally:
            conn.close()

        return plan

    def _find_tracked_sandbox(
        self,
        request_id: str,
        sandbox_root: Path,
        db_path: Path | str | None = None,
    ) -> Any | None:
        """Find and verify tracked sandbox resource on disk."""
        conn = get_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT resource_id, filesystem_path, ownership_token
                FROM tracked_resources
                WHERE request_id = ? AND resource_type IN ('SANDBOX_DIRECTORY', 'MOCK_SANDBOX') AND is_quarantined = 0
                ORDER BY created_at DESC
                LIMIT 1;
                """,
                (request_id,),
            )
            row = cursor.fetchone()
            cursor.close()
        finally:
            conn.close()

        if row is None:
            return None

        sbx_dir = Path(row["filesystem_path"]).resolve()
        if not sbx_dir.exists():
            return None

        meta_file = sbx_dir / ".sandbox-metadata.json"
        if not meta_file.exists():
            return None

        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if data.get("ownership_token") != row["ownership_token"]:
                return None

            from src.adapters.sandbox_provisioner import MockSandboxResult
            return MockSandboxResult(
                sandbox_id=data["sandbox_id"],
                request_id=request_id,
                sandbox_dir=sbx_dir,
                ownership_token=row["ownership_token"],
                created_at=datetime.fromisoformat(data["created_at"]),
                expires_at=datetime.fromisoformat(data["expires_at"]),
                environment_label=data.get("environment_label", "MOCK / LOCAL ONLY"),
                is_mock=True,
                status="PROVISIONED",
            )
        except Exception:
            return None

    def _find_step(self, plan: SetupPlan, action_type: StepActionType) -> Any | None:
        """Locate first step matching action_type in plan."""
        for step in plan.steps:
            if step.action_type == action_type:
                return step
        return None

    def _update_request_status(
        self,
        request_id: str,
        status: WorkflowStatus,
        db_path: Path | str | None = None,
    ) -> None:
        """Atomically update bootstrap request status in SQLite."""
        now_iso = datetime.now(timezone.utc).isoformat()
        conn = get_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE bootstrap_requests
                SET status = ?, updated_at = ?
                WHERE request_id = ?;
                """,
                (status.value, now_iso, request_id),
            )
            conn.commit()
            cursor.close()
        finally:
            conn.close()

    def _save_checkpoint(
        self,
        request_id: str,
        current_status: WorkflowStatus,
        stage: WorkflowStage,
        state_payload: dict[str, Any],
        db_path: Path | str | None = None,
    ) -> str:
        """Persist a workflow execution checkpoint."""
        checkpoint_id = f"chk-{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now(timezone.utc).isoformat()
        payload = {
            "stage": stage.value,
            "current_status": current_status.value,
            **state_payload,
        }
        conn = get_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO workflow_checkpoints (checkpoint_id, request_id, current_status, state_payload, created_at)
                VALUES (?, ?, ?, ?, ?);
                """,
                (checkpoint_id, request_id, current_status.value, json.dumps(payload, default=str), now_iso),
            )
            conn.commit()
            cursor.close()
        finally:
            conn.close()
        return checkpoint_id
