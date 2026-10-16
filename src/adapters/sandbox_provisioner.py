"""Local mock sandbox provisioner adapter with strict path confinement and pre-action guard."""

from __future__ import annotations

import json
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3

from src.adapters.execution_tracker import StepExecutionTracker
from src.adapters.path_utils import resolve_safe_path
from src.core.config import get_settings
from src.core.exceptions import (
    AuthorizationDeniedError,
    PathTraversalError,
    ResourceOwnershipError,
    SandboxProvisioningError,
    StepExecutionError,
)

from src.models.approvals import AuthGuardEvaluationContext
from src.models.audit import AuditActor
from src.models.enums import (
    AuditEventType,
    AuditSeverity,
    PermissionScope,
    StepActionType,
    StepExecutionStatus,
    WorkflowStatus,
)
from src.security.approvals import ApprovalService
from src.security.audit_chain import AuditChainService
from src.security.guard import ServerSideAuthGuard
from src.storage.connection import get_connection, transaction_scope


@dataclass(frozen=True)
class MockSandboxResult:
    """Result metadata for a locally provisioned mock sandbox."""

    sandbox_id: str
    request_id: str
    sandbox_dir: Path
    ownership_token: str
    created_at: datetime
    expires_at: datetime
    environment_label: str = "MOCK / LOCAL ONLY"
    is_mock: bool = True
    status: str = "PROVISIONED"


class MockSandboxProvisioner:
    """
    Local mock sandbox provisioner adapter.
    Confines all filesystem operations strictly to a configured sandbox root directory.
    Enforces server-side authorization guard and CAS approval consumption immediately before provisioning.
    """

    METADATA_FILENAME = ".sandbox-metadata.json"

    def __init__(
        self,
        auth_guard: ServerSideAuthGuard | None = None,
        approval_service: ApprovalService | None = None,
        execution_tracker: StepExecutionTracker | None = None,
        audit_service: AuditChainService | None = None,
    ) -> None:
        self.auth_guard = auth_guard or ServerSideAuthGuard()
        self.approval_service = approval_service or ApprovalService()
        self.execution_tracker = execution_tracker or StepExecutionTracker()
        self.audit_service = audit_service or AuditChainService()

    def provision_sandbox(
        self,
        request_id: str,
        approval_id: str,
        execution_id: str,
        step_id: str,
        plan_hash: str,
        plan_version: int,
        target_environment: str,
        granted_scopes: list[PermissionScope],
        caller_token: str | None = None,
        custom_root: Path | str | None = None,
        db_path: Path | str | None = None,
    ) -> MockSandboxResult:
        """
        Provision an isolated local mock sandbox directory under strict authorization.

        Guarantees:
        1. JIT authorization revalidated via ServerSideAuthGuard.evaluate immediately before action.
        2. Approval consumed atomically via ApprovalService.consume_approval_atomic.
        3. Step state tracked durably in SQLite step_executions table.
        4. Restricts all directory creation to sandbox_root; rejects path traversal and escapes.
        5. Writes unique ownership token to .sandbox-metadata.json.
        6. Persists resource tracking in tracked_resources table.
        7. Idempotent: repeated calls with same execution_id return existing verified sandbox.
        8. Never overwrites unverified or unrelated user files.
        9. Clearly marked as 'MOCK / LOCAL ONLY'.

        Args:
            request_id: Bootstrap request ID.
            approval_id: Approved authorization record ID.
            execution_id: Overall workflow execution ID.
            step_id: Step identifier from plan.
            plan_hash: Canonical SHA-256 plan fingerprint.
            plan_version: Plan version number.
            target_environment: Execution environment.
            granted_scopes: Scopes approved for execution.
            caller_token: Optional approver token for caller verification.
            custom_root: Optional override of sandbox storage root.
            db_path: Optional explicit database path.

        Returns:
            MockSandboxResult containing sandbox metadata.
        """
        settings = get_settings()
        sandbox_root = Path(custom_root or settings.sandbox_storage_dir).resolve()
        sandbox_root.mkdir(parents=True, exist_ok=True)

        now = datetime.now(timezone.utc)

        # 1. IMMEDIATE PRE-ACTION AUTHORIZATION GUARD CHECK
        guard_ctx = AuthGuardEvaluationContext(
            approval_id=approval_id,
            request_id=request_id,
            action_type=StepActionType.PROVISION_MOCK_SANDBOX,
            target_environment=target_environment,
            required_scope=PermissionScope.SANDBOX_CREATE,
            active_plan_hash=plan_hash,
            active_plan_version=plan_version,
            current_status=WorkflowStatus.APPROVED,
            current_time=now,
        )
        self.auth_guard.evaluate(guard_ctx, caller_token=caller_token, db_path=db_path)

        # 2. ATOMIC SINGLE-USE CAS CONSUMPTION (WITH IDEMPOTENT RETRY RECONCILIATION)
        approval_record = self.approval_service.consume_approval_atomic(
            approval_id=approval_id,
            request_id=request_id,
            canonical_plan_hash=plan_hash,
            plan_version=plan_version,
            target_environment=target_environment,
            granted_scopes=granted_scopes,
            execution_id=execution_id,
            db_path=db_path,
        )

        # 3. DURABLE STEP EXECUTION STATE CHECK
        step_record = self.execution_tracker.start_step(
            execution_id=execution_id,
            request_id=request_id,
            plan_hash=plan_hash,
            plan_version=plan_version,
            step_id=step_id,
            action_type=StepActionType.PROVISION_MOCK_SANDBOX,
            db_path=db_path,
        )

        # If step is already COMPLETED, inspect local filesystem state to verify sandbox
        if step_record.status in (StepExecutionStatus.COMPLETED, StepExecutionStatus.SUCCEEDED):
            existing_sbx = self._find_tracked_sandbox(request_id, sandbox_root, db_path=db_path)
            if existing_sbx is not None:
                return existing_sbx

        try:
            # 4. Check if sandbox was already provisioned in tracked_resources for this request
            existing_sbx = self._find_tracked_sandbox(request_id, sandbox_root, db_path=db_path)
            if existing_sbx is not None:
                self.execution_tracker.complete_step(
                    execution_id=execution_id,
                    step_id=step_id,
                    output_summary={"sandbox_id": existing_sbx.sandbox_id, "reused": True},
                    db_path=db_path,
                )
                return existing_sbx

            # 5. Generate unique sandbox ID and ownership token
            sandbox_id = f"sbx-{uuid.uuid4().hex[:12]}"
            ownership_token = str(uuid.uuid4())
            sandbox_dir = resolve_safe_path(sandbox_root, sandbox_id)

            # Never overwrite existing unowned directory
            if sandbox_dir.exists():
                meta_file = sandbox_dir / self.METADATA_FILENAME
                if not meta_file.exists():
                    raise ResourceOwnershipError(
                        f"Target path '{sandbox_dir}' exists without verified sandbox metadata. Overwrite forbidden."
                    )

            sandbox_dir.mkdir(parents=True, exist_ok=True)

            # Write .sandbox-metadata.json
            metadata_file = sandbox_dir / self.METADATA_FILENAME
            expires_at = now + timedelta(hours=settings.sandbox_retention_hours)
            metadata_payload = {
                "sandbox_id": sandbox_id,
                "request_id": request_id,
                "ownership_token": ownership_token,
                "created_at": now.isoformat(),
                "expires_at": expires_at.isoformat(),
                "target_environment": target_environment,
                "environment_label": "MOCK / LOCAL ONLY",
                "is_mock": True,
            }
            metadata_file.write_text(json.dumps(metadata_payload, indent=2), encoding="utf-8")

            # 6. Record resource ownership in tracked_resources table
            conn = get_connection(db_path)
            try:
                with transaction_scope(conn) as cursor:
                    cursor.execute(
                        """
                        INSERT INTO tracked_resources (
                            resource_id, request_id, resource_type, filesystem_path,
                            ownership_token, created_at, expires_at, is_quarantined
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, 0);
                        """,
                        (
                            sandbox_id,
                            request_id,
                            "SANDBOX_DIRECTORY",
                            str(sandbox_dir),
                            ownership_token,
                            now.isoformat(),
                            expires_at.isoformat(),
                        ),
                    )
            finally:
                conn.close()

            # 7. Record step completion in durable tracker
            output_summary = {
                "sandbox_id": sandbox_id,
                "sandbox_dir": str(sandbox_dir),
                "environment_label": "MOCK / LOCAL ONLY",
                "is_mock": True,
            }
            self.execution_tracker.complete_step(
                execution_id=execution_id,
                step_id=step_id,
                output_summary=output_summary,
                db_path=db_path,
            )

            # 8. Append hash-chained audit event
            self.audit_service.append_event(
                request_id=request_id,
                event_type=AuditEventType.STEP_COMPLETED,
                severity=AuditSeverity.INFO,
                actor=AuditActor(actor_id=approval_record.approver_id, role="SECURITY_LEAD"),
                action_name="ProvisionMockSandbox",
                details=output_summary,
                db_path=db_path,
            )

            return MockSandboxResult(
                sandbox_id=sandbox_id,
                request_id=request_id,
                sandbox_dir=sandbox_dir,
                ownership_token=ownership_token,
                created_at=now,
                expires_at=expires_at,
                environment_label="MOCK / LOCAL ONLY",
                is_mock=True,
                status="PROVISIONED",
            )
        except Exception as exc:
            self.execution_tracker.fail_step(
                execution_id=execution_id,
                step_id=step_id,
                error_message=str(exc),
                error_category="PROVISIONING_ERROR",
                db_path=db_path,
            )
            if isinstance(exc, (ResourceOwnershipError, AuthorizationDeniedError, PathTraversalError)):
                raise
            raise SandboxProvisioningError(f"Mock sandbox provisioning failed: {exc}") from exc


    def cleanup_sandbox(
        self,
        sandbox_id: str,
        request_id: str,
        approval_id: str,
        execution_id: str,
        step_id: str,
        plan_hash: str,
        plan_version: int,
        target_environment: str,
        granted_scopes: list[PermissionScope],
        caller_token: str | None = None,
        custom_root: Path | str | None = None,
        db_path: Path | str | None = None,
    ) -> bool:
        """
        Safely remove an application-owned sandbox directory under strict authorization.

        Guarantees:
        1. JIT authorization revalidated via ServerSideAuthGuard.evaluate immediately before action.
        2. Approval consumed atomically via ApprovalService.consume_approval_atomic.
        3. Step state tracked durably in SQLite step_executions table.
        4. Verifies ownership in SQLite tracked_resources table.
        5. Resolves path within sandbox_root, preventing traversal and symlink escapes.
        6. Inspects .sandbox-metadata.json inside the directory and validates ownership_token.
        7. Refuses to delete any directory that is unverified or not application-owned.
        8. Removes row from tracked_resources and writes audit event.

        Args:
            sandbox_id: Identifier of sandbox to clean up.
            request_id: Bootstrap request ID.
            approval_id: Valid authorization record ID.
            execution_id: Overall workflow execution ID.
            step_id: Step identifier from plan.
            plan_hash: Canonical SHA-256 plan fingerprint.
            plan_version: Plan version number.
            target_environment: Execution environment.
            granted_scopes: Scopes approved for execution.
            caller_token: Optional approver token for caller verification.
            custom_root: Optional override of sandbox storage root.
            db_path: Optional explicit database path.

        Returns:
            True if sandbox was successfully cleaned up.

        Raises:
            AuthorizationDeniedError: If approval or scope validation fails.
            ResourceOwnershipError: If ownership verification fails.
            SandboxProvisioningError: If unexpected cleanup failure occurs.
        """
        now = datetime.now(timezone.utc)

        # 1. IMMEDIATE PRE-ACTION AUTHORIZATION GUARD CHECK
        guard_ctx = AuthGuardEvaluationContext(
            approval_id=approval_id,
            request_id=request_id,
            action_type=StepActionType.CLEANUP_MOCK_SANDBOX,
            target_environment=target_environment,
            required_scope=PermissionScope.SANDBOX_DELETE,
            active_plan_hash=plan_hash,
            active_plan_version=plan_version,
            current_status=WorkflowStatus.APPROVED,
            current_time=now,
        )
        self.auth_guard.evaluate(guard_ctx, caller_token=caller_token, db_path=db_path)

        # 2. ATOMIC SINGLE-USE CAS CONSUMPTION (WITH IDEMPOTENT RETRY RECONCILIATION)
        approval_record = self.approval_service.consume_approval_atomic(
            approval_id=approval_id,
            request_id=request_id,
            canonical_plan_hash=plan_hash,
            plan_version=plan_version,
            target_environment=target_environment,
            granted_scopes=granted_scopes,
            execution_id=execution_id,
            db_path=db_path,
        )

        # 3. DURABLE STEP EXECUTION STATE CHECK
        step_record = self.execution_tracker.start_step(
            execution_id=execution_id,
            request_id=request_id,
            plan_hash=plan_hash,
            plan_version=plan_version,
            step_id=step_id,
            action_type=StepActionType.CLEANUP_MOCK_SANDBOX,
            db_path=db_path,
        )

        # If step is already COMPLETED, verify that the directory has indeed been removed
        if step_record.status in (StepExecutionStatus.COMPLETED, StepExecutionStatus.SUCCEEDED):
            conn = get_connection(db_path)
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT count(*) FROM tracked_resources
                    WHERE resource_id = ? AND request_id = ? AND resource_type = 'SANDBOX_DIRECTORY';
                    """,
                    (sandbox_id, request_id),
                )
                count = cursor.fetchone()[0]
                cursor.close()
            finally:
                conn.close()
            if count == 0:
                return True

        settings = get_settings()
        sandbox_root = Path(custom_root or settings.sandbox_storage_dir).resolve()

        try:
            conn = get_connection(db_path)
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT resource_id, request_id, filesystem_path, ownership_token
                    FROM tracked_resources
                    WHERE resource_id = ? AND request_id = ? AND resource_type = 'SANDBOX_DIRECTORY';
                    """,
                    (sandbox_id, request_id),
                )
                row = cursor.fetchone()
                cursor.close()
            finally:
                conn.close()

            if row is None:
                raise ResourceOwnershipError(
                    f"Cannot clean up sandbox '{sandbox_id}': No tracked ownership record found for request '{request_id}'."
                )

            stored_path = Path(row["filesystem_path"])
            stored_token = row["ownership_token"]

            # Path confinement check
            verified_path = resolve_safe_path(sandbox_root, stored_path)

            if not verified_path.exists():
                # Already deleted on filesystem, clean up DB record
                self._delete_tracked_resource(sandbox_id, db_path=db_path)
                self.execution_tracker.complete_step(
                    execution_id=execution_id,
                    step_id=step_id,
                    output_summary={"sandbox_id": sandbox_id, "cleaned": True, "already_absent": True},
                    db_path=db_path,
                )
                return True

            # Verify .sandbox-metadata.json inside target directory
            meta_file = verified_path / self.METADATA_FILENAME
            if not meta_file.exists():
                raise ResourceOwnershipError(
                    f"Directory '{verified_path}' does not contain '{self.METADATA_FILENAME}'. Refusing to delete."
                )

            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
                if meta.get("ownership_token") != stored_token or meta.get("sandbox_id") != sandbox_id:
                    raise ResourceOwnershipError(
                        f"Metadata token mismatch in '{verified_path}'. Ownership verification failed."
                    )
            except Exception as err:
                raise ResourceOwnershipError(f"Corrupt metadata in '{verified_path}': {err}") from err

            # Securely remove directory
            shutil.rmtree(verified_path)

            # Remove from database
            self._delete_tracked_resource(sandbox_id, db_path=db_path)

            # 4. Complete step in durable tracker
            output_summary = {
                "sandbox_id": sandbox_id,
                "cleaned": True,
                "path": str(verified_path),
                "environment_label": "MOCK / LOCAL ONLY",
                "is_mock": True,
            }
            self.execution_tracker.complete_step(
                execution_id=execution_id,
                step_id=step_id,
                output_summary=output_summary,
                db_path=db_path,
            )

            # 5. Audit event
            self.audit_service.append_event(
                request_id=request_id,
                event_type=AuditEventType.STEP_COMPLETED,
                severity=AuditSeverity.INFO,
                actor=AuditActor(actor_id=approval_record.approver_id, role="SECURITY_LEAD"),
                action_name="CleanupSandbox",
                details=output_summary,
                db_path=db_path,
            )
            return True
        except Exception as exc:
            self.execution_tracker.fail_step(
                execution_id=execution_id,
                step_id=step_id,
                error_message=str(exc),
                error_category="CLEANUP_ERROR",
                db_path=db_path,
            )
            if isinstance(exc, (ResourceOwnershipError, AuthorizationDeniedError, PathTraversalError)):
                raise
            raise SandboxProvisioningError(f"Mock sandbox cleanup failed: {exc}") from exc

    def _find_tracked_sandbox(
        self,
        request_id: str,
        sandbox_root: Path,
        db_path: Path | str | None = None,
    ) -> MockSandboxResult | None:
        """Find and verify an already existing sandbox record for the request."""
        conn = get_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT resource_id, request_id, filesystem_path, ownership_token, created_at, expires_at
                FROM tracked_resources
                WHERE request_id = ? AND resource_type = 'SANDBOX_DIRECTORY';
                """,
                (request_id,),
            )
            row = cursor.fetchone()
            cursor.close()
        finally:
            conn.close()

        if row is None:
            return None

        sandbox_dir = resolve_safe_path(sandbox_root, Path(row["filesystem_path"]))
        meta_file = sandbox_dir / self.METADATA_FILENAME
        if not sandbox_dir.exists() or not meta_file.exists():
            return None

        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            if meta.get("ownership_token") != row["ownership_token"]:
                return None
        except Exception:
            return None

        return MockSandboxResult(
            sandbox_id=row["resource_id"],
            request_id=request_id,
            sandbox_dir=sandbox_dir,
            ownership_token=row["ownership_token"],
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
            environment_label="MOCK / LOCAL ONLY",
            is_mock=True,
            status="PROVISIONED",
        )

    def _delete_tracked_resource(self, resource_id: str, db_path: Path | str | None = None) -> None:
        """Remove resource record from tracked_resources."""
        conn = get_connection(db_path)
        try:
            with transaction_scope(conn) as cursor:
                cursor.execute(
                    "DELETE FROM tracked_resources WHERE resource_id = ?;",
                    (resource_id,),
                )
        finally:
            conn.close()
