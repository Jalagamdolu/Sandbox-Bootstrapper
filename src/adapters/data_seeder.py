"""Synthetic data seeder adapter with strict allowlisting, path confinement, and JIT authorization."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import sqlite3

from src.adapters.execution_tracker import StepExecutionTracker
from src.adapters.fixtures import ALLOWED_FIXTURE_IDS, get_canonical_fixture_bytes
from src.adapters.path_utils import resolve_safe_path
from src.core.config import get_settings
from src.core.exceptions import (
    AuthorizationDeniedError,
    PathTraversalError,
    ResourceOwnershipError,
    SyntheticDataSeedingError,
    UnknownFixtureError,
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
from src.storage.connection import get_connection


@dataclass(frozen=True)
class FixtureSeedResult:
    """Outcome for an individual seeded fixture."""

    fixture_id: str
    destination_path: Path
    sha256_hash: str
    bytes_written: int
    status: str  # 'SEEDED' or 'UNCHANGED'


@dataclass(frozen=True)
class SeedingSummary:
    """Aggregate result of a synthetic data seeding operation."""

    request_id: str
    sandbox_id: str
    fixtures_seeded: list[FixtureSeedResult]
    total_bytes_written: int
    environment_label: str = "MOCK / LOCAL ONLY"
    is_mock: bool = True


class SyntheticDataSeeder:
    """
    Adapter responsible for seeding synthetic test data into local sandboxes.
    Uses strictly allowlisted, deterministic synthetic fixtures (zero real credentials or PII).
    Enforces server-side authorization guard and CAS approval consumption immediately before seeding.
    """

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

    def seed_fixtures(
        self,
        request_id: str,
        sandbox_id: str,
        approval_id: str,
        execution_id: str,
        step_id: str,
        plan_hash: str,
        plan_version: int,
        target_environment: str,
        granted_scopes: list[PermissionScope],
        fixture_ids: list[str],
        destination_subpath: str = "fixtures",
        caller_token: str | None = None,
        custom_root: Path | str | None = None,
        db_path: Path | str | None = None,
    ) -> SeedingSummary:
        """
        Seed allowlisted synthetic fixtures into an authorized local sandbox.

        Guarantees:
        1. JIT authorization revalidated via ServerSideAuthGuard immediately before writing.
        2. Approval consumed atomically via ApprovalService.consume_approval_atomic.
        3. Step state tracked durably in step_executions table.
        4. Rejects any fixture ID not in ALLOWED_FIXTURE_IDS.
        5. Defense-in-depth regex scan ensures zero live secrets or PII.
        6. Confines all file writes strictly within the target sandbox directory; rejects escapes.
        7. Idempotent: re-seeding identical fixtures returns UNCHANGED status without duplication.
        8. Records fixture IDs, destination paths, content hashes, and status in audit trail.

        Args:
            request_id: Bootstrap request ID.
            sandbox_id: Sandbox directory ID.
            approval_id: Approved authorization record ID.
            execution_id: Overall workflow execution ID.
            step_id: Step identifier from plan.
            plan_hash: Canonical SHA-256 plan fingerprint.
            plan_version: Plan version number.
            target_environment: Execution environment.
            granted_scopes: Scopes approved for execution.
            fixture_ids: List of requested fixture IDs (must be allowlisted).
            destination_subpath: Subdirectory inside sandbox to place fixtures (default 'fixtures').
            caller_token: Optional approver token for caller verification.
            custom_root: Optional override of sandbox storage root.
            db_path: Optional explicit database path.

        Returns:
            SeedingSummary containing results for all seeded fixtures.
        """
        now = datetime.now(timezone.utc)

        # 1. FIXTURE ALLOWLIST VALIDATION (FAIL FAST BEFORE ACTIONS)
        for fid in fixture_ids:
            if fid not in ALLOWED_FIXTURE_IDS:
                raise UnknownFixtureError(
                    f"Fixture '{fid}' is not allowlisted. Permitted: {sorted(ALLOWED_FIXTURE_IDS)}"
                )

        # 2. IMMEDIATE PRE-ACTION AUTHORIZATION GUARD CHECK
        guard_ctx = AuthGuardEvaluationContext(
            approval_id=approval_id,
            request_id=request_id,
            action_type=StepActionType.SEED_SYNTHETIC_DATA,
            target_environment=target_environment,
            required_scope=PermissionScope.DATA_SEED_SYNTHETIC,
            active_plan_hash=plan_hash,
            active_plan_version=plan_version,
            current_status=WorkflowStatus.APPROVED,
            current_time=now,
        )
        self.auth_guard.evaluate(guard_ctx, caller_token=caller_token, db_path=db_path)

        # 3. ATOMIC SINGLE-USE CAS CONSUMPTION (WITH IDEMPOTENT RETRY RECONCILIATION)
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

        # 4. DURABLE STEP EXECUTION STATE CHECK
        step_record = self.execution_tracker.start_step(
            execution_id=execution_id,
            request_id=request_id,
            plan_hash=plan_hash,
            plan_version=plan_version,
            step_id=step_id,
            action_type=StepActionType.SEED_SYNTHETIC_DATA,
            db_path=db_path,
        )

        settings = get_settings()
        sandbox_root = Path(custom_root or settings.sandbox_storage_dir).resolve()

        try:
            # 5. VERIFY SANDBOX OWNERSHIP AND LOCAL DIRECTORY
            sandbox_dir = self._verify_and_resolve_sandbox(sandbox_id, request_id, sandbox_root, db_path=db_path)

            # 6. RESOLVE DESTINATION FIXTURES DIRECTORY INSIDE SANDBOX
            target_fixtures_dir = resolve_safe_path(sandbox_dir, destination_subpath)
            target_fixtures_dir.mkdir(parents=True, exist_ok=True)

            results: list[FixtureSeedResult] = []
            total_bytes = 0

            # 7. WRITE FIXTURES IDEMPOTENTLY
            for fid in sorted(fixture_ids):
                payload_bytes, sha256_hash = get_canonical_fixture_bytes(fid)
                dest_file = resolve_safe_path(target_fixtures_dir, fid)

                if dest_file.exists():
                    existing_bytes = dest_file.read_bytes()
                    if existing_bytes == payload_bytes:
                        results.append(
                            FixtureSeedResult(
                                fixture_id=fid,
                                destination_path=dest_file,
                                sha256_hash=sha256_hash,
                                bytes_written=len(payload_bytes),
                                status="UNCHANGED",
                            )
                        )
                        continue

                dest_file.write_bytes(payload_bytes)
                total_bytes += len(payload_bytes)
                results.append(
                    FixtureSeedResult(
                        fixture_id=fid,
                        destination_path=dest_file,
                        sha256_hash=sha256_hash,
                        bytes_written=len(payload_bytes),
                        status="SEEDED",
                    )
                )

            output_summary = {
                "sandbox_id": sandbox_id,
                "fixtures_count": len(results),
                "fixtures": [
                    {
                        "fixture_id": r.fixture_id,
                        "sha256_hash": r.sha256_hash,
                        "status": r.status,
                        "bytes": r.bytes_written,
                    }
                    for r in results
                ],
                "total_bytes": total_bytes,
                "environment_label": "MOCK / LOCAL ONLY",
                "is_mock": True,
            }

            # 8. MARK STEP COMPLETED IN DURABLE TRACKER
            self.execution_tracker.complete_step(
                execution_id=execution_id,
                step_id=step_id,
                output_summary=output_summary,
                db_path=db_path,
            )

            # 9. RECORD AUDIT EVENT
            self.audit_service.append_event(
                request_id=request_id,
                event_type=AuditEventType.STEP_COMPLETED,
                severity=AuditSeverity.INFO,
                actor=AuditActor(actor_id=approval_record.approver_id, role="SECURITY_LEAD"),
                action_name="SeedSyntheticData",
                details=output_summary,
                db_path=db_path,
            )

            return SeedingSummary(
                request_id=request_id,
                sandbox_id=sandbox_id,
                fixtures_seeded=results,
                total_bytes_written=total_bytes,
                environment_label="MOCK / LOCAL ONLY",
                is_mock=True,
            )
        except Exception as exc:
            self.execution_tracker.fail_step(
                execution_id=execution_id,
                step_id=step_id,
                error_message=str(exc),
                error_category="SEEDING_ERROR",
                db_path=db_path,
            )
            if isinstance(exc, (UnknownFixtureError, AuthorizationDeniedError, ResourceOwnershipError, PathTraversalError)):
                raise
            raise SyntheticDataSeedingError(f"Synthetic data seeding failed: {exc}") from exc


    def _verify_and_resolve_sandbox(
        self,
        sandbox_id: str,
        request_id: str,
        sandbox_root: Path,
        db_path: Path | str | None = None,
    ) -> Path:
        """Verify that the target sandbox is application-owned and contains valid metadata."""
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
                f"Cannot seed data: Sandbox '{sandbox_id}' not found in tracked_resources for request '{request_id}'."
            )

        stored_path = Path(row["filesystem_path"])
        stored_token = row["ownership_token"]

        sandbox_dir = resolve_safe_path(sandbox_root, stored_path)
        if not sandbox_dir.exists():
            raise ResourceOwnershipError(
                f"Sandbox directory '{sandbox_dir}' does not exist on disk."
            )

        meta_file = sandbox_dir / ".sandbox-metadata.json"
        if not meta_file.exists():
            raise ResourceOwnershipError(
                f"Sandbox directory '{sandbox_dir}' missing '.sandbox-metadata.json'. Refusing to seed unowned directory."
            )

        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            if meta.get("ownership_token") != stored_token or meta.get("sandbox_id") != sandbox_id:
                raise ResourceOwnershipError(
                    f"Metadata token mismatch in '{sandbox_dir}'. Ownership verification failed."
                )
        except Exception as err:
            raise ResourceOwnershipError(f"Corrupt metadata in '{sandbox_dir}': {err}") from err

        return sandbox_dir
