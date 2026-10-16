"""Approval lifecycle, cryptographic binding, and atomic CAS consumption service."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3

from src.core.config import get_settings
from src.core.exceptions import (
    ApprovalAlreadyConsumedError,
    ApprovalError,
    ApprovalExpiredError,
    ApprovalMismatchError,
    ApprovalNotFoundError,
    ApprovalRevokedError,
    DatabaseError,
    TokenScopeError,
)
from src.models.approvals import ApprovalDecisionType, ApprovalRecord, ApprovalRequest, ApproverIdentity
from src.models.enums import PermissionScope
from src.storage.connection import get_connection


class ApprovalService:
    """Manages creation, verification, revocation, and atomic single-use consumption of approvals."""

    def create_approval(
        self,
        request: ApprovalRequest,
        approver: ApproverIdentity,
        target_environment: str,
        granted_scopes: list[PermissionScope],
        db_path: Path | str | None = None,
    ) -> ApprovalRecord:
        """
        Record an authentic approval or rejection decision.

        Validates:
        1. Approver is authorized to grant every requested scope.
        2. Plan fingerprint and version match the active plan in the database.
        3. Enforces configured 30-minute approval TTL.

        Args:
            request: The client approval submission.
            approver: Server-resolved identity of the approving actor.
            target_environment: Execution environment approved for.
            granted_scopes: Scopes approved for execution.
            db_path: Optional explicit database path.

        Returns:
            ApprovalRecord representing the stored decision.

        Raises:
            TokenScopeError: If approver lacks required authorized scopes.
            ApprovalMismatchError: If submitted plan hash does not match stored plan.
        """
        # Validate approver scopes
        authorized_set = set(approver.authorized_scopes)
        for s in granted_scopes:
            if s not in authorized_set:
                raise TokenScopeError(
                    f"Approver '{approver.approver_id}' is not authorized to grant scope '{s.value}'."
                )

        settings = get_settings()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=settings.approval_ttl_minutes)
        approval_id = f"appr-{uuid.uuid4().hex[:12]}"
        scopes_json = json.dumps([s.value for s in sorted(granted_scopes, key=lambda x: x.value)])

        conn = get_connection(db_path)
        try:
            cursor = conn.cursor()
            # Verify plan in database matches submitted plan hash and version
            cursor.execute(
                """
                SELECT canonical_plan_hash, plan_version, target_environment
                FROM setup_plans
                WHERE request_id = ?;
                """,
                (request.request_id,),
            )
            plan_row = cursor.fetchone()
            if plan_row is not None:
                stored_hash = plan_row["canonical_plan_hash"]
                stored_version = plan_row["plan_version"]
                stored_env = plan_row["target_environment"]

                if stored_hash != request.submitted_plan_hash:
                    raise ApprovalMismatchError(
                        f"Submitted plan hash '{request.submitted_plan_hash}' does not match stored plan hash '{stored_hash}'."
                    )
                if stored_version != request.plan_version:
                    raise ApprovalMismatchError(
                        f"Submitted plan version {request.plan_version} does not match stored plan version {stored_version}."
                    )
                if stored_env != target_environment:
                    raise ApprovalMismatchError(
                        f"Target environment '{target_environment}' does not match plan target environment '{stored_env}'."
                    )

            # Insert approval record
            cursor.execute(
                """
                INSERT INTO approval_records (
                    approval_id, request_id, approver_id, decision, canonical_plan_hash,
                    plan_version, target_environment, granted_scopes, created_at, expires_at,
                    rejection_reason, is_revoked, execution_consumed, consumed_at, execution_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, NULL, NULL);
                """,
                (
                    approval_id,
                    request.request_id,
                    approver.approver_id,
                    request.decision.value,
                    request.submitted_plan_hash,
                    request.plan_version,
                    target_environment,
                    scopes_json,
                    now.isoformat(),
                    expires_at.isoformat(),
                    request.rejection_reason,
                ),
            )
            conn.commit()
            cursor.close()
        finally:
            conn.close()

        return ApprovalRecord(
            approval_id=approval_id,
            request_id=request.request_id,
            approver_id=approver.approver_id,
            decision=request.decision,
            canonical_plan_hash=request.submitted_plan_hash,
            plan_version=request.plan_version,
            target_environment=target_environment,
            granted_scopes=granted_scopes,
            created_at=now,
            expires_at=expires_at,
            is_revoked=False,
            execution_consumed=False,
            consumed_at=None,
            rejection_reason=request.rejection_reason,
            execution_id=None,
        )

    def get_approval(self, approval_id: str, db_path: Path | str | None = None) -> ApprovalRecord:
        """Retrieve an approval record by unique ID."""
        conn = get_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT approval_id, request_id, approver_id, decision, canonical_plan_hash,
                       plan_version, target_environment, granted_scopes, created_at, expires_at,
                       rejection_reason, is_revoked, execution_consumed, consumed_at, execution_id
                FROM approval_records
                WHERE approval_id = ?;
                """,
                (approval_id,),
            )
            row = cursor.fetchone()
            cursor.close()
        finally:
            conn.close()

        if row is None:
            raise ApprovalNotFoundError(f"Approval record '{approval_id}' not found.")

        scopes_raw = json.loads(row["granted_scopes"])
        granted_scopes = [PermissionScope(s) for s in scopes_raw]

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
            expires_at=datetime.fromisoformat(row["expires_at"]),
            is_revoked=bool(row["is_revoked"]),
            execution_consumed=bool(row["execution_consumed"]),
            consumed_at=datetime.fromisoformat(row["consumed_at"]) if row["consumed_at"] else None,
            rejection_reason=row["rejection_reason"],
            execution_id=row["execution_id"],
        )

    def revoke_approval(
        self,
        approval_id: str,
        reason: str,
        db_path: Path | str | None = None,
    ) -> None:
        """Mark an unconsumed approval record as revoked."""
        conn = get_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE approval_records
                SET is_revoked = 1,
                    rejection_reason = ?
                WHERE approval_id = ?;
                """,
                (reason, approval_id),
            )
            if cursor.rowcount == 0:
                raise ApprovalNotFoundError(f"Approval record '{approval_id}' not found.")
            conn.commit()
            cursor.close()
        finally:
            conn.close()

    def consume_approval_atomic(
        self,
        approval_id: str,
        request_id: str,
        canonical_plan_hash: str,
        plan_version: int,
        target_environment: str,
        granted_scopes: list[PermissionScope],
        execution_id: str,
        db_path: Path | str | None = None,
    ) -> ApprovalRecord:
        """
        Atomically consume an approval record using SQLite BEGIN IMMEDIATE and a conditional CAS update.

        Guarantees:
        1. Single-use enforcement: Exactly one concurrent attempt succeeds; all other concurrent attempts fail with ApprovalAlreadyConsumedError.
        2. Idempotent resume/retry: If the same execution_id retries after a process crash or restart, it returns the existing valid consumed record.
        3. Strict parameter binding: Rejects if any bound parameter (request_id, hash, version, target_environment, scopes, expiry, revocation) fails.
        4. Fails closed on any error.

        Args:
            approval_id: Unique approval ID.
            request_id: Bootstrap request ID.
            canonical_plan_hash: Exact SHA-256 plan fingerprint.
            plan_version: Plan schema version.
            target_environment: Execution environment.
            granted_scopes: Scopes approved for execution.
            execution_id: Unique execution identifier bound to this run.
            db_path: Optional explicit database path.

        Returns:
            ApprovalRecord updated with execution_consumed=True, consumed_at, and execution_id.

        Raises:
            ApprovalNotFoundError: If approval does not exist.
            ApprovalRevokedError: If approval is revoked.
            ApprovalExpiredError: If approval has passed TTL.
            ApprovalMismatchError: If request, plan, version, environment, or scopes do not match.
            ApprovalAlreadyConsumedError: If approval was already consumed by another execution.
        """
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        scopes_json = json.dumps([s.value for s in sorted(granted_scopes, key=lambda x: x.value)])

        conn = get_connection(db_path)
        conn.isolation_level = None  # Autocommit mode for explicit BEGIN IMMEDIATE transaction management

        cursor = conn.cursor()
        try:
            # 1. Acquire exclusive write lock immediately
            cursor.execute("BEGIN IMMEDIATE;")

            # 2. Inspect current record state under exclusive lock
            cursor.execute(
                """
                SELECT approval_id, request_id, approver_id, decision, canonical_plan_hash,
                       plan_version, target_environment, granted_scopes, created_at, expires_at,
                       rejection_reason, is_revoked, execution_consumed, consumed_at, execution_id
                FROM approval_records
                WHERE approval_id = ?;
                """,
                (approval_id,),
            )
            row = cursor.fetchone()

            if row is None:
                cursor.execute("ROLLBACK;")
                raise ApprovalNotFoundError(f"Approval record '{approval_id}' not found.")

            # Validate basic parameters
            if row["request_id"] != request_id:
                cursor.execute("ROLLBACK;")
                raise ApprovalMismatchError(f"Request ID '{request_id}' does not match approval record request '{row['request_id']}'.")

            if row["canonical_plan_hash"] != canonical_plan_hash:
                cursor.execute("ROLLBACK;")
                raise ApprovalMismatchError("Canonical plan hash does not match approval record.")

            if row["plan_version"] != plan_version:
                cursor.execute("ROLLBACK;")
                raise ApprovalMismatchError(f"Plan version {plan_version} does not match approval record version {row['plan_version']}.")

            if row["target_environment"] != target_environment:
                cursor.execute("ROLLBACK;")
                raise ApprovalMismatchError(f"Target environment '{target_environment}' does not match approval record.")

            stored_scopes = sorted(json.loads(row["granted_scopes"]))
            requested_scopes_sorted = sorted([s.value for s in granted_scopes])
            if stored_scopes != requested_scopes_sorted:
                cursor.execute("ROLLBACK;")
                raise ApprovalMismatchError("Granted permission scopes do not match approval record.")

            if row["is_revoked"]:
                cursor.execute("ROLLBACK;")
                raise ApprovalRevokedError(f"Approval record '{approval_id}' is revoked.")

            expires_at = datetime.fromisoformat(row["expires_at"])
            if now > expires_at:
                cursor.execute("ROLLBACK;")
                raise ApprovalExpiredError(f"Approval record '{approval_id}' expired at {expires_at.isoformat()}.")

            # Check if already consumed
            if row["execution_consumed"]:
                # Idempotency check: if already consumed by the SAME execution_id, reconcile/resume safely
                if row["execution_id"] == execution_id:
                    cursor.execute("COMMIT;")
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
                        execution_consumed=True,
                        consumed_at=datetime.fromisoformat(row["consumed_at"]) if row["consumed_at"] else now,
                        rejection_reason=row["rejection_reason"],
                        execution_id=row["execution_id"],
                    )
                else:
                    cursor.execute("ROLLBACK;")
                    raise ApprovalAlreadyConsumedError(
                        f"Approval record '{approval_id}' has already been consumed by execution '{row['execution_id']}'."
                    )

            # 3. Perform conditional CAS update
            cursor.execute(
                """
                UPDATE approval_records
                SET execution_consumed = 1,
                    consumed_at = ?,
                    execution_id = ?
                WHERE approval_id = ?
                  AND request_id = ?
                  AND canonical_plan_hash = ?
                  AND plan_version = ?
                  AND target_environment = ?
                  AND is_revoked = 0
                  AND execution_consumed = 0
                  AND expires_at >= ?;
                """,
                (
                    now_iso,
                    execution_id,
                    approval_id,
                    request_id,
                    canonical_plan_hash,
                    plan_version,
                    target_environment,
                    now_iso,
                ),
            )

            if cursor.rowcount != 1:
                cursor.execute("ROLLBACK;")
                raise ApprovalAlreadyConsumedError(
                    f"Concurrent consumption collision on approval '{approval_id}'."
                )

            # Commit the transaction
            cursor.execute("COMMIT;")

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
                is_revoked=False,
                execution_consumed=True,
                consumed_at=now,
                rejection_reason=row["rejection_reason"],
                execution_id=execution_id,
            )
        except Exception:
            try:
                cursor.execute("ROLLBACK;")
            except Exception:
                pass
            raise
        finally:
            cursor.close()
            conn.close()
