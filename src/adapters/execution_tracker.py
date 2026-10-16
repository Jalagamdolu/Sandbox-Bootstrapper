"""Durable step execution tracker and state machine service."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
import sqlite3

from src.core.exceptions import ExecutionConflictError, StepExecutionError
from src.models.enums import StepActionType, StepExecutionStatus
from src.models.workflow import StepExecutionRecord
from src.storage.connection import get_connection


class StepExecutionTracker:
    """
    Durable tracker for step executions in SQLite.
    Enforces atomic state transitions (PENDING -> RUNNING -> COMPLETED/FAILED),
    reconciles crash/retry attempts, and prevents duplicate or concurrent execution.
    """

    def start_step(
        self,
        execution_id: str,
        request_id: str,
        plan_hash: str,
        plan_version: int,
        step_id: str,
        action_type: StepActionType,
        db_path: Path | str | None = None,
    ) -> StepExecutionRecord:
        """
        Record the start of a step execution under SQLite BEGIN IMMEDIATE lock.

        Guarantees:
        1. Plan hash & version mismatch against prior executions raises ExecutionConflictError.
        2. If step is already COMPLETED, returns existing record without re-running.
        3. If step is currently RUNNING, raises ExecutionConflictError to block duplicate/concurrent execution.
        4. If step previously FAILED, transitions to RUNNING and increments retry_count.
        5. If step is new, inserts initial record with status=RUNNING.

        Args:
            execution_id: Overall workflow execution ID.
            request_id: Bootstrap request ID.
            plan_hash: Canonical SHA-256 plan fingerprint.
            plan_version: Plan version number.
            step_id: Step identifier from plan.
            action_type: Action type enum.
            db_path: Optional explicit database path.

        Returns:
            StepExecutionRecord reflecting durable state.
        """
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        conn = get_connection(db_path)
        conn.isolation_level = None  # Autocommit mode for explicit BEGIN IMMEDIATE transaction
        cursor = conn.cursor()

        try:
            cursor.execute("BEGIN IMMEDIATE;")

            # 1. Check for conflicting plan hash under this execution_id or request_id
            cursor.execute(
                """
                SELECT execution_id, plan_hash, plan_version
                FROM step_executions
                WHERE execution_id = ? OR request_id = ?
                LIMIT 1;
                """,
                (execution_id, request_id),
            )
            conflict_row = cursor.fetchone()
            if conflict_row is not None:
                if conflict_row["plan_hash"] != plan_hash:
                    cursor.execute("ROLLBACK;")
                    raise ExecutionConflictError(
                        f"Mismatched plan hash for execution '{execution_id}': "
                        f"expected '{conflict_row['plan_hash']}', got '{plan_hash}'."
                    )
                if conflict_row["plan_version"] != plan_version:
                    cursor.execute("ROLLBACK;")
                    raise ExecutionConflictError(
                        f"Mismatched plan version for execution '{execution_id}': "
                        f"expected {conflict_row['plan_version']}, got {plan_version}."
                    )

            # 2. Check current status of this specific step
            cursor.execute(
                """
                SELECT step_execution_id, execution_id, request_id, plan_hash, plan_version,
                       step_id, action_type, status, retry_count, started_at, completed_at,
                       error_category, error_message, output_summary
                FROM step_executions
                WHERE execution_id = ? AND step_id = ?;
                """,
                (execution_id, step_id),
            )
            row = cursor.fetchone()

            if row is not None:
                curr_status = row["status"]
                # If already COMPLETED, return record to allow caller to skip duplicate work safely
                if curr_status in (StepExecutionStatus.COMPLETED.value, StepExecutionStatus.SUCCEEDED.value):
                    cursor.execute("COMMIT;")
                    return self._row_to_record(row)

                # If currently RUNNING, block concurrent duplicate execution
                if curr_status in (StepExecutionStatus.RUNNING.value, StepExecutionStatus.IN_PROGRESS.value):
                    cursor.execute("ROLLBACK;")
                    raise ExecutionConflictError(
                        f"Step '{step_id}' is already RUNNING under execution '{execution_id}'. "
                        "Concurrent execution or unhandled collision detected."
                    )

                # If FAILED or PENDING, retry step
                new_retry_count = row["retry_count"] + 1
                cursor.execute(
                    """
                    UPDATE step_executions
                    SET status = ?,
                        retry_count = ?,
                        started_at = ?,
                        completed_at = NULL,
                        error_category = NULL,
                        error_message = NULL
                    WHERE execution_id = ? AND step_id = ?;
                    """,
                    (StepExecutionStatus.RUNNING.value, new_retry_count, now_iso, execution_id, step_id),
                )
                cursor.execute("COMMIT;")
                return StepExecutionRecord(
                    step_execution_id=row["step_execution_id"],
                    execution_id=execution_id,
                    request_id=request_id,
                    plan_hash=plan_hash,
                    plan_version=plan_version,
                    step_id=step_id,
                    action_type=action_type,
                    status=StepExecutionStatus.RUNNING,
                    retry_count=new_retry_count,
                    started_at=now,
                    completed_at=None,
                    error_category=None,
                    error_message=None,
                    output_summary=json.loads(row["output_summary"]) if row["output_summary"] else {},
                )

            # 3. New step execution record
            step_exec_id = f"sexec-{uuid.uuid4().hex[:12]}"
            cursor.execute(
                """
                INSERT INTO step_executions (
                    step_execution_id, execution_id, request_id, plan_hash, plan_version,
                    step_id, action_type, status, retry_count, started_at, completed_at,
                    error_category, error_message, output_summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, NULL, NULL, NULL, '{}');
                """,
                (
                    step_exec_id,
                    execution_id,
                    request_id,
                    plan_hash,
                    plan_version,
                    step_id,
                    action_type.value,
                    StepExecutionStatus.RUNNING.value,
                    now_iso,
                ),
            )
            cursor.execute("COMMIT;")
            return StepExecutionRecord(
                step_execution_id=step_exec_id,
                execution_id=execution_id,
                request_id=request_id,
                plan_hash=plan_hash,
                plan_version=plan_version,
                step_id=step_id,
                action_type=action_type,
                status=StepExecutionStatus.RUNNING,
                retry_count=0,
                started_at=now,
                completed_at=None,
                error_category=None,
                error_message=None,
                output_summary={},
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

    def complete_step(
        self,
        execution_id: str,
        step_id: str,
        output_summary: dict | None = None,
        db_path: Path | str | None = None,
    ) -> StepExecutionRecord:
        """Atomically transition step execution status to COMPLETED."""
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        summary_json = json.dumps(output_summary or {})

        conn = get_connection(db_path)
        conn.isolation_level = None
        cursor = conn.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE;")
            cursor.execute(
                """
                UPDATE step_executions
                SET status = ?,
                    completed_at = ?,
                    output_summary = ?
                WHERE execution_id = ? AND step_id = ?;
                """,
                (StepExecutionStatus.COMPLETED.value, now_iso, summary_json, execution_id, step_id),
            )
            if cursor.rowcount == 0:
                cursor.execute("ROLLBACK;")
                raise StepExecutionError(f"Step execution not found for '{execution_id}:{step_id}'.")

            cursor.execute(
                """
                SELECT step_execution_id, execution_id, request_id, plan_hash, plan_version,
                       step_id, action_type, status, retry_count, started_at, completed_at,
                       error_category, error_message, output_summary
                FROM step_executions
                WHERE execution_id = ? AND step_id = ?;
                """,
                (execution_id, step_id),
            )
            row = cursor.fetchone()
            cursor.execute("COMMIT;")
            return self._row_to_record(row)
        except Exception:
            try:
                cursor.execute("ROLLBACK;")
            except Exception:
                pass
            raise
        finally:
            cursor.close()
            conn.close()

    def fail_step(
        self,
        execution_id: str,
        step_id: str,
        error_message: str,
        error_category: str = "EXECUTION_ERROR",
        db_path: Path | str | None = None,
    ) -> StepExecutionRecord:
        """Atomically transition step execution status to FAILED."""
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        conn = get_connection(db_path)
        conn.isolation_level = None
        cursor = conn.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE;")
            cursor.execute(
                """
                UPDATE step_executions
                SET status = ?,
                    completed_at = ?,
                    error_category = ?,
                    error_message = ?
                WHERE execution_id = ? AND step_id = ?;
                """,
                (StepExecutionStatus.FAILED.value, now_iso, error_category, error_message, execution_id, step_id),
            )
            if cursor.rowcount == 0:
                cursor.execute("ROLLBACK;")
                raise StepExecutionError(f"Step execution not found for '{execution_id}:{step_id}'.")

            cursor.execute(
                """
                SELECT step_execution_id, execution_id, request_id, plan_hash, plan_version,
                       step_id, action_type, status, retry_count, started_at, completed_at,
                       error_category, error_message, output_summary
                FROM step_executions
                WHERE execution_id = ? AND step_id = ?;
                """,
                (execution_id, step_id),
            )
            row = cursor.fetchone()
            cursor.execute("COMMIT;")
            return self._row_to_record(row)
        except Exception:
            try:
                cursor.execute("ROLLBACK;")
            except Exception:
                pass
            raise
        finally:
            cursor.close()
            conn.close()

    def get_step_execution(
        self,
        execution_id: str,
        step_id: str,
        db_path: Path | str | None = None,
    ) -> StepExecutionRecord | None:
        """Retrieve step execution record if it exists."""
        conn = get_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT step_execution_id, execution_id, request_id, plan_hash, plan_version,
                       step_id, action_type, status, retry_count, started_at, completed_at,
                       error_category, error_message, output_summary
                FROM step_executions
                WHERE execution_id = ? AND step_id = ?;
                """,
                (execution_id, step_id),
            )
            row = cursor.fetchone()
            cursor.close()
            return self._row_to_record(row) if row else None
        finally:
            conn.close()

    def get_executions_for_request(
        self,
        request_id: str,
        db_path: Path | str | None = None,
    ) -> list[StepExecutionRecord]:
        """Retrieve all step execution records for a request ordered chronologically."""
        conn = get_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT step_execution_id, execution_id, request_id, plan_hash, plan_version,
                       step_id, action_type, status, retry_count, started_at, completed_at,
                       error_category, error_message, output_summary
                FROM step_executions
                WHERE request_id = ?
                ORDER BY started_at ASC;
                """,
                (request_id,),
            )
            rows = cursor.fetchall()
            cursor.close()
            return [self._row_to_record(row) for row in rows]
        finally:
            conn.close()

    get_all_executions_for_request = get_executions_for_request

    def _row_to_record(self, row: sqlite3.Row) -> StepExecutionRecord:
        """Map SQLite row to typed StepExecutionRecord model."""
        return StepExecutionRecord(
            step_execution_id=row["step_execution_id"],
            execution_id=row["execution_id"],
            request_id=row["request_id"],
            plan_hash=row["plan_hash"],
            plan_version=row["plan_version"],
            step_id=row["step_id"],
            action_type=StepActionType(row["action_type"]),
            status=StepExecutionStatus(row["status"]),
            retry_count=row["retry_count"],
            started_at=datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
            completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
            error_category=row["error_category"],
            error_message=row["error_message"],
            output_summary=json.loads(row["output_summary"]) if row["output_summary"] else {},
        )
