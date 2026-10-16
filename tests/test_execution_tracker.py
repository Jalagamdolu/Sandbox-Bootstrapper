"""Tests for StepExecutionTracker state transitions, retry reconciliation, and conflict detection."""

from __future__ import annotations

from pathlib import Path
import pytest

from src.adapters.execution_tracker import StepExecutionTracker
from src.core.exceptions import ExecutionConflictError, StepExecutionError
from src.models.enums import StepActionType, StepExecutionStatus
from src.storage.connection import get_connection


def _setup_request(db_path: Path, request_id: str) -> None:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT OR IGNORE INTO bootstrap_requests (
            request_id, idempotency_key, project_name, template, repository_path,
            requested_scopes, developer_id, target_environment, status, created_at, updated_at
        ) VALUES (?, ?, 'proj', 'python-fastapi-service', 'c:/repos/proj', '[]', 'dev-1', 'local', 'APPROVED', '2026-01-01', '2026-01-01');
        """,
        (request_id, f"idem-{request_id}"),
    )
    conn.commit()
    conn.close()


def test_execution_state_transitions(
    execution_tracker: StepExecutionTracker,
    initialized_db_path: Path,
) -> None:
    """Verify clean state progression from RUNNING to COMPLETED and retrieval."""
    req_id = "req-exec-01"
    _setup_request(initialized_db_path, req_id)

    # 1. Start step
    record = execution_tracker.start_step(
        execution_id="exec-run-1",
        request_id=req_id,
        plan_hash="a" * 64,
        plan_version=1,
        step_id="step-00000001",
        action_type=StepActionType.PROVISION_MOCK_SANDBOX,
        db_path=initialized_db_path,
    )
    assert record.status == StepExecutionStatus.RUNNING
    assert record.retry_count == 0
    assert record.started_at is not None
    assert record.completed_at is None

    # 2. Complete step
    completed = execution_tracker.complete_step(
        execution_id="exec-run-1",
        step_id="step-00000001",
        output_summary={"sandbox_id": "sbx-123"},
        db_path=initialized_db_path,
    )
    assert completed.status == StepExecutionStatus.COMPLETED
    assert completed.completed_at is not None
    assert completed.output_summary["sandbox_id"] == "sbx-123"

    # 3. Retrieve step
    retrieved = execution_tracker.get_step_execution("exec-run-1", "step-00000001", db_path=initialized_db_path)
    assert retrieved is not None
    assert retrieved.status == StepExecutionStatus.COMPLETED


def test_failed_step_retry_increments_count(
    execution_tracker: StepExecutionTracker,
    initialized_db_path: Path,
) -> None:
    """Verify failing a step and retrying transitions back to RUNNING and increments retry_count."""
    req_id = "req-exec-fail"
    _setup_request(initialized_db_path, req_id)

    # Start
    execution_tracker.start_step(
        execution_id="exec-run-2",
        request_id=req_id,
        plan_hash="b" * 64,
        plan_version=1,
        step_id="step-00000001",
        action_type=StepActionType.PROVISION_MOCK_SANDBOX,
        db_path=initialized_db_path,
    )

    # Fail
    failed = execution_tracker.fail_step(
        execution_id="exec-run-2",
        step_id="step-00000001",
        error_message="Disk quota exceeded",
        error_category="QUOTA_EXCEEDED",
        db_path=initialized_db_path,
    )
    assert failed.status == StepExecutionStatus.FAILED
    assert failed.error_message == "Disk quota exceeded"
    assert failed.error_category == "QUOTA_EXCEEDED"

    # Retry with same execution ID
    retried = execution_tracker.start_step(
        execution_id="exec-run-2",
        request_id=req_id,
        plan_hash="b" * 64,
        plan_version=1,
        step_id="step-00000001",
        action_type=StepActionType.PROVISION_MOCK_SANDBOX,
        db_path=initialized_db_path,
    )
    assert retried.status == StepExecutionStatus.RUNNING
    assert retried.retry_count == 1
    assert retried.error_message is None


def test_completed_step_skips_duplicate_work(
    execution_tracker: StepExecutionTracker,
    initialized_db_path: Path,
) -> None:
    """Verify calling start_step on an already completed step returns COMPLETED without error."""
    req_id = "req-exec-skip"
    _setup_request(initialized_db_path, req_id)

    execution_tracker.start_step(
        execution_id="exec-run-3",
        request_id=req_id,
        plan_hash="c" * 64,
        plan_version=1,
        step_id="step-00000001",
        action_type=StepActionType.PROVISION_MOCK_SANDBOX,
        db_path=initialized_db_path,
    )
    execution_tracker.complete_step(
        execution_id="exec-run-3",
        step_id="step-00000001",
        output_summary={"ok": True},
        db_path=initialized_db_path,
    )

    # Re-call start_step on completed step
    rec = execution_tracker.start_step(
        execution_id="exec-run-3",
        request_id=req_id,
        plan_hash="c" * 64,
        plan_version=1,
        step_id="step-00000001",
        action_type=StepActionType.PROVISION_MOCK_SANDBOX,
        db_path=initialized_db_path,
    )
    assert rec.status == StepExecutionStatus.COMPLETED


def test_concurrent_execution_detected_and_rejected(
    execution_tracker: StepExecutionTracker,
    initialized_db_path: Path,
) -> None:
    """Verify that if a step is RUNNING, a concurrent call to start_step raises ExecutionConflictError."""
    req_id = "req-exec-race"
    _setup_request(initialized_db_path, req_id)

    # Thread 1 starts step (now RUNNING)
    execution_tracker.start_step(
        execution_id="exec-run-4",
        request_id=req_id,
        plan_hash="d" * 64,
        plan_version=1,
        step_id="step-00000001",
        action_type=StepActionType.PROVISION_MOCK_SANDBOX,
        db_path=initialized_db_path,
    )

    # Thread 2 attempts to start same step while RUNNING
    with pytest.raises(ExecutionConflictError, match="already RUNNING"):
        execution_tracker.start_step(
            execution_id="exec-run-4",
            request_id=req_id,
            plan_hash="d" * 64,
            plan_version=1,
            step_id="step-00000001",
            action_type=StepActionType.PROVISION_MOCK_SANDBOX,
            db_path=initialized_db_path,
        )


def test_mismatched_plan_hash_rejected(
    execution_tracker: StepExecutionTracker,
    initialized_db_path: Path,
) -> None:
    """Verify starting a step with mismatched plan hash raises ExecutionConflictError."""
    req_id = "req-exec-hash-mismatch"
    _setup_request(initialized_db_path, req_id)

    execution_tracker.start_step(
        execution_id="exec-run-5",
        request_id=req_id,
        plan_hash="e" * 64,
        plan_version=1,
        step_id="step-00000001",
        action_type=StepActionType.PROVISION_MOCK_SANDBOX,
        db_path=initialized_db_path,
    )

    # Second step with different plan hash for same execution
    with pytest.raises(ExecutionConflictError, match="Mismatched plan hash"):
        execution_tracker.start_step(
            execution_id="exec-run-5",
            request_id=req_id,
            plan_hash="f" * 64,
            plan_version=1,
            step_id="step-00000002",
            action_type=StepActionType.SEED_SYNTHETIC_DATA,
            db_path=initialized_db_path,
        )
