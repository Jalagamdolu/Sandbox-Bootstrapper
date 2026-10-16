"""Tests for AuditChainService concurrent writer serialization and hash-chain verification."""

from __future__ import annotations

import concurrent.futures
from pathlib import Path

from src.models.audit import AuditActor
from src.models.enums import AuditEventType, AuditSeverity, WorkflowStatus
from src.security.audit_chain import AuditChainService


def test_concurrent_audit_writers_serialize_cleanly(
    audit_service: AuditChainService,
    initialized_db_path: Path,
) -> None:
    """
    Simulate 10 concurrent threads appending audit events simultaneously.
    Verifies that SQLite BEGIN IMMEDIATE transaction serialization prevents
    sequence collisions, gaps, and broken hash links.
    """
    req_id = "req-audit-concur-01"
    num_threads = 10
    results: list[int] = []
    errors: list[Exception] = []

    def _worker(thread_idx: int) -> None:
        try:
            actor = AuditActor(actor_id=f"worker-{thread_idx}", role="DEVELOPER")
            event = audit_service.append_event(
                request_id=req_id,
                event_type=AuditEventType.STEP_COMPLETED,
                severity=AuditSeverity.INFO,
                actor=actor,
                action_name=f"ConcurrentAction-{thread_idx}",
                details={"worker": thread_idx, "payload": f"data-{thread_idx}"},
                state_before=WorkflowStatus.APPROVED,
                state_after=WorkflowStatus.APPROVED,
                db_path=initialized_db_path,
            )
            results.append(event.sequence_number)
        except Exception as e:
            errors.append(e)

    # Launch 10 parallel worker threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(_worker, i) for i in range(num_threads)]
        concurrent.futures.wait(futures)

    # All 10 threads must succeed without errors
    assert len(errors) == 0, f"Errors occurred during concurrent audit writes: {errors}"
    assert len(results) == num_threads

    # Verify that sequences are unique and form a complete set 0..9
    assert sorted(results) == list(range(num_threads))

    # Verify full cryptographic chain from genesis
    report = audit_service.verify_chain(db_path=initialized_db_path)
    assert report.is_valid is True
    assert report.events_inspected == num_threads
    assert len(report.errors) == 0
