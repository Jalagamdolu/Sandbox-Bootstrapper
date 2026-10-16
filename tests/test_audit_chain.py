"""Tests for AuditChainService cryptographic event chaining and integrity verification."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import pytest

from src.models.audit import AuditActor
from src.models.enums import AuditEventType, AuditSeverity, WorkflowStatus
from src.security.audit_chain import AuditChainService, GENESIS_HASH
from src.storage.connection import get_connection


def test_append_and_verify_valid_chain(
    audit_service: AuditChainService,
    initialized_db_path: Path,
) -> None:
    """Verify sequential events are appended with valid cryptographic hash chaining from genesis."""
    actor = AuditActor(actor_id="admin-1", role="PROJECT_OWNER")
    req_id = "req-audit-01"

    # Append 3 sequential events
    e0 = audit_service.append_event(
        request_id=req_id,
        event_type=AuditEventType.REQUEST_CREATED,
        severity=AuditSeverity.INFO,
        actor=actor,
        action_name="CreateRequest",
        details={"project": "sandbox-demo"},
        state_after=WorkflowStatus.DRAFT,
        db_path=initialized_db_path,
    )
    assert e0.sequence_number == 0
    assert e0.previous_event_hash == GENESIS_HASH

    e1 = audit_service.append_event(
        request_id=req_id,
        event_type=AuditEventType.PLAN_GENERATED,
        severity=AuditSeverity.INFO,
        actor=actor,
        action_name="GeneratePlan",
        details={"steps_count": 3},
        state_before=WorkflowStatus.DRAFT,
        state_after=WorkflowStatus.PLANNING,
        db_path=initialized_db_path,
    )
    assert e1.sequence_number == 1
    assert e1.previous_event_hash == e0.event_hash

    e2 = audit_service.append_event(
        request_id=req_id,
        event_type=AuditEventType.APPROVAL_SUBMITTED,
        severity=AuditSeverity.SECURITY,
        actor=actor,
        action_name="ApprovePlan",
        details={"decision": "APPROVE"},
        state_before=WorkflowStatus.PENDING_APPROVAL,
        state_after=WorkflowStatus.APPROVED,
        db_path=initialized_db_path,
    )
    assert e2.sequence_number == 2
    assert e2.previous_event_hash == e1.event_hash

    # Verify chain
    report = audit_service.verify_chain(db_path=initialized_db_path)
    assert report.is_valid is True
    assert report.events_inspected == 3
    assert len(report.errors) == 0


def test_detect_payload_tampering(
    audit_service: AuditChainService,
    initialized_db_path: Path,
) -> None:
    """Verify tampering with details payload is detected by verify_chain."""
    actor = AuditActor(actor_id="dev-2", role="DEVELOPER")
    req_id = "req-audit-tamper"

    audit_service.append_event(
        request_id=req_id,
        event_type=AuditEventType.REQUEST_CREATED,
        severity=AuditSeverity.INFO,
        actor=actor,
        action_name="CreateRequest",
        details={"initial_quota": 5},
        db_path=initialized_db_path,
    )

    # In order to simulate attacker modifying the sqlite file, we drop the trigger temporarily
    conn = get_connection(initialized_db_path)
    cursor = conn.cursor()
    cursor.execute("DROP TRIGGER prevent_audit_update;")
    # Attacker tampers with the details payload
    cursor.execute(
        "UPDATE audit_log SET details = ? WHERE sequence_number = 0;",
        (json.dumps({"initial_quota": 9999}),),
    )
    conn.commit()
    conn.close()

    # Verification must detect payload tampering
    report = audit_service.verify_chain(db_path=initialized_db_path)
    assert report.is_valid is False
    assert any("Payload tampering detected" in err for err in report.errors)


def test_detect_broken_chain_or_missing_events(
    audit_service: AuditChainService,
    initialized_db_path: Path,
) -> None:
    """Verify sequence gaps or broken links are detected."""
    actor = AuditActor(actor_id="dev-3", role="DEVELOPER")
    req_id = "req-audit-gap"

    for i in range(3):
        audit_service.append_event(
            request_id=req_id,
            event_type=AuditEventType.STEP_COMPLETED,
            severity=AuditSeverity.INFO,
            actor=actor,
            action_name=f"Step-{i}",
            details={"step": i},
            db_path=initialized_db_path,
        )

    # Attacker drops trigger and deletes intermediate event (sequence 1)
    conn = get_connection(initialized_db_path)
    cursor = conn.cursor()
    cursor.execute("DROP TRIGGER prevent_audit_delete;")
    cursor.execute("DELETE FROM audit_log WHERE sequence_number = 1;")
    conn.commit()
    conn.close()

    report = audit_service.verify_chain(db_path=initialized_db_path)
    assert report.is_valid is False
    assert any("Sequence discontinuity" in err or "Broken hash link" in err for err in report.errors)


def test_audit_triggers_prevent_tampering(
    audit_service: AuditChainService,
    initialized_db_path: Path,
) -> None:
    """Verify standard application SQLite triggers block UPDATE and DELETE."""
    actor = AuditActor(actor_id="admin-4", role="PROJECT_OWNER")
    req_id = "req-trigger-test"

    event = audit_service.append_event(
        request_id=req_id,
        event_type=AuditEventType.REQUEST_CREATED,
        severity=AuditSeverity.INFO,
        actor=actor,
        action_name="CreateRequest",
        details={"status": "new"},
        db_path=initialized_db_path,
    )

    conn = get_connection(initialized_db_path)
    cursor = conn.cursor()

    # Attempting UPDATE raises DatabaseError/IntegrityError via RAISE(FAIL)
    with pytest.raises(sqlite3.DatabaseError, match="SECURITY VIOLATION.*Updates to audit_log"):
        cursor.execute("UPDATE audit_log SET action_name = 'Hacked' WHERE event_id = ?;", (event.event_id,))

    # Attempting DELETE raises DatabaseError/IntegrityError via RAISE(FAIL)
    with pytest.raises(sqlite3.DatabaseError, match="SECURITY VIOLATION.*Deletions from audit_log"):
        cursor.execute("DELETE FROM audit_log WHERE event_id = ?;", (event.event_id,))

    conn.close()


def test_secrets_redacted_from_audit_details(
    audit_service: AuditChainService,
    initialized_db_path: Path,
) -> None:
    """Verify passwords, bearer tokens, and API secrets are never stored in plaintext in the audit trail."""
    actor = AuditActor(actor_id="dev-sec", role="DEVELOPER")
    req_id = "req-redact-test"

    dirty_details = {
        "user_email": "dev@company.local",
        "password": "SuperSecretPassword123!",
        "api_token": "secret_token_abcdef123456",
        "nested": {
            "bearer_header": "Bearer raw_token_xyz987654321",
            "normal_field": "safe_value",
        },
    }

    event = audit_service.append_event(
        request_id=req_id,
        event_type=AuditEventType.REQUEST_CREATED,
        severity=AuditSeverity.INFO,
        actor=actor,
        action_name="LoginAttempt",
        details=dirty_details,
        db_path=initialized_db_path,
    )

    # Check event.details
    assert event.details["password"] == "[REDACTED]"
    assert event.details["api_token"] == "[REDACTED]"
    assert event.details["nested"]["bearer_header"] == "[REDACTED]"
    assert event.details["nested"]["normal_field"] == "safe_value"

    # Check database raw row
    conn = get_connection(initialized_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT details FROM audit_log WHERE event_id = ?;", (event.event_id,))
    stored_details_str = cursor.fetchone()[0]
    conn.close()

    assert "SuperSecretPassword123!" not in stored_details_str
    assert "secret_token_abcdef123456" not in stored_details_str
    assert "raw_token_xyz987654321" not in stored_details_str
    assert "[REDACTED]" in stored_details_str
