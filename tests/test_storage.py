"""Tests for SQLite database initialization, transaction rollback, and triggers."""

from __future__ import annotations

import sqlite3
from pathlib import Path
import pytest

from src.core.exceptions import DatabaseError
from src.storage.connection import get_connection, transaction_scope
from src.storage.db_init import initialize_database


def test_db_initialization_tables_created(initialized_db: sqlite3.Connection) -> None:
    """Verify all 8 documented tables and their indexes exist after initialization."""
    cursor = initialized_db.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = {row["name"] for row in cursor.fetchall()}

    expected_tables = {
        "approver_tokens",
        "bootstrap_requests",
        "setup_plans",
        "approval_records",
        "tracked_resources",
        "workflow_checkpoints",
        "step_executions",
        "audit_log",
    }
    assert expected_tables.issubset(tables)

    # Verify triggers exist
    cursor.execute("SELECT name FROM sqlite_master WHERE type='trigger';")
    triggers = {row["name"] for row in cursor.fetchall()}
    expected_triggers = {
        "prevent_audit_update",
        "prevent_audit_delete",
        "revoke_approvals_on_plan_change",
    }
    assert expected_triggers.issubset(triggers)
    cursor.close()


def test_repeat_initialization_idempotent_and_preserves_data(isolated_db_path: Path) -> None:
    """Verify initialize_database can be rerun safely on an existing database without data loss."""
    initialize_database(isolated_db_path)

    # Insert a test record
    conn = get_connection(isolated_db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO bootstrap_requests (
            request_id, idempotency_key, project_name, template, repository_path,
            requested_scopes, developer_id, target_environment, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            "req-001",
            "idem-key-1",
            "test-proj",
            "python-fastapi-service",
            "c:/repos/proj",
            '["sandbox:read"]',
            "dev-1",
            "local-sandbox",
            "DRAFT",
            "2026-10-16T10:00:00Z",
            "2026-10-16T10:00:00Z",
        ),
    )
    conn.commit()
    conn.close()

    # Rerun initialization
    initialize_database(isolated_db_path)

    # Verify data remains intact
    conn = get_connection(isolated_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT project_name FROM bootstrap_requests WHERE request_id = 'req-001';")
    row = cursor.fetchone()
    assert row is not None
    assert row["project_name"] == "test-proj"
    conn.close()


def test_foreign_key_enforcement(initialized_db: sqlite3.Connection) -> None:
    """Verify that foreign keys are enforced and child records without parent fail."""
    cursor = initialized_db.cursor()

    # Attempt to insert setup_plan referencing non-existent request_id
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY constraint failed"):
        cursor.execute(
            """
            INSERT INTO setup_plans (
                plan_id, request_id, plan_version, target_environment, canonical_plan_hash, plan_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (
                "plan-001",
                "non-existent-request-id",
                1,
                "local-sandbox",
                "a" * 64,
                "{}",
                "2026-10-16T10:00:00Z",
            ),
        )
    cursor.close()


def test_idempotency_key_uniqueness(initialized_db: sqlite3.Connection) -> None:
    """Verify that duplicate idempotency keys are rejected by unique constraint."""
    cursor = initialized_db.cursor()
    cursor.execute(
        """
        INSERT INTO bootstrap_requests (
            request_id, idempotency_key, project_name, template, repository_path,
            requested_scopes, developer_id, target_environment, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            "req-1",
            "shared-idempotency-key",
            "proj-1",
            "python-fastapi-service",
            "c:/repos/1",
            '["sandbox:read"]',
            "dev-1",
            "local-sandbox",
            "DRAFT",
            "2026-10-16T10:00:00Z",
            "2026-10-16T10:00:00Z",
        ),
    )
    initialized_db.commit()

    # Attempt to insert duplicate idempotency key
    with pytest.raises(sqlite3.IntegrityError, match="UNIQUE constraint failed"):
        cursor.execute(
            """
            INSERT INTO bootstrap_requests (
                request_id, idempotency_key, project_name, template, repository_path,
                requested_scopes, developer_id, target_environment, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                "req-2",
                "shared-idempotency-key",
                "proj-2",
                "node-microservice",
                "c:/repos/2",
                '["sandbox:read"]',
                "dev-2",
                "local-sandbox",
                "DRAFT",
                "2026-10-16T10:00:00Z",
                "2026-10-16T10:00:00Z",
            ),
        )
    cursor.close()


def test_transaction_scope_rollback(initialized_db: sqlite3.Connection) -> None:
    """Verify transaction_scope rolls back changes when an exception occurs."""
    with pytest.raises(DatabaseError):
        with transaction_scope(initialized_db) as cursor:
            cursor.execute(
                """
                INSERT INTO bootstrap_requests (
                    request_id, idempotency_key, project_name, template, repository_path,
                    requested_scopes, developer_id, target_environment, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    "req-rollback",
                    "rollback-key",
                    "proj-rollback",
                    "python-fastapi-service",
                    "c:/repos/rb",
                    '["sandbox:read"]',
                    "dev-rb",
                    "local-sandbox",
                    "DRAFT",
                    "2026-10-16T10:00:00Z",
                    "2026-10-16T10:00:00Z",
                ),
            )
            # Simulate unexpected failure
            raise RuntimeError("Simulated failure mid-transaction")

    # Verify record was rolled back
    cursor = initialized_db.cursor()
    cursor.execute("SELECT * FROM bootstrap_requests WHERE request_id = 'req-rollback';")
    assert cursor.fetchone() is None
    cursor.close()


def test_audit_log_prevent_update_trigger(initialized_db: sqlite3.Connection) -> None:
    """Verify application-level trigger blocks any UPDATE operation on audit_log."""
    cursor = initialized_db.cursor()
    cursor.execute(
        """
        INSERT INTO audit_log (
            event_id, request_id, sequence_number, timestamp, event_type, severity,
            actor_id, actor_role, action_name, state_before, state_after,
            previous_event_hash, payload_hash, event_hash, details
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            "evt-001",
            "req-001",
            1,
            "2026-10-16T10:00:00Z",
            "REQUEST_CREATED",
            "INFO",
            "dev-1",
            "DEVELOPER",
            "CreateRequest",
            "NONE",
            "DRAFT",
            "0" * 64,
            "1" * 64,
            "2" * 64,
            "{}",
        ),
    )
    initialized_db.commit()

    # Attempt to tamper with audit record
    with pytest.raises(sqlite3.DatabaseError, match="SECURITY VIOLATION: Updates to audit_log table are forbidden"):
        cursor.execute("UPDATE audit_log SET details = '{\"tampered\": true}' WHERE event_id = 'evt-001';")

    cursor.close()


def test_audit_log_prevent_delete_trigger(initialized_db: sqlite3.Connection) -> None:
    """Verify application-level trigger blocks any DELETE operation on audit_log."""
    cursor = initialized_db.cursor()
    cursor.execute(
        """
        INSERT INTO audit_log (
            event_id, request_id, sequence_number, timestamp, event_type, severity,
            actor_id, actor_role, action_name, state_before, state_after,
            previous_event_hash, payload_hash, event_hash, details
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            "evt-002",
            "req-002",
            1,
            "2026-10-16T10:00:00Z",
            "REQUEST_CREATED",
            "INFO",
            "dev-1",
            "DEVELOPER",
            "CreateRequest",
            "NONE",
            "DRAFT",
            "0" * 64,
            "1" * 64,
            "2" * 64,
            "{}",
        ),
    )
    initialized_db.commit()

    # Attempt to delete audit record
    with pytest.raises(sqlite3.DatabaseError, match="SECURITY VIOLATION: Deletions from audit_log table are forbidden"):
        cursor.execute("DELETE FROM audit_log WHERE event_id = 'evt-002';")

    cursor.close()


def test_no_raw_token_persistence(initialized_db: sqlite3.Connection) -> None:
    """Verify approver_tokens table stores SHA-256 token hash and contains no raw token column."""
    cursor = initialized_db.cursor()
    cursor.execute("PRAGMA table_info(approver_tokens);")
    columns = {row["name"] for row in cursor.fetchall()}

    assert "token_hash" in columns
    assert "token" not in columns
    assert "raw_token" not in columns

    # Insert a hashed token
    cursor.execute(
        """
        INSERT INTO approver_tokens (
            token_hash, approver_id, role, authorized_scopes, created_at, revoked_at
        ) VALUES (?, ?, ?, ?, ?, ?);
        """,
        (
            "f" * 64,
            "sec-lead-1",
            "SECURITY_APPROVER",
            '["sandbox:create"]',
            "2026-10-16T10:00:00Z",
            None,
        ),
    )
    initialized_db.commit()
    cursor.close()


def test_revoke_approvals_on_plan_change_trigger(initialized_db: sqlite3.Connection) -> None:
    """Verify updating a plan automatically marks unconsumed approvals as is_revoked = 1."""
    cursor = initialized_db.cursor()

    # 1. Create parent request
    cursor.execute(
        """
        INSERT INTO bootstrap_requests (
            request_id, idempotency_key, project_name, template, repository_path,
            requested_scopes, developer_id, target_environment, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            "req-drift",
            "drift-key",
            "proj-drift",
            "python-fastapi-service",
            "c:/repos/drift",
            '["sandbox:create"]',
            "dev-1",
            "local-sandbox",
            "PENDING_APPROVAL",
            "2026-10-16T10:00:00Z",
            "2026-10-16T10:00:00Z",
        ),
    )

    # 2. Create setup plan
    cursor.execute(
        """
        INSERT INTO setup_plans (
            plan_id, request_id, plan_version, target_environment, canonical_plan_hash, plan_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?);
        """,
        (
            "plan-drift",
            "req-drift",
            1,
            "local-sandbox",
            "1" * 64,
            '{"steps": []}',
            "2026-10-16T10:00:00Z",
        ),
    )

    # 3. Create approval record
    cursor.execute(
        """
        INSERT INTO approval_records (
            approval_id, request_id, approver_id, decision, canonical_plan_hash,
            plan_version, target_environment, granted_scopes, created_at, expires_at,
            is_revoked, execution_consumed
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            "appr-drift",
            "req-drift",
            "sec-lead-1",
            "APPROVE",
            "1" * 64,
            1,
            "local-sandbox",
            '["sandbox:create"]',
            "2026-10-16T10:00:00Z",
            "2026-10-16T10:30:00Z",
            0,
            0,
        ),
    )
    initialized_db.commit()

    # 4. Mutate the plan
    cursor.execute(
        """
        UPDATE setup_plans 
        SET canonical_plan_hash = ?, plan_version = 2 
        WHERE plan_id = 'plan-drift';
        """,
        ("2" * 64,),
    )
    initialized_db.commit()

    # 5. Verify trigger automatically updated approval record to is_revoked = 1
    cursor.execute("SELECT is_revoked, rejection_reason FROM approval_records WHERE approval_id = 'appr-drift';")
    row = cursor.fetchone()
    assert row is not None
    assert row["is_revoked"] == 1
    assert "AUTOMATICALLY_REVOKED" in row["rejection_reason"]
    cursor.close()


def test_get_connection_memory_db() -> None:
    """Verify get_connection works with in-memory database (:memory:)."""
    conn = get_connection(":memory:")
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys;")
    row = cursor.fetchone()
    assert row[0] == 1  # Foreign keys enabled
    conn.close()


def test_get_connection_default_settings_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify get_connection uses settings.database_path when db_path is None."""
    custom_db = tmp_path / "default_from_settings.db"
    monkeypatch.setenv("DATABASE_PATH", str(custom_db))
    from src.core.config import get_settings
    get_settings(reload=True)

    conn = get_connection(None)
    assert custom_db.is_file()
    conn.close()


def test_db_init_cli_script(tmp_path: Path) -> None:
    """Verify db_init module executes cleanly via CLI with an explicit target database argument."""
    import subprocess
    import sys

    target_db = tmp_path / "cli_init.db"
    result = subprocess.run(
        [sys.executable, "-m", "src.storage.db_init", str(target_db)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "Database schema successfully initialized" in result.stdout
    assert target_db.is_file()
