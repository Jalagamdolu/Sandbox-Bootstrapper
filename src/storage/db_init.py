"""Database schema initialization and idempotent migration script."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

from src.core.config import get_settings
from src.core.exceptions import DatabaseError
from src.storage.connection import get_connection

SCHEMA_SQL = """
-- 1. Approver Tokens (Hashed at rest via SHA-256; raw tokens are NEVER stored)
CREATE TABLE IF NOT EXISTS approver_tokens (
    token_hash TEXT PRIMARY KEY,
    approver_id TEXT NOT NULL,
    role TEXT NOT NULL,
    authorized_scopes TEXT NOT NULL, -- JSON array of PermissionScope strings
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

-- 2. Bootstrap Requests
CREATE TABLE IF NOT EXISTS bootstrap_requests (
    request_id TEXT PRIMARY KEY,
    idempotency_key TEXT UNIQUE NOT NULL,
    project_name TEXT NOT NULL,
    template TEXT NOT NULL,
    repository_path TEXT NOT NULL,
    requested_scopes TEXT NOT NULL, -- JSON array of PermissionScope strings
    developer_id TEXT NOT NULL,
    target_environment TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_requests_status ON bootstrap_requests(status);
CREATE INDEX IF NOT EXISTS idx_requests_idempotency ON bootstrap_requests(idempotency_key);

-- 3. Setup Plans
CREATE TABLE IF NOT EXISTS setup_plans (
    plan_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    plan_version INTEGER NOT NULL DEFAULT 1,
    target_environment TEXT NOT NULL,
    canonical_plan_hash TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (request_id) REFERENCES bootstrap_requests(request_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_plans_request ON setup_plans(request_id);
CREATE INDEX IF NOT EXISTS idx_plans_hash ON setup_plans(canonical_plan_hash);

-- Automated Invalidation Trigger: Plan or scope mutation immediately revokes prior unconsumed approvals
CREATE TRIGGER IF NOT EXISTS revoke_approvals_on_plan_change
AFTER UPDATE ON setup_plans
BEGIN
    UPDATE approval_records 
    SET is_revoked = 1,
        rejection_reason = 'AUTOMATICALLY_REVOKED: Plan altered post-approval'
    WHERE request_id = NEW.request_id AND execution_consumed = 0;
END;

-- 4. Approval Records (Server-Side Authenticated Source of Truth)
CREATE TABLE IF NOT EXISTS approval_records (
    approval_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    approver_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('APPROVE', 'REJECT')),
    canonical_plan_hash TEXT NOT NULL,
    plan_version INTEGER NOT NULL DEFAULT 1,
    target_environment TEXT NOT NULL,
    granted_scopes TEXT NOT NULL, -- JSON array of PermissionScope strings
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    rejection_reason TEXT,
    is_revoked INTEGER NOT NULL DEFAULT 0 CHECK(is_revoked IN (0, 1)),
    execution_consumed INTEGER NOT NULL DEFAULT 0 CHECK(execution_consumed IN (0, 1)),
    consumed_at TEXT,
    execution_id TEXT,
    FOREIGN KEY (request_id) REFERENCES bootstrap_requests(request_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_approvals_request ON approval_records(request_id);
CREATE INDEX IF NOT EXISTS idx_approvals_hash ON approval_records(canonical_plan_hash);

-- 5. Resource Ownership (Guarantees safe compensation and prevents orphaned directories)
CREATE TABLE IF NOT EXISTS tracked_resources (
    resource_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    filesystem_path TEXT NOT NULL,
    ownership_token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    is_quarantined INTEGER NOT NULL DEFAULT 0 CHECK(is_quarantined IN (0, 1)),
    FOREIGN KEY (request_id) REFERENCES bootstrap_requests(request_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_resources_request ON tracked_resources(request_id);
CREATE INDEX IF NOT EXISTS idx_resources_expires ON tracked_resources(expires_at);

-- 6. Workflow Checkpoints (LangGraph State)
CREATE TABLE IF NOT EXISTS workflow_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    current_status TEXT NOT NULL,
    state_payload TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (request_id) REFERENCES bootstrap_requests(request_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_checkpoints_request ON workflow_checkpoints(request_id);

-- 7. Step Executions
CREATE TABLE IF NOT EXISTS step_executions (
    step_execution_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    plan_hash TEXT NOT NULL,
    plan_version INTEGER NOT NULL DEFAULT 1,
    step_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    status TEXT NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    started_at TEXT,
    completed_at TEXT,
    error_category TEXT,
    error_message TEXT,
    output_summary TEXT,
    FOREIGN KEY (request_id) REFERENCES bootstrap_requests(request_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_step_exec_run_step ON step_executions(execution_id, step_id);
CREATE INDEX IF NOT EXISTS idx_steps_request ON step_executions(request_id);
CREATE INDEX IF NOT EXISTS idx_steps_status ON step_executions(status);

-- 8. Hash-Chained Audit Log
CREATE TABLE IF NOT EXISTS audit_log (
    event_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    sequence_number INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    action_name TEXT NOT NULL,
    state_before TEXT,
    state_after TEXT,
    previous_event_hash TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    details TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_seq ON audit_log(sequence_number);
CREATE INDEX IF NOT EXISTS idx_audit_request ON audit_log(request_id);

-- Application-Level Triggers Blocking Audit Alteration
-- NOTE: Provides application-level append-only protection.
-- Does NOT guarantee disk-level physical immutability if database file is modified directly.
CREATE TRIGGER IF NOT EXISTS prevent_audit_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(FAIL, 'SECURITY VIOLATION: Updates to audit_log table are forbidden.');
END;

CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(FAIL, 'SECURITY VIOLATION: Deletions from audit_log table are forbidden.');
END;
"""


def initialize_database(db_path: Path | str | None = None) -> None:
    """
    Idempotently initialize all database tables, indexes, and triggers.

    This function is safe to rerun repeatedly on an existing database without
    altering, destroying, or resetting existing data.

    Args:
        db_path: Optional explicit database path. If None, uses settings.database_path.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.executescript(SCHEMA_SQL)
        # Safe idempotent column migration for existing databases
        cursor.execute("PRAGMA table_info(approval_records);")
        existing_cols = {row["name"] for row in cursor.fetchall()}
        if "execution_id" not in existing_cols:
            cursor.execute("ALTER TABLE approval_records ADD COLUMN execution_id TEXT;")

        # Safe idempotent migration for step_executions
        cursor.execute("PRAGMA table_info(step_executions);")
        existing_step_cols = {row["name"] for row in cursor.fetchall()}
        if existing_step_cols and "step_execution_id" not in existing_step_cols:
            cursor.execute("SELECT count(*) FROM step_executions;")
            if cursor.fetchone()[0] == 0:
                cursor.execute("DROP TABLE step_executions;")
                cursor.execute(
                    """
                    CREATE TABLE step_executions (
                        step_execution_id TEXT PRIMARY KEY,
                        execution_id TEXT NOT NULL,
                        request_id TEXT NOT NULL,
                        plan_hash TEXT NOT NULL,
                        plan_version INTEGER NOT NULL DEFAULT 1,
                        step_id TEXT NOT NULL,
                        action_type TEXT NOT NULL,
                        status TEXT NOT NULL,
                        retry_count INTEGER NOT NULL DEFAULT 0,
                        started_at TEXT,
                        completed_at TEXT,
                        error_category TEXT,
                        error_message TEXT,
                        output_summary TEXT,
                        FOREIGN KEY (request_id) REFERENCES bootstrap_requests(request_id) ON DELETE CASCADE
                    );
                    """
                )
                cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_step_exec_run_step ON step_executions(execution_id, step_id);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_steps_request ON step_executions(request_id);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_steps_status ON step_executions(status);")
            else:
                if "plan_hash" not in existing_step_cols:
                    cursor.execute("ALTER TABLE step_executions ADD COLUMN plan_hash TEXT;")
                if "plan_version" not in existing_step_cols:
                    cursor.execute("ALTER TABLE step_executions ADD COLUMN plan_version INTEGER DEFAULT 1;")
                if "error_category" not in existing_step_cols:
                    cursor.execute("ALTER TABLE step_executions ADD COLUMN error_category TEXT;")

        conn.commit()
        cursor.close()
    except sqlite3.Error as e:
        raise DatabaseError(f"Database schema initialization failed: {e}") from e
    finally:
        conn.close()


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else str(get_settings().database_path)
    print(f"Initializing Developer Sandbox Bootstrapper database at: {target}")
    try:
        initialize_database(target)
        print("Database schema successfully initialized.")
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
