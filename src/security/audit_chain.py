"""Audit trail logging and cryptographic hash-chain verification service."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import sqlite3

from src.core.exceptions import AuditChainIntegrityError, DatabaseError
from src.models.audit import AuditActor, AuditEvent
from src.models.enums import AuditEventType, AuditSeverity, WorkflowStatus
from src.security.canonicalization import canonicalize
from src.storage.connection import get_connection, transaction_scope

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class VerificationReport:
    """Result of audit hash chain integrity audit."""

    is_valid: bool
    events_inspected: int
    errors: list[str]


def scrub_secrets(data: Any) -> Any:
    """Recursively redact passwords, bearer tokens, and private credentials."""
    if isinstance(data, dict):
        clean_dict: dict[str, Any] = {}
        sensitive_pattern = re.compile(r"(password|token|secret|authorization|bearer|private_key|api_key)", re.I)
        for k, v in data.items():
            if sensitive_pattern.search(str(k)):
                clean_dict[k] = "[REDACTED]"
            else:
                clean_dict[k] = scrub_secrets(v)
        return clean_dict
    if isinstance(data, (list, tuple)):
        return [scrub_secrets(item) for item in data]
    if isinstance(data, str):
        # Scrub Bearer tokens in text
        return re.sub(r"(Bearer\s+)[A-Za-z0-9_\-\.]{10,}", r"\1[REDACTED]", data, flags=re.IGNORECASE)
    return data


def compute_payload_hash(details: dict[str, Any]) -> str:
    """Compute deterministic SHA-256 hash of the canonical scrubbed details."""
    clean = scrub_secrets(details)
    return canonicalize(clean).sha256_digest


def compute_event_hash(
    sequence_number: int,
    previous_event_hash: str,
    timestamp_iso: str,
    event_type: str,
    severity: str,
    actor_id: str,
    actor_role: str,
    action_name: str,
    state_before: str | None,
    state_after: str | None,
    payload_hash: str,
) -> str:
    """
    Compute cryptographic SHA-256 hash linking the previous event hash
    and all event attributes into the immutable hash chain.
    """
    envelope = {
        "action_name": action_name,
        "actor_id": actor_id,
        "actor_role": actor_role,
        "event_type": event_type,
        "payload_hash": payload_hash,
        "previous_event_hash": previous_event_hash,
        "sequence_number": sequence_number,
        "severity": severity,
        "state_after": state_after,
        "state_before": state_before,
        "timestamp": timestamp_iso,
    }
    return canonicalize(envelope).sha256_digest


class AuditChainService:
    """
    Appends events to the local SQLite audit log with cryptographic hash-chaining,
    and provides comprehensive chain verification from genesis.

    Security Boundary Note:
    Protects against application errors, concurrent race conditions, and SQL injection.
    Does NOT guarantee physical immutability against an OS administrator with direct file write access.
    """

    def append_event(
        self,
        request_id: str,
        event_type: AuditEventType,
        severity: AuditSeverity,
        actor: AuditActor,
        action_name: str,
        details: dict[str, Any],
        state_before: WorkflowStatus | None = None,
        state_after: WorkflowStatus | None = None,
        db_path: Path | str | None = None,
    ) -> AuditEvent:
        """
        Append a cryptographically chained audit event record.
        Enforces monotonic sequence numbering and links to the previous event's hash.

        Args:
            request_id: Bootstrap request ID.
            event_type: Categorized event type.
            severity: Severity level.
            actor: Identity of actor initiating the action.
            action_name: Distinct action name.
            details: Event metadata dictionary (secrets are automatically redacted).
            state_before: Optional status before state transition.
            state_after: Optional status after state transition.
            db_path: Optional explicit database path.

        Returns:
            The persisted, immutable AuditEvent model.
        """
        clean_details = scrub_secrets(details)
        payload_hash = compute_payload_hash(clean_details)
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        event_id = f"evt-{uuid.uuid4().hex[:12]}"

        conn = get_connection(db_path)
        conn.isolation_level = None  # Autocommit mode for explicit BEGIN IMMEDIATE transaction management
        cursor = conn.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE;")
            # Retrieve preceding event in chain under exclusive write lock
            cursor.execute(
                """
                SELECT sequence_number, event_hash
                FROM audit_log
                ORDER BY sequence_number DESC
                LIMIT 1;
                """
            )
            last_row = cursor.fetchone()

            if last_row is None:
                sequence_number = 0
                previous_event_hash = GENESIS_HASH
            else:
                sequence_number = last_row["sequence_number"] + 1
                previous_event_hash = last_row["event_hash"]

            state_before_val = state_before.value if state_before else None
            state_after_val = state_after.value if state_after else None

            event_hash = compute_event_hash(
                sequence_number=sequence_number,
                previous_event_hash=previous_event_hash,
                timestamp_iso=now_iso,
                event_type=event_type.value,
                severity=severity.value,
                actor_id=actor.actor_id,
                actor_role=actor.role,
                action_name=action_name,
                state_before=state_before_val,
                state_after=state_after_val,
                payload_hash=payload_hash,
            )

            cursor.execute(
                """
                INSERT INTO audit_log (
                    event_id, request_id, sequence_number, timestamp, event_type,
                    severity, actor_id, actor_role, action_name, state_before,
                    state_after, previous_event_hash, payload_hash, event_hash, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    event_id,
                    request_id,
                    sequence_number,
                    now_iso,
                    event_type.value,
                    severity.value,
                    actor.actor_id,
                    actor.role,
                    action_name,
                    state_before_val,
                    state_after_val,
                    previous_event_hash,
                    payload_hash,
                    event_hash,
                    json.dumps(clean_details),
                ),
            )
            cursor.execute("COMMIT;")
        except Exception:
            try:
                cursor.execute("ROLLBACK;")
            except Exception:
                pass
            raise
        finally:
            cursor.close()
            conn.close()

        return AuditEvent(
            event_id=event_id,
            request_id=request_id,
            sequence_number=sequence_number,
            timestamp=now,
            event_type=event_type,
            severity=severity,
            actor=actor,
            action_name=action_name,
            state_before=state_before,
            state_after=state_after,
            previous_event_hash=previous_event_hash,
            payload_hash=payload_hash,
            event_hash=event_hash,
            details=clean_details,
        )

    def verify_chain(self, db_path: Path | str | None = None) -> VerificationReport:
        """
        Verify the entire audit log hash-chain from genesis.

        Detects:
        - Altered payload details (payload_hash mismatch).
        - Altered event hashes (event_hash mismatch).
        - Broken chain links (previous_event_hash mismatch).
        - Sequence gaps or missing records.
        - Out-of-order sequence numbering.

        Args:
            db_path: Optional explicit database path.

        Returns:
            VerificationReport indicating overall validity and specific error descriptions.
        """
        conn = get_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT event_id, request_id, sequence_number, timestamp, event_type,
                       severity, actor_id, actor_role, action_name, state_before,
                       state_after, previous_event_hash, payload_hash, event_hash, details
                FROM audit_log
                ORDER BY sequence_number ASC;
                """
            )
            rows = cursor.fetchall()
            cursor.close()
        finally:
            conn.close()

        if not rows:
            return VerificationReport(is_valid=True, events_inspected=0, errors=[])

        errors: list[str] = []
        expected_prev_hash = GENESIS_HASH

        for idx, row in enumerate(rows):
            seq = row["sequence_number"]
            event_id = row["event_id"]

            # 1. Verify sequence numbers are strictly 0, 1, 2, ...
            if seq != idx:
                errors.append(
                    f"Sequence discontinuity at event '{event_id}': expected sequence {idx}, found {seq}."
                )

            # 2. Verify previous_event_hash linkage
            prev_hash = row["previous_event_hash"]
            if prev_hash != expected_prev_hash:
                errors.append(
                    f"Broken hash link at sequence {seq} (event '{event_id}'): "
                    f"expected previous_event_hash '{expected_prev_hash}', found '{prev_hash}'."
                )

            # 3. Verify payload_hash matches stored details
            try:
                details = json.loads(row["details"])
                recomputed_payload_hash = compute_payload_hash(details)
                if recomputed_payload_hash != row["payload_hash"]:
                    errors.append(
                        f"Payload tampering detected at sequence {seq} (event '{event_id}'): "
                        f"expected payload_hash '{recomputed_payload_hash}', found '{row['payload_hash']}'."
                    )
            except Exception as e:
                errors.append(f"Invalid JSON details payload at sequence {seq} (event '{event_id}'): {e}")

            # 4. Recompute and verify event_hash
            recomputed_event_hash = compute_event_hash(
                sequence_number=seq,
                previous_event_hash=prev_hash,
                timestamp_iso=row["timestamp"],
                event_type=row["event_type"],
                severity=row["severity"],
                actor_id=row["actor_id"],
                actor_role=row["actor_role"],
                action_name=row["action_name"],
                state_before=row["state_before"],
                state_after=row["state_after"],
                payload_hash=row["payload_hash"],
            )

            if recomputed_event_hash != row["event_hash"]:
                errors.append(
                    f"Event hash tampering detected at sequence {seq} (event '{event_id}'): "
                    f"recomputed hash '{recomputed_event_hash}' does not match stored hash '{row['event_hash']}'."
                )

            # Advance expected previous hash for next iteration
            expected_prev_hash = row["event_hash"]

        return VerificationReport(
            is_valid=len(errors) == 0,
            events_inspected=len(rows),
            errors=errors,
        )
