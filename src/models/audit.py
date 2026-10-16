"""Audit event and hash-chain data contracts for Developer Sandbox Bootstrapper."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from src.models.enums import AuditEventType, AuditSeverity, WorkflowStatus


class AuditActor(BaseModel):
    """Identity and origin of an actor initiating an auditable action."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    actor_id: str = Field(..., min_length=1, max_length=64, description="User or system actor identifier")
    role: str = Field(..., min_length=1, max_length=64, description="Role of the actor")
    ip_address: str = Field(default="127.0.0.1", description="Network address of the actor")


class AuditEvent(BaseModel):
    """Cryptographically hash-chained, append-only audit event record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(..., description="Unique UUID event identifier")
    request_id: str = Field(..., description="Associated bootstrap request ID")
    sequence_number: int = Field(..., ge=0, description="Monotonically increasing sequence number")
    timestamp: datetime = Field(..., description="UTC timestamp of the event")
    event_type: AuditEventType = Field(..., description="Categorized event type")
    severity: AuditSeverity = Field(..., description="Event severity classification")
    actor: AuditActor = Field(..., description="Actor who triggered the event")
    action_name: str = Field(..., min_length=1, max_length=128, description="Action or step name")
    state_before: WorkflowStatus | None = Field(default=None, description="Workflow status before transition")
    state_after: WorkflowStatus | None = Field(default=None, description="Workflow status after transition")
    previous_event_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="SHA-256 event_hash of preceding event (all zeros for genesis block)",
    )
    payload_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="SHA-256 digest of the event details/payload",
    )
    event_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="SHA-256 hash chaining previous_event_hash, timestamp, type, actor, payload",
    )
    details: dict[str, Any] = Field(default_factory=dict, description="Structured event metadata")
