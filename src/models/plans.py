"""Plan and execution step data contracts for Developer Sandbox Bootstrapper."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.models.enums import PermissionScope, StepActionType


class PlannedStep(BaseModel):
    """An individual discrete setup action within a plan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    step_id: str = Field(
        ...,
        pattern=r"^step-[0-9a-f]{8}$",
        description="Unique step identifier formatted as step-<8 hex chars>",
    )
    action_type: StepActionType = Field(
        ...,
        description="Allowlisted action type",
    )
    name: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Human-readable step name",
    )
    description: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Summary of step actions",
    )
    is_privileged: bool = Field(
        ...,
        description="Indicates whether this step requires explicit human approval",
    )
    required_scopes: list[PermissionScope] = Field(
        default_factory=list,
        description="Minimum permission scopes required to execute this step",
    )
    depends_on_step_ids: list[str] = Field(
        default_factory=list,
        description="Prerequisite step IDs that must complete before this step",
    )
    action_parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="Typed parameters specific to the action type",
    )

    @field_validator("action_parameters")
    @classmethod
    def reject_code_snippets(cls, params: dict[str, Any]) -> dict[str, Any]:
        forbidden_keys = {"shell_cmd", "bash", "exec", "eval", "python_code", "cmd", "powershell"}
        for k in params:
            if k.lower() in forbidden_keys:
                raise ValueError(f"Dangerous action parameter detected in planned step: '{k}'. Shell execution is prohibited.")
        return params


class SetupPlan(BaseModel):
    """Immutable sequence of setup steps in dependency DAG order."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: str = Field(..., description="Unique plan identifier")
    request_id: str = Field(..., description="Associated bootstrap request ID")
    plan_version: int = Field(default=1, ge=1, description="Plan schema version")
    target_environment: str = Field(..., description="Target execution environment name")
    steps: list[PlannedStep] = Field(..., description="Ordered planned steps")
    estimated_duration_seconds: int = Field(default=0, ge=0, description="Estimated total duration in seconds")
    created_at: datetime = Field(..., description="Creation timestamp")
    canonical_plan_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Deterministic SHA-256 fingerprint computed via RFC 8785",
    )


class CanonicalApprovalPayload(BaseModel):
    """
    The exact canonical structure serialized and hashed for human sign-off.
    Must be serialized using an RFC 8785 package without character normalization.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    target_environment: str
    plan_version: int = 1
    granted_scopes: list[str]
    planned_actions: list[dict[str, Any]]
    synthetic_fixtures: list[str]

    @field_validator("granted_scopes", "synthetic_fixtures")
    @classmethod
    def sort_lists(cls, v: list[str]) -> list[str]:
        return sorted(v)
