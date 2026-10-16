"""Workflow state and step execution tracking models for Developer Sandbox Bootstrapper."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from src.models.approvals import ApprovalRecord
from src.models.enums import StepActionType, StepExecutionStatus, WorkflowStage, WorkflowStatus
from src.models.manifest import SetupManifest
from src.models.plans import SetupPlan
from src.models.retention import ResourceOwnershipMetadata


class StepExecutionResult(BaseModel):
    """Execution status, retry count, and outcome summary for an individual step."""

    model_config = ConfigDict(extra="forbid")

    step_id: str = Field(..., description="Step identifier")
    action_type: StepActionType = Field(..., description="Executed action type")
    status: StepExecutionStatus = Field(..., description="Current execution status")
    retry_count: int = Field(default=0, ge=0, description="Number of retries attempted")
    started_at: datetime | None = Field(default=None, description="Step start timestamp")
    completed_at: datetime | None = Field(default=None, description="Step completion timestamp")
    error_message: str | None = Field(default=None, description="Captured error message if step failed")
    output_summary: dict[str, Any] = Field(default_factory=dict, description="Redacted step execution summary")


class StepExecutionRecord(BaseModel):
    """Durable record of step execution persisted in SQLite step_executions table."""

    model_config = ConfigDict(extra="forbid")

    step_execution_id: str = Field(..., description="Unique step execution record ID")
    execution_id: str = Field(..., description="Overall workflow execution run ID")
    request_id: str = Field(..., description="Bootstrap request ID")
    plan_hash: str = Field(..., description="Canonical plan SHA-256 fingerprint")
    plan_version: int = Field(default=1, ge=1, description="Plan version")
    step_id: str = Field(..., description="Planned step ID")
    action_type: StepActionType = Field(..., description="Action executed")
    status: StepExecutionStatus = Field(..., description="Current status (PENDING, RUNNING, COMPLETED, FAILED, SKIPPED)")
    retry_count: int = Field(default=0, ge=0, description="Retry attempt count")
    started_at: datetime | None = Field(default=None, description="Execution start timestamp")
    completed_at: datetime | None = Field(default=None, description="Execution completion timestamp")
    error_category: str | None = Field(default=None, description="Error classification category")
    error_message: str | None = Field(default=None, description="Error message details if failed")
    output_summary: dict[str, Any] = Field(default_factory=dict, description="Redacted summary of step output")



class WorkflowState(BaseModel):
    """State dictionary maintained across workflow execution and checkpoints."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(..., description="Bootstrap request ID")
    current_status: WorkflowStatus = Field(..., description="Active workflow status")
    plan: SetupPlan | None = Field(default=None, description="Approved setup plan")
    approval: ApprovalRecord | None = Field(default=None, description="Active approval record")
    step_results: dict[str, StepExecutionResult] = Field(default_factory=dict, description="Step results by step_id")
    tracked_resources: list[ResourceOwnershipMetadata] = Field(
        default_factory=list,
        description="Resources owned by this request requiring tracked lifecycle",
    )
    active_step_id: str | None = Field(default=None, description="Currently executing step ID")
    compensation_required: bool = Field(default=False, description="Flag indicating compensation/rollback needed")
    sandbox_id: str | None = Field(default=None, description="Allocated sandbox identifier")
    manifest_id: str | None = Field(default=None, description="Final manifest identifier")
    last_error: str | None = Field(default=None, description="Last unhandled error string")
    iteration_counter: int = Field(default=0, ge=0, description="Workflow loop guard iteration counter")


class WorkflowRunResult(BaseModel):
    """Result of executing or resuming a workflow."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(..., description="Bootstrap request ID")
    execution_id: str = Field(..., description="Workflow execution run ID")
    current_status: WorkflowStatus = Field(..., description="Active workflow lifecycle status")
    stage: WorkflowStage = Field(..., description="Orchestration stage reached or executed")
    is_completed: bool = Field(default=False, description="Whether workflow reached terminal COMPLETED status")
    approval_required: bool = Field(default=False, description="Whether workflow is paused awaiting human approval")
    sandbox_id: str | None = Field(default=None, description="Provisioned sandbox ID if available")
    manifest_id: str | None = Field(default=None, description="Manifest identifier if generated")
    manifest: SetupManifest | None = Field(default=None, description="Final setup manifest if finalized")
    error_message: str | None = Field(default=None, description="Captured failure message if halted")
    error_category: str | None = Field(default=None, description="Error classification if failed")
    cleanup_deadline: str | None = Field(default=None, description="ISO timestamp for the 24-hour sandbox cleanup deadline")
    step_results: dict[str, Any] = Field(default_factory=dict, description="Results by step ID")

