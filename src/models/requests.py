"""Request and discovery data contracts for Developer Sandbox Bootstrapper."""

from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.models.enums import PermissionScope, ProjectTemplate, WorkflowStatus


class BootstrapRequestCreate(BaseModel):
    """Input payload to create a new sandbox bootstrap request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    project_name: str = Field(
        ...,
        min_length=2,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_\-]+$",
        description="Alphanumeric project identifier",
    )
    template: ProjectTemplate = Field(
        ...,
        description="Starter project template",
    )
    repository_path: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Local repository directory path",
    )
    requested_scopes: list[PermissionScope] = Field(
        ...,
        min_length=1,
        description="Permission scopes requested for this sandbox",
    )
    developer_id: str = Field(
        ...,
        min_length=2,
        max_length=64,
        description="Identifier of requesting developer",
    )
    target_environment: str = Field(
        default="local-sandbox",
        min_length=2,
        max_length=32,
        description="Target execution environment name",
    )

    @field_validator("requested_scopes")
    @classmethod
    def ensure_unique_scopes(cls, v: list[PermissionScope]) -> list[PermissionScope]:
        if len(v) != len(set(v)):
            raise ValueError("Duplicate permission scopes requested.")
        return sorted(v, key=lambda s: s.value)


class BootstrapRequest(BaseModel):
    """Internal domain entity representing a persisted bootstrap request."""

    model_config = ConfigDict(extra="forbid")

    request_id: str
    idempotency_key: str
    project_name: str
    template: ProjectTemplate
    repository_path: str
    requested_scopes: list[PermissionScope]
    developer_id: str
    target_environment: str = "local-sandbox"
    status: WorkflowStatus = WorkflowStatus.DRAFT
    created_at: datetime
    updated_at: datetime


class BootstrapRequestResponse(BaseModel):
    """API response representation of a bootstrap request."""

    model_config = ConfigDict(extra="forbid")

    request_id: str
    status: WorkflowStatus
    project_name: str
    template: ProjectTemplate
    requested_scopes: list[PermissionScope]
    developer_id: str
    target_environment: str
    created_at: datetime
    updated_at: datetime


class RepoDiscoveryResult(BaseModel):
    """Results from inspecting local repository metadata and documentation."""

    model_config = ConfigDict(extra="forbid")

    repository_path: str
    detected_framework: str
    config_files_found: list[str]
    inferred_dependencies: list[str]
    untrusted_documentation_snippet: str | None = None
    discovery_timestamp: datetime


class DashboardDiscoveryResult(BaseModel):
    """Results from querying mock enterprise environment dashboard."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    quota_available_sandboxes: int
    existing_sandboxes_count: int
    allowed_synthetic_fixtures: list[str]
    mock_network_range: str
