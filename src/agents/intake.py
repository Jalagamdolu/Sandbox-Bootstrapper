"""Intake Agent for Developer Sandbox Bootstrapper.

Responsible for receiving, validating, and normalizing sandbox requests.
Applies safe defaults and rejects malformed, dangerous, or unsupported inputs.
"""

from __future__ import annotations

import re
from typing import Any, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.core.exceptions import ModelValidationError
from src.models.enums import PermissionScope, ProjectTemplate, WorkflowStatus
from src.models.requests import BootstrapRequest, BootstrapRequestCreate


class IntakeRequest(BaseModel):
    """Raw input payload accepted by the Intake Agent."""

    model_config = ConfigDict(extra="forbid")

    project_name: str = Field(..., description="Project name identifier")
    template: str = Field(..., description="Sandbox template identifier")
    repository_path: str = Field(default="./", description="Target repository path")
    requested_scopes: List[str] = Field(default_factory=list, description="Requested permission scopes")
    developer_id: str = Field(..., description="Developer ID")
    target_environment: str = Field(default="local-mock-dev", description="Target execution environment")
    synthetic_fixtures: Optional[List[str]] = Field(
        default=None, description="Optional custom synthetic fixture filenames"
    )


class ProjectSpecification(BaseModel):
    """Validated, normalized project specification produced by the Intake Agent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    project_name: str
    template: ProjectTemplate
    repository_path: str
    requested_scopes: List[PermissionScope]
    developer_id: str
    target_environment: str
    synthetic_fixtures: List[str]
    status: WorkflowStatus = WorkflowStatus.DRAFT


class IntakeAgent:
    """Agent 1: Validates and normalizes user sandbox requests with strict security checks."""

    PROJECT_NAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]{3,64}$")
    DEFAULT_FIXTURES = ["users.json", "teams.json", "projects.json", "configs.json"]

    def validate_request(self, payload: IntakeRequest | dict[str, Any]) -> ProjectSpecification:
        """Validate input and return an immutable ProjectSpecification."""
        if isinstance(payload, dict):
            try:
                raw = IntakeRequest.model_validate(payload)
            except Exception as exc:
                raise ModelValidationError(f"Intake validation failed: {exc}") from exc
        else:
            raw = payload

        # 1. Project name safety
        if not self.PROJECT_NAME_REGEX.match(raw.project_name):
            raise ModelValidationError(
                f"Invalid project_name '{raw.project_name}'. Must match {self.PROJECT_NAME_REGEX.pattern}."
            )
        if ".." in raw.project_name or "/" in raw.project_name or "\\" in raw.project_name:
            raise ModelValidationError("Path traversal characters not allowed in project_name.")

        # 2. Template validation
        try:
            template = ProjectTemplate(raw.template)
        except ValueError:
            valid = [t.value for t in ProjectTemplate]
            raise ModelValidationError(
                f"Unsupported template '{raw.template}'. Supported templates: {valid}"
            )

        # 3. Permission scopes validation
        if not raw.requested_scopes:
            raise ModelValidationError("requested_scopes cannot be empty.")

        parsed_scopes: list[PermissionScope] = []
        seen = set()
        for s in raw.requested_scopes:
            try:
                scope = PermissionScope(s)
            except ValueError:
                raise ModelValidationError(f"Invalid permission scope '{s}'.")
            if scope in seen:
                raise ModelValidationError(f"Duplicate scope '{s}' in requested_scopes.")
            seen.add(scope)
            parsed_scopes.append(scope)

        # 4. Safe defaults
        fixtures = raw.synthetic_fixtures or list(self.DEFAULT_FIXTURES)
        target_env = raw.target_environment.strip() or "local-mock-dev"

        return ProjectSpecification(
            project_name=raw.project_name.strip(),
            template=template,
            repository_path=raw.repository_path.strip(),
            requested_scopes=parsed_scopes,
            developer_id=raw.developer_id.strip(),
            target_environment=target_env,
            synthetic_fixtures=fixtures,
            status=WorkflowStatus.DRAFT,
        )
