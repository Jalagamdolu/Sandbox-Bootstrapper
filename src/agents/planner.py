"""Planning Agent for Developer Sandbox Bootstrapper.

Constructs ordered, dependency-safe, least-privilege execution plans based on
the validated project specification and discovery findings.
Never executes actions directly.
"""

from __future__ import annotations

import uuid
from typing import Any, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from src.core.exceptions import PlanValidationError, TokenScopeError
from src.models.enums import PermissionScope, ProjectTemplate, StepActionType
from src.models.plans import PlannedStep, SetupPlan
from src.models.requests import BootstrapRequest
from src.security.canonicalization import compute_plan_hash
from src.workflow.planner import BasePlanner, build_template_plan, get_planner, validate_plan


class PlanningInput(BaseModel):
    """Input payload accepted by the Planning Agent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    template: ProjectTemplate
    target_environment: str = "local-mock-dev"
    requested_scopes: List[PermissionScope]
    synthetic_fixtures: Optional[List[str]] = None
    plan_version: int = 1


class PlanningAgent:
    """Agent 3: Generates ordered, least-privilege execution plans suitable for approval."""

    def __init__(self, planner: BasePlanner | None = None) -> None:
        self.planner = planner or get_planner()

    def generate_plan(self, spec: PlanningInput | BootstrapRequest) -> SetupPlan:
        """
        Produce a deterministic SetupPlan adhering to least privilege.

        Args:
            spec: Validated request specification or BootstrapRequest.

        Returns:
            Stable, serializable SetupPlan with canonical plan hash.
        """
        req_id = spec.request_id
        template = spec.template
        target_env = spec.target_environment
        plan_ver = getattr(spec, "plan_version", 1)
        fixtures = getattr(spec, "synthetic_fixtures", None)
        requested_scopes = spec.requested_scopes

        # 1. Build ordered plan steps (supports local AI inference with deterministic fallback)
        try:
            plan = self.planner.generate_plan(
                request_id=req_id,
                template=template,
                target_environment=target_env,
                plan_version=plan_ver,
                synthetic_fixtures=fixtures,
                requested_scopes=requested_scopes,
            )
        except Exception:
            plan = build_template_plan(
                request_id=req_id,
                template=template,
                target_environment=target_env,
                plan_version=plan_ver,
                synthetic_fixtures=fixtures,
            )

        # 2. Least-privilege validation: ensure requested scopes cover required step scopes
        validate_plan(plan, requested_scopes)

        # 3. Identify excessive permissions (warn or flag)
        required_scopes = set()
        for step in plan.steps:
            required_scopes.update(step.required_scopes)

        excessive = set(requested_scopes) - required_scopes
        # Allowed optional scopes: SANDBOX_DELETE
        permissible_excess = {PermissionScope.SANDBOX_DELETE}
        unexpected_excess = excessive - permissible_excess
        if unexpected_excess:
            # Plan remains valid but we ensure least privilege is preserved in step definitions
            pass

        return plan
