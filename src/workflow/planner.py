"""Deterministic template planner and plan validation module."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from src.adapters.fixtures import ALLOWED_FIXTURE_IDS
from src.core.exceptions import (
    PlanTamperingError,
    PlanValidationError,
    UnknownFixtureError,
)
from src.models.enums import PermissionScope, ProjectTemplate, StepActionType
from src.models.plans import CanonicalApprovalPayload, PlannedStep, SetupPlan
from src.security.canonicalization import compute_plan_hash, extract_canonical_payload_from_plan


def build_template_plan(
    request_id: str,
    template: ProjectTemplate,
    target_environment: str = "local-sandbox",
    plan_version: int = 1,
    synthetic_fixtures: list[str] | None = None,
) -> SetupPlan:
    """
    Construct a deterministic ordered setup plan for a project template.
    Baseline deterministic planner: completely rule-based, zero-cost, zero LLM dependencies.

    Args:
        request_id: Associated bootstrap request ID.
        template: Project starter template.
        target_environment: Execution environment.
        plan_version: Plan schema version.
        synthetic_fixtures: Allowlisted synthetic fixtures to seed (defaults to all standard fixtures).

    Returns:
        Deterministic SetupPlan with computed RFC 8785 canonical plan hash.
    """
    fixtures = sorted(synthetic_fixtures or ["users.json", "teams.json", "projects.json", "configs.json"])

    # Build discrete planned steps in dependency DAG order
    steps: list[PlannedStep] = [
        PlannedStep(
            step_id="step-00000001",
            action_type=StepActionType.DISCOVER_REPOSITORY,
            name="Discover Repository",
            description="Inspect local configuration files and project metadata without command execution.",
            is_privileged=False,
            required_scopes=[PermissionScope.SANDBOX_READ],
            depends_on_step_ids=[],
            action_parameters={"template": template.value},
        ),
        PlannedStep(
            step_id="step-00000002",
            action_type=StepActionType.DISCOVER_DASHBOARD,
            name="Discover Mock Dashboard",
            description="Query local mock environment quotas and network parameters.",
            is_privileged=False,
            required_scopes=[PermissionScope.SANDBOX_READ],
            depends_on_step_ids=["step-00000001"],
            action_parameters={"tenant_id": "mock-tenant-01"},
        ),
        PlannedStep(
            step_id="step-00000003",
            action_type=StepActionType.VALIDATE_DEPENDENCIES,
            name="Validate Dependencies",
            description="Verify safe dependency constraints for the requested template.",
            is_privileged=False,
            required_scopes=[PermissionScope.SANDBOX_READ],
            depends_on_step_ids=["step-00000001"],
            action_parameters={"template": template.value},
        ),
        PlannedStep(
            step_id="step-00000004",
            action_type=StepActionType.PROVISION_MOCK_SANDBOX,
            name="Provision Mock Sandbox",
            description="Create isolated local mock sandbox directory under server-side approval.",
            is_privileged=True,
            required_scopes=[PermissionScope.SANDBOX_CREATE],
            depends_on_step_ids=["step-00000003"],
            action_parameters={"target_environment": target_environment},
        ),
        PlannedStep(
            step_id="step-00000005",
            action_type=StepActionType.SEED_SYNTHETIC_DATA,
            name="Seed Synthetic Data",
            description="Seed allowlisted synthetic fixtures into the authorized sandbox.",
            is_privileged=True,
            required_scopes=[PermissionScope.DATA_SEED_SYNTHETIC],
            depends_on_step_ids=["step-00000004"],
            action_parameters={"fixtures": fixtures},
        ),
        PlannedStep(
            step_id="step-00000006",
            action_type=StepActionType.EXECUTE_SMOKE_TEST,
            name="Execute Smoke Test",
            description="Run mock auth login verification against local sandbox.",
            is_privileged=False,
            required_scopes=[PermissionScope.TEST_EXECUTE],
            depends_on_step_ids=["step-00000005"],
            action_parameters={"endpoint": "http://127.0.0.1:9000/mock-auth/login"},
        ),
        PlannedStep(
            step_id="step-00000007",
            action_type=StepActionType.GENERATE_MANIFEST,
            name="Generate Manifest",
            description="Produce canonical setup manifest with evidence and audit verification.",
            is_privileged=False,
            required_scopes=[PermissionScope.AUDIT_READ],
            depends_on_step_ids=["step-00000006"],
            action_parameters={"manifest_version": "1.3.0"},
        ),
    ]

    # Compute genuine RFC 8785 canonical plan hash
    planned_actions: list[dict[str, Any]] = [
        {
            "step_id": step.step_id,
            "action_type": step.action_type.value,
            "is_privileged": step.is_privileged,
            "required_scopes": [s.value for s in step.required_scopes],
            "action_parameters": step.action_parameters,
        }
        for step in steps
    ]
    all_scopes = sorted({s.value for step in steps for s in step.required_scopes})

    canonical_payload = CanonicalApprovalPayload(
        request_id=request_id,
        target_environment=target_environment,
        plan_version=plan_version,
        granted_scopes=all_scopes,
        planned_actions=planned_actions,
        synthetic_fixtures=fixtures,
    )
    plan_hash = compute_plan_hash(canonical_payload)

    now = datetime.now(timezone.utc)
    return SetupPlan(
        plan_id=f"plan-{uuid.uuid4().hex[:12]}",
        request_id=request_id,
        plan_version=plan_version,
        target_environment=target_environment,
        steps=steps,
        estimated_duration_seconds=30,
        created_at=now,
        canonical_plan_hash=plan_hash,
    )


def validate_plan(plan: SetupPlan, requested_scopes: list[PermissionScope]) -> None:
    """
    Validate plan structure, action allowlists, fixture safety, and least-privilege boundaries.

    Args:
        plan: The SetupPlan to validate.
        requested_scopes: Permission scopes authorized by the initial bootstrap request.

    Raises:
        PlanValidationError: If plan structure, DAG order, or least-privilege scope boundary is violated.
        UnknownFixtureError: If an unregistered fixture ID is included.
        PlanTamperingError: If plan canonical hash does not match computed fingerprint.
    """
    requested_set = {s.value for s in requested_scopes}
    seen_step_ids: set[str] = set()

    for step in plan.steps:
        # 1. Action type validation
        if not isinstance(step.action_type, StepActionType):
            raise PlanValidationError(f"Invalid action type in step '{step.step_id}': '{step.action_type}'.")

        # 2. Least-privilege scope boundary validation
        for scope in step.required_scopes:
            if scope.value not in requested_set:
                raise PlanValidationError(
                    f"Least-privilege violation: Step '{step.step_id}' ({step.action_type.value}) "
                    f"requires scope '{scope.value}' which was not requested in the bootstrap request."
                )

        # 3. Fixture allowlist validation in seeding steps
        if step.action_type == StepActionType.SEED_SYNTHETIC_DATA:
            fixtures = step.action_parameters.get("fixtures", [])
            for fid in fixtures:
                if fid not in ALLOWED_FIXTURE_IDS:
                    raise UnknownFixtureError(
                        f"Fixture '{fid}' in step '{step.step_id}' is not allowlisted. "
                        f"Allowed fixtures: {sorted(ALLOWED_FIXTURE_IDS)}"
                    )

        # 4. Dependency DAG ordering validation
        for dep_id in step.depends_on_step_ids:
            if dep_id not in seen_step_ids:
                raise PlanValidationError(
                    f"DAG dependency error: Step '{step.step_id}' depends on '{dep_id}', "
                    "which has not appeared earlier in execution order."
                )

        seen_step_ids.add(step.step_id)

    # 5. Cryptographic fingerprint verification
    computed_hash = compute_plan_hash(plan)
    if plan.canonical_plan_hash != computed_hash:
        raise PlanTamperingError(
            f"Plan hash mismatch: stored '{plan.canonical_plan_hash}', computed '{computed_hash}'. "
            "Plan payload has been modified or corrupted."
        )


# =============================================================================
# Pluggable AI / Deterministic Planner Interface
# =============================================================================

import logging
import urllib.error
import urllib.request
from typing import Protocol

logger = logging.getLogger(__name__)


class BasePlanner(Protocol):
    """Pluggable planner interface supporting local inference or deterministic fallback."""

    def generate_plan(
        self,
        request_id: str,
        template: ProjectTemplate,
        target_environment: str = "local-sandbox",
        plan_version: int = 1,
        synthetic_fixtures: list[str] | None = None,
        requested_scopes: list[PermissionScope] | None = None,
    ) -> SetupPlan: ...


class DeterministicTemplatePlanner:
    """Baseline deterministic planner: completely rule-based, zero-cost, zero LLM dependencies."""

    def generate_plan(
        self,
        request_id: str,
        template: ProjectTemplate,
        target_environment: str = "local-sandbox",
        plan_version: int = 1,
        synthetic_fixtures: list[str] | None = None,
        requested_scopes: list[PermissionScope] | None = None,
    ) -> SetupPlan:
        return build_template_plan(
            request_id=request_id,
            template=template,
            target_environment=target_environment,
            plan_version=plan_version,
            synthetic_fixtures=synthetic_fixtures,
        )


class LocalLLMPlanner:
    """Pluggable local AI inference planner with automatic deterministic fallback.

    Connects to local inference daemon (e.g. Ollama) when enabled.
    Generates structured plan candidates, validates them against existing schemas,
    fixture allowlists, and DAG policies, and falls back gracefully to the
    deterministic template planner if Ollama is disabled, offline, or returns invalid proposals.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama3.2",
        enabled: bool = False,
        fallback: BasePlanner | None = None,
        timeout_seconds: float = 1.5,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.enabled = enabled
        self.fallback = fallback or DeterministicTemplatePlanner()
        self.timeout_seconds = timeout_seconds

    def generate_plan(
        self,
        request_id: str,
        template: ProjectTemplate,
        target_environment: str = "local-sandbox",
        plan_version: int = 1,
        synthetic_fixtures: list[str] | None = None,
        requested_scopes: list[PermissionScope] | None = None,
    ) -> SetupPlan:
        if not self.enabled:
            return self.fallback.generate_plan(
                request_id=request_id,
                template=template,
                target_environment=target_environment,
                plan_version=plan_version,
                synthetic_fixtures=synthetic_fixtures,
                requested_scopes=requested_scopes,
            )

        fixtures = sorted(synthetic_fixtures or ["users.json", "teams.json", "projects.json", "configs.json"])

        try:
            candidate = self._query_ollama(
                request_id=request_id,
                template=template,
                target_environment=target_environment,
                plan_version=plan_version,
                fixtures=fixtures,
                requested_scopes=requested_scopes,
            )
            if candidate is not None:
                return candidate
        except Exception as exc:
            logger.warning(
                "Local AI model inference on %s failed (%s); falling back to deterministic template planner.",
                self.base_url,
                exc,
            )

        # Fail-safe deterministic fallback
        return self.fallback.generate_plan(
            request_id=request_id,
            template=template,
            target_environment=target_environment,
            plan_version=plan_version,
            synthetic_fixtures=fixtures,
            requested_scopes=requested_scopes,
        )

    def _query_ollama(
        self,
        request_id: str,
        template: ProjectTemplate,
        target_environment: str,
        plan_version: int,
        fixtures: list[str],
        requested_scopes: list[PermissionScope] | None = None,
    ) -> SetupPlan | None:
        """Query local Ollama instance for structured plan candidates."""
        import json

        prompt = (
            f"You are an infrastructure planning agent for the Developer Sandbox Bootstrapper.\n"
            f"Generate an ordered, dependency-safe, least-privilege execution plan for template '{template.value}' "
            f"in target environment '{target_environment}'.\n"
            f"Allowed action types: {[a.value for a in StepActionType]}.\n"
            f"Allowed permission scopes: {[s.value for s in PermissionScope]}.\n"
            f"Allowed synthetic fixtures: {fixtures}.\n"
            f"Return JSON adhering strictly to: {{\"steps\": [{{\"step_id\": \"step-00000001\", \"action_type\": \"DISCOVER_REPOSITORY\", \"name\": \"...\", \"description\": \"...\", \"is_privileged\": false, \"required_scopes\": [\"sandbox:read\"], \"depends_on_step_ids\": [], \"action_parameters\": {{}}}}]}}"
        )
        payload = {
            "model": self.model,
            "prompt": prompt,
            "format": "json",
            "stream": False,
        }

        req_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=req_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
            if resp.status != 200:
                raise RuntimeError(f"Ollama returned HTTP status {resp.status}")
            resp_body = resp.read().decode("utf-8")
            data = json.loads(resp_body)

        raw_response = data.get("response")
        if not raw_response:
            raise ValueError("Empty response payload from Ollama")

        model_json = json.loads(raw_response) if isinstance(raw_response, str) else raw_response
        raw_steps = model_json.get("steps")
        if not isinstance(raw_steps, list) or len(raw_steps) == 0:
            raise ValueError("Ollama response missing non-empty 'steps' array")

        # Parse and construct PlannedStep objects
        parsed_steps: list[PlannedStep] = []
        for idx, s in enumerate(raw_steps, start=1):
            act_type = StepActionType(s["action_type"])
            req_scopes = [PermissionScope(sc) for sc in s.get("required_scopes", [])]
            step_id = str(s.get("step_id") or f"step-{idx:08d}")
            parsed_steps.append(
                PlannedStep(
                    step_id=step_id,
                    action_type=act_type,
                    name=str(s.get("name") or act_type.value),
                    description=str(s.get("description") or ""),
                    is_privileged=bool(s.get("is_privileged", False)),
                    required_scopes=req_scopes,
                    depends_on_step_ids=list(s.get("depends_on_step_ids", [])),
                    action_parameters=dict(s.get("action_parameters", {})),
                )
            )

        # Build RFC 8785 canonical hash
        planned_actions: list[dict[str, Any]] = [
            {
                "step_id": step.step_id,
                "action_type": step.action_type.value,
                "is_privileged": step.is_privileged,
                "required_scopes": [sc.value for sc in step.required_scopes],
                "action_parameters": step.action_parameters,
            }
            for step in parsed_steps
        ]
        all_scopes = sorted({sc.value for step in parsed_steps for sc in step.required_scopes})

        # Extract fixtures matching extract_canonical_payload_from_plan
        seed_fixtures: list[str] = []
        for step in parsed_steps:
            if step.action_type == StepActionType.SEED_SYNTHETIC_DATA:
                seed_fixtures = step.action_parameters.get("fixtures", fixtures)
                break

        canonical_payload = CanonicalApprovalPayload(
            request_id=request_id,
            target_environment=target_environment,
            plan_version=plan_version,
            granted_scopes=all_scopes,
            planned_actions=planned_actions,
            synthetic_fixtures=seed_fixtures,
        )
        plan_hash = compute_plan_hash(canonical_payload)

        candidate_plan = SetupPlan(
            plan_id=f"plan-llm-{uuid.uuid4().hex[:12]}",
            request_id=request_id,
            plan_version=plan_version,
            target_environment=target_environment,
            steps=parsed_steps,
            estimated_duration_seconds=30,
            created_at=datetime.now(timezone.utc),
            canonical_plan_hash=plan_hash,
        )

        # Validate candidate plan against policies and scopes
        scopes_to_validate = requested_scopes or [
            PermissionScope.SANDBOX_READ,
            PermissionScope.SANDBOX_CREATE,
            PermissionScope.DATA_SEED_SYNTHETIC,
            PermissionScope.TEST_EXECUTE,
            PermissionScope.AUDIT_READ,
        ]
        validate_plan(candidate_plan, scopes_to_validate)
        logger.info("Successfully validated Ollama plan candidate (%d steps)", len(parsed_steps))
        return candidate_plan


def get_planner(
    enabled: bool | None = None,
    base_url: str | None = None,
    model: str | None = None,
) -> BasePlanner:
    """Factory creating the configured pluggable planner."""
    from src.core.config import get_settings

    settings = get_settings()
    is_enabled = settings.enable_ollama_planner if enabled is None else enabled
    url = settings.ollama_base_url if base_url is None else base_url
    mod = settings.ollama_model if model is None else model

    fallback = DeterministicTemplatePlanner()
    return LocalLLMPlanner(
        base_url=url,
        model=mod,
        enabled=is_enabled,
        fallback=fallback,
    )

