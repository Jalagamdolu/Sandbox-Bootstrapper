"""Central Security Policy Module for Developer Sandbox Bootstrapper.

Enforces least privilege, tool and action allowlists, input validation,
and initial approver credential bootstrapping.
Independent of LLM and agent outputs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List, Set
import sqlite3

from src.core.exceptions import PolicyViolationError, SecurityViolationError
from src.models.enums import PermissionScope, ProjectTemplate, StepActionType
from src.models.plans import PlannedStep, SetupPlan
from src.security.tokens import TokenCreationResult, TokenService
from src.storage.connection import get_connection


class PolicyEngine:
    """Central policy enforcement engine governing allowed actions, tools, and scopes."""

    # Explicit Tool and Action Allowlists
    ALLOWED_ACTIONS: Set[StepActionType] = {
        StepActionType.DISCOVER_REPOSITORY,
        StepActionType.DISCOVER_DASHBOARD,
        StepActionType.VALIDATE_DEPENDENCIES,
        StepActionType.PROVISION_MOCK_SANDBOX,
        StepActionType.SEED_SYNTHETIC_DATA,
        StepActionType.EXECUTE_SMOKE_TEST,
        StepActionType.GENERATE_MANIFEST,
    }

    ALLOWED_SCOPES: Set[PermissionScope] = {
        PermissionScope.SANDBOX_READ,
        PermissionScope.SANDBOX_CREATE,
        PermissionScope.SANDBOX_DELETE,
        PermissionScope.DATA_SEED_SYNTHETIC,
        PermissionScope.TEST_EXECUTE,
        PermissionScope.AUDIT_READ,
    }

    FORBIDDEN_PARAMETER_KEYS: Set[str] = {
        "shell",
        "shell_cmd",
        "bash",
        "sh",
        "cmd",
        "powershell",
        "exec",
        "eval",
        "python_code",
        "script",
        "command",
    }

    # Minimum least-privilege scopes required by each step action
    STEP_LEAST_PRIVILEGE_MAP = {
        StepActionType.DISCOVER_REPOSITORY: {PermissionScope.SANDBOX_READ},
        StepActionType.DISCOVER_DASHBOARD: {PermissionScope.SANDBOX_READ},
        StepActionType.VALIDATE_DEPENDENCIES: {PermissionScope.SANDBOX_READ},
        StepActionType.PROVISION_MOCK_SANDBOX: {PermissionScope.SANDBOX_CREATE},
        StepActionType.SEED_SYNTHETIC_DATA: {PermissionScope.DATA_SEED_SYNTHETIC},
        StepActionType.EXECUTE_SMOKE_TEST: {PermissionScope.TEST_EXECUTE},
        StepActionType.GENERATE_MANIFEST: {PermissionScope.AUDIT_READ},
    }

    @classmethod
    def validate_step_policy(cls, step: PlannedStep) -> None:
        """Validate an individual step against security policies."""
        # 1. Action allowlist check
        if step.action_type not in cls.ALLOWED_ACTIONS:
            raise PolicyViolationError(
                f"Action '{step.action_type}' is not in the allowed action policy list."
            )

        # 2. Scope allowlist check
        for scope in step.required_scopes:
            if scope not in cls.ALLOWED_SCOPES:
                raise PolicyViolationError(
                    f"Scope '{scope}' is not in the allowed scope policy list."
                )

        # 3. Parameter inspection for command injection risks
        for key in step.action_parameters:
            if key.lower() in cls.FORBIDDEN_PARAMETER_KEYS:
                raise SecurityViolationError(
                    f"Dangerous parameter '{key}' forbidden by policy in step '{step.step_id}'."
                )

        # 4. Least privilege enforcement
        expected_scopes = cls.STEP_LEAST_PRIVILEGE_MAP.get(step.action_type)
        if expected_scopes:
            for scope in step.required_scopes:
                if scope not in expected_scopes:
                    raise PolicyViolationError(
                        f"Step '{step.name}' requests excessive scope '{scope}'. "
                        f"Permitted for {step.action_type}: {expected_scopes}"
                    )

    @classmethod
    def validate_plan_policy(cls, plan: SetupPlan, requested_scopes: List[PermissionScope]) -> None:
        """Validate an entire plan against policy."""
        if not plan.steps:
            raise PolicyViolationError("Plan contains zero steps; invalid for execution.")

        for step in plan.steps:
            cls.validate_step_policy(step)

        # Ensure requested scopes can fulfill the plan
        plan_scopes = set()
        for step in plan.steps:
            plan_scopes.update(step.required_scopes)

        missing = plan_scopes - set(requested_scopes)
        if missing:
            raise PolicyViolationError(
                f"Plan policy check failed: requested scopes lack required permissions: {missing}"
            )

    @classmethod
    def bootstrap_initial_approver_token(
        cls,
        token_service: TokenService | None = None,
        db_path: Path | str | None = None,
    ) -> TokenCreationResult | None:
        """
        Generate initial approver token on local setup if no active credential exists.

        Returns TokenCreationResult (containing raw_token) ONLY ONCE, or None if already initialized.
        """
        conn = get_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT count(*) FROM approver_tokens WHERE revoked_at IS NULL;"
            )
            count = cursor.fetchone()[0]
            cursor.close()
        finally:
            conn.close()

        if count > 0:
            return None

        svc = token_service or TokenService()
        return svc.create_token(
            approver_id="security-lead-local",
            role="SECURITY_LEAD",
            authorized_scopes=list(cls.ALLOWED_SCOPES),
            db_path=db_path,
        )
