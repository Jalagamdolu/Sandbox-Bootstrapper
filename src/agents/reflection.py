"""Deterministic Reflection Node for Developer Sandbox Bootstrapper.

Records structured failure reasons and determines whether a bounded retry is appropriate.
Enforces a maximum of 2 retry attempts for eligible transient failures.
Never retries unauthorized, rejected, or prohibited security actions.
Does NOT use LLMs.
"""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field

from src.core.exceptions import (
    ApprovalExpiredError,
    ApprovalRevokedError,
    AuthorizationDeniedError,
    PathTraversalError,
    PlanTamperingError,
    SecurityViolationError,
    TokenScopeError,
)


class ReflectionDecision(BaseModel):
    """Structured decision output produced by the Reflection Node."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    can_retry: bool
    current_retry_count: int
    max_retries: int = 2
    reason: str
    is_terminal_failure: bool
    failure_category: str


class ReflectionNode:
    """Deterministic failure reflection and bounded retry engine."""

    MAX_RETRIES = 2

    NON_RETRIABLE_EXCEPTION_TYPES = (
        AuthorizationDeniedError,
        ApprovalExpiredError,
        ApprovalRevokedError,
        SecurityViolationError,
        PlanTamperingError,
        TokenScopeError,
        PathTraversalError,
    )

    NON_RETRIABLE_KEYWORDS = {
        "security",
        "denied",
        "revoked",
        "expired",
        "tampering",
        "scope",
        "unauthorized",
        "forbidden",
        "traversal",
        "prohibited",
        "rejection",
    }

    def reflect(
        self,
        error: Exception | str,
        current_retry_count: int = 0,
        stage_name: str = "EXECUTION",
    ) -> ReflectionDecision:
        """
        Evaluate an error and determine if a retry is permissible.

        Args:
            error: Captured exception or error message string.
            current_retry_count: Number of retries already attempted.
            stage_name: Name of the workflow stage where failure occurred.

        Returns:
            ReflectionDecision indicating whether to retry or transition to terminal FAILED.
        """
        err_msg = str(error)
        err_type = error.__class__.__name__ if isinstance(error, Exception) else "ExecutionError"

        # 1. Prohibited / Security errors must NEVER be retried
        if isinstance(error, self.NON_RETRIABLE_EXCEPTION_TYPES):
            return ReflectionDecision(
                can_retry=False,
                current_retry_count=current_retry_count,
                max_retries=self.MAX_RETRIES,
                reason=f"Security/Authorization policy violation in {stage_name} cannot be retried: {err_msg}",
                is_terminal_failure=True,
                failure_category=err_type,
            )

        err_lower = err_msg.lower()
        for kw in self.NON_RETRIABLE_KEYWORDS:
            if kw in err_lower:
                return ReflectionDecision(
                    can_retry=False,
                    current_retry_count=current_retry_count,
                    max_retries=self.MAX_RETRIES,
                    reason=f"Non-retriable condition ({kw}) detected in {stage_name}: {err_msg}",
                    is_terminal_failure=True,
                    failure_category=err_type,
                )

        # 2. Check retry count bounds
        if current_retry_count >= self.MAX_RETRIES:
            return ReflectionDecision(
                can_retry=False,
                current_retry_count=current_retry_count,
                max_retries=self.MAX_RETRIES,
                reason=f"Maximum retry limit ({self.MAX_RETRIES}) reached for stage {stage_name}.",
                is_terminal_failure=True,
                failure_category=err_type,
            )

        # 3. Eligible transient error: allow bounded retry
        next_count = current_retry_count + 1
        return ReflectionDecision(
            can_retry=True,
            current_retry_count=next_count,
            max_retries=self.MAX_RETRIES,
            reason=f"Transient failure in {stage_name}; scheduled retry attempt {next_count}/{self.MAX_RETRIES}.",
            is_terminal_failure=False,
            failure_category=err_type,
        )
