"""Deterministic Verification Node for Developer Sandbox Bootstrapper.

Compares actual local mock execution results against plan expectations.
Does NOT use LLMs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List
from pydantic import BaseModel, ConfigDict, Field

from src.workflow.verifier import SandboxVerificationResult, SandboxVerifier


class VerificationReport(BaseModel):
    """Detailed evidence report produced by the Verification Node."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    is_valid: bool
    sandbox_id: str
    checks_performed: int
    fixtures_verified: List[str]
    smoke_tests_passed: bool
    failure_reasons: List[str] = Field(default_factory=list)


class VerificationNode:
    """Deterministic verification node validating real local mock artifacts."""

    def __init__(self, verifier: SandboxVerifier | None = None) -> None:
        self.verifier = verifier or SandboxVerifier()

    def verify(
        self,
        sandbox_dir: Path,
        sandbox_id: str,
        expected_fixtures: list[str],
    ) -> VerificationReport:
        """
        Verify that sandbox directory, ownership token, and fixtures meet expectations.

        Returns VerificationReport indicating pass/fail.
        """
        reasons: list[str] = []

        if not sandbox_dir.exists():
            reasons.append(f"Sandbox directory '{sandbox_dir}' does not exist on disk.")
            return VerificationReport(
                is_valid=False,
                sandbox_id=sandbox_id,
                checks_performed=1,
                fixtures_verified=[],
                smoke_tests_passed=False,
                failure_reasons=reasons,
            )

        try:
            res: SandboxVerificationResult = self.verifier.verify_sandbox(
                sandbox_dir=sandbox_dir,
                expected_fixtures=expected_fixtures,
                expected_sandbox_id=sandbox_id,
            )
            return VerificationReport(
                is_valid=res.is_verified,
                sandbox_id=sandbox_id,
                checks_performed=len(expected_fixtures) + 2,
                fixtures_verified=list(res.fixture_hashes.keys()),
                smoke_tests_passed=(res.smoke_test_evidence.health_status_code == 200),
                failure_reasons=[],
            )
        except Exception as exc:
            reasons.append(str(exc))
            return VerificationReport(
                is_valid=False,
                sandbox_id=sandbox_id,
                checks_performed=1,
                fixtures_verified=[],
                smoke_tests_passed=False,
                failure_reasons=reasons,
            )
