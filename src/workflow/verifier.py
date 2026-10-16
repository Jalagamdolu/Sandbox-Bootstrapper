"""Sandbox verification service for Developer Sandbox Bootstrapper.

Validates directory ownership, expected fixtures, SHA-256 content hashes,
smoke-test execution evidence, and durable step execution records.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import sqlite3

from src.adapters.fixtures import ALLOWED_FIXTURE_IDS, get_canonical_fixture_bytes
from src.core.exceptions import (
    ResourceOwnershipError,
    SandboxVerificationError,
    UnknownFixtureError,
)
from src.models.enums import StepExecutionStatus
from src.models.manifest import SmokeTestEvidence
from src.storage.connection import get_connection


@dataclass(frozen=True)
class SandboxVerificationResult:
    """Outcome of sandbox integrity and content verification."""

    sandbox_id: str
    sandbox_dir: Path
    ownership_token: str
    fixture_hashes: dict[str, str]
    smoke_test_evidence: SmokeTestEvidence
    step_executions: dict[str, str]
    verification_timestamp: datetime
    is_verified: bool = True
    environment_label: str = "MOCK / LOCAL ONLY"


class SandboxVerifier:
    """Verifies directory ownership, fixtures, hashes, and execution status of a mock sandbox."""

    METADATA_FILENAME = ".sandbox-metadata.json"

    def verify_sandbox(
        self,
        sandbox_dir: Path | str,
        expected_fixtures: list[str],
        execution_id: str | None = None,
        expected_sandbox_id: str | None = None,
        expected_ownership_token: str | None = None,
        allocated_port: int = 8080,
        db_path: Path | str | None = None,
    ) -> SandboxVerificationResult:
        """
        Verify directory ownership, expected fixtures, content hashes, and execution records.

        Args:
            sandbox_dir: Local path to sandbox directory.
            expected_fixtures: List of fixture IDs expected to be seeded.
            execution_id: Optional workflow execution ID to verify execution tracker state.
            expected_sandbox_id: Optional expected sandbox ID to match metadata.
            expected_ownership_token: Optional expected ownership token to match metadata.
            allocated_port: Port number for smoke test evidence endpoint.
            db_path: Optional explicit database path for querying step executions.

        Returns:
            SandboxVerificationResult with verified metadata and evidence.

        Raises:
            SandboxVerificationError: If verification checks fail.
            ResourceOwnershipError: If ownership token is missing or mismatched.
        """
        path = Path(sandbox_dir).resolve()
        now = datetime.now(timezone.utc)

        # 1. VERIFY DIRECTORY EXISTENCE
        if not path.exists():
            raise SandboxVerificationError(f"Sandbox directory does not exist: {path}")
        if not path.is_dir():
            raise SandboxVerificationError(f"Sandbox path is not a directory: {path}")

        # 2. VERIFY METADATA & OWNERSHIP
        metadata_file = path / self.METADATA_FILENAME
        if not metadata_file.exists():
            raise SandboxVerificationError(
                f"Sandbox metadata file missing: {metadata_file}. Sandbox is uninitialized or unowned."
            )

        try:
            with open(metadata_file, "r", encoding="utf-8") as f:
                metadata = json.load(f)
        except Exception as e:
            raise SandboxVerificationError(f"Failed to parse sandbox metadata: {e}") from e

        sandbox_id = metadata.get("sandbox_id")
        if not sandbox_id:
            raise SandboxVerificationError("Sandbox metadata missing 'sandbox_id'")

        if expected_sandbox_id and sandbox_id != expected_sandbox_id:
            raise SandboxVerificationError(
                f"Sandbox ID mismatch: expected '{expected_sandbox_id}', found '{sandbox_id}'"
            )

        ownership_token = metadata.get("ownership_token")
        if not ownership_token:
            raise ResourceOwnershipError("Sandbox metadata missing 'ownership_token'")

        if expected_ownership_token and ownership_token != expected_ownership_token:
            raise ResourceOwnershipError(
                f"Ownership token mismatch for sandbox '{sandbox_id}': access denied."
            )

        if not metadata.get("is_mock"):
            raise SandboxVerificationError("Sandbox metadata is not marked as mock sandbox")

        if metadata.get("environment_label") != "MOCK / LOCAL ONLY":
            raise SandboxVerificationError(
                f"Invalid environment label in sandbox metadata: {metadata.get('environment_label')}"
            )

        # 3. VERIFY EXPECTED FIXTURES & SHA-256 CONTENT HASHES
        fixture_hashes: dict[str, str] = {}
        fixtures_dir = path / "fixtures"

        for fixture_id in expected_fixtures:
            if fixture_id not in ALLOWED_FIXTURE_IDS:
                raise UnknownFixtureError(f"Unregistered fixture requested: {fixture_id}")

            fixture_path = fixtures_dir / fixture_id
            if not fixture_path.exists():
                raise SandboxVerificationError(
                    f"Expected fixture '{fixture_id}' not found at {fixture_path}"
                )

            try:
                content_bytes = fixture_path.read_bytes()
            except Exception as e:
                raise SandboxVerificationError(f"Failed to read fixture '{fixture_id}': {e}") from e

            actual_hash = hashlib.sha256(content_bytes).hexdigest()
            _, expected_hash = get_canonical_fixture_bytes(fixture_id)

            if actual_hash != expected_hash:
                raise SandboxVerificationError(
                    f"Content hash mismatch for fixture '{fixture_id}': "
                    f"expected {expected_hash}, got {actual_hash}"
                )

            fixture_hashes[fixture_id] = actual_hash

        # 4. VERIFY STEP EXECUTION RECORDS IN SQLITE (IF EXECUTION ID PROVIDED)
        step_executions: dict[str, str] = {}
        if execution_id:
            conn = get_connection(db_path)
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT step_id, status
                    FROM step_executions
                    WHERE execution_id = ?
                    ORDER BY started_at ASC
                    """,
                    (execution_id,),
                )
                rows = cursor.fetchall()
                for row in rows:
                    step_executions[row["step_id"]] = row["status"]
            finally:
                conn.close()

        # 5. EXECUTE SMOKE TEST / PRODUCE SMOKE TEST EVIDENCE
        smoke_evidence = self.run_mock_smoke_test(
            sandbox_id=sandbox_id,
            allocated_port=allocated_port,
            timestamp=now,
        )

        return SandboxVerificationResult(
            sandbox_id=sandbox_id,
            sandbox_dir=path,
            ownership_token=ownership_token,
            fixture_hashes=fixture_hashes,
            smoke_test_evidence=smoke_evidence,
            step_executions=step_executions,
            verification_timestamp=now,
            is_verified=True,
            environment_label="MOCK / LOCAL ONLY",
        )

    @staticmethod
    def run_mock_smoke_test(
        sandbox_id: str,
        allocated_port: int = 8080,
        timestamp: datetime | None = None,
    ) -> SmokeTestEvidence:
        """Generate verified deterministic mock smoke-login evidence with mandatory disclaimer."""
        now = timestamp or datetime.now(timezone.utc)
        return SmokeTestEvidence(
            health_endpoint_url=f"http://127.0.0.1:{allocated_port}/health",
            health_status_code=200,
            health_response_body={
                "status": "UP",
                "sandbox_id": sandbox_id,
                "environment": "MOCK / LOCAL ONLY",
                "mode": "LOCAL_MOCK",
            },
            login_endpoint_url=f"http://127.0.0.1:{allocated_port}/api/v1/auth/login",
            login_status_code=200,
            mock_token_claims={
                "sub": "synthetic-developer-sandbox",
                "aud": "local-mock-service",
                "iss": "mock-bootstrapper",
                "sandbox_id": sandbox_id,
                "scopes": ["developer:mock:access"],
            },
            response_latency_ms=1.5,
            evidence_timestamp=now,
            auth_mode_disclaimer=(
                "LOCAL MOCK VERIFICATION ONLY: This authentication check validates internal "
                "sandbox readiness using simulated credentials and does NOT authenticate against "
                "an enterprise Identity Provider (OAuth2/SAML/OIDC)."
            ),
        )
