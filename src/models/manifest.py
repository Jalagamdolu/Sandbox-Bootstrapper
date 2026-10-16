"""Manifest and smoke-test evidence data contracts for Developer Sandbox Bootstrapper."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from src.models.enums import PermissionScope, ProjectTemplate


class SmokeTestEvidence(BaseModel):
    """Concrete evidence collected during local mock smoke-login execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    health_endpoint_url: str = Field(..., description="Target health probe URL")
    health_status_code: int = Field(..., description="HTTP status code received on health probe")
    health_response_body: dict[str, Any] = Field(..., description="Response body from health probe")
    login_endpoint_url: str = Field(..., description="Mock auth login URL")
    login_status_code: int = Field(..., description="HTTP status code received on mock login")
    mock_token_claims: dict[str, Any] = Field(..., description="Decoded claims from mock JWT token")
    response_latency_ms: float = Field(..., ge=0.0, description="Round-trip latency in milliseconds")
    evidence_timestamp: datetime = Field(..., description="Timestamp when smoke test executed")
    auth_mode_disclaimer: str = Field(
        default=(
            "LOCAL MOCK VERIFICATION ONLY: This authentication check validates internal "
            "sandbox readiness using simulated credentials and does NOT authenticate against "
            "an enterprise Identity Provider (OAuth2/SAML/OIDC)."
        ),
        description="Immutable architectural disclaimer separating mock check from real IdP",
    )


class ManifestEnvironment(BaseModel):
    """Runtime network and environment parameters allocated to the sandbox."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_environment: str = Field(..., description="Target environment name")
    sandbox_id: str = Field(..., description="Unique sandbox instance identifier")
    mock_endpoint_url: str = Field(..., description="Primary mock sandbox HTTP endpoint URL")
    allocated_ports: list[int] = Field(..., description="Local TCP ports allocated to this sandbox")
    created_timestamp: datetime = Field(..., description="Creation timestamp")
    expires_timestamp: datetime = Field(..., description="Scheduled expiration timestamp (24h default)")


class ManifestProvisioningInfo(BaseModel):
    """Details of template and permission configuration applied during provisioning."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    template_applied: ProjectTemplate = Field(..., description="Starter template configured")
    applied_scopes: list[PermissionScope] = Field(..., description="Granted permission scopes")
    sandbox_filesystem_path: str = Field(..., description="Isolated local directory hosting the sandbox")


class ManifestSeedSummary(BaseModel):
    """Summary of synthetic fixtures loaded into the sandbox."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fixtures_loaded: list[str] = Field(..., description="List of synthetic fixture names seeded")
    total_records_seeded: int = Field(..., ge=0, description="Total synthetic records inserted")
    generation_mode: str = Field(
        default="DETERMINISTIC_SYNTHETIC_GENERATOR",
        description="Data generation methodology",
    )
    pii_scan_status: str = Field(
        default="PASSED_DEFENSE_IN_DEPTH_SCAN",
        description="Result of secondary defense-in-depth secret & PII regex sweep",
    )


class ManifestSignatureMetadata(BaseModel):
    """Integrity and lineage metadata binding the manifest to approval and plan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$", description="SHA-256 digest of final manifest")
    canonical_plan_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$", description="Approved plan fingerprint")
    approval_id: str = Field(..., description="Approval record authorizing this environment")
    generated_at: datetime = Field(..., description="Manifest generation timestamp")
    generator_version: str = Field(default="1.3.0", description="Bootstrapper version that created manifest")


class SetupManifest(BaseModel):
    """The canonical, finalized setup manifest saved to disk (strictly 0 secrets)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest_version: str = Field(default="1.3.0", description="Manifest schema version")
    request_id: str = Field(..., description="Associated bootstrap request ID")
    workflow_id: str | None = Field(default=None, description="Associated workflow execution run ID")
    plan_version: int = Field(default=1, description="Plan schema version")
    environment_label: str = Field(default="MOCK / LOCAL ONLY", description="Explicit mock environment banner")
    environment: ManifestEnvironment = Field(..., description="Sandbox environment allocation details")
    provisioning: ManifestProvisioningInfo = Field(..., description="Provisioning configuration summary")
    data_seeding: ManifestSeedSummary = Field(..., description="Synthetic seeding report")
    verification: SmokeTestEvidence = Field(..., description="Mock smoke-login evidence and disclaimer")
    integrity: ManifestSignatureMetadata = Field(..., description="Cryptographic integrity and provenance metadata")
    planned_actions: list[dict[str, Any]] = Field(default_factory=list, description="Ordered planned actions and scopes")
    step_executions: dict[str, str] = Field(default_factory=dict, description="Per-step execution status")
    fixture_hashes: dict[str, str] = Field(default_factory=dict, description="Verified fixture content hashes")
    workflow_status: str = Field(default="COMPLETED", description="Final workflow lifecycle state")
    error_category: str | None = Field(default=None, description="Error category if failed")

