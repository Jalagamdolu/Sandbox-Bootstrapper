"""Retention policy and resource ownership data contracts for Developer Sandbox Bootstrapper."""

from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class SandboxRetentionConfig(BaseModel):
    """Configuration governing sandbox lifecycle, disk quotas, and retention."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    active_sandbox_ttl_hours: int = Field(
        default=24,
        ge=1,
        le=720,
        description="Owner-selected active sandbox TTL in hours",
    )
    failure_quarantine_hours: int = Field(
        default=1,
        ge=0,
        le=168,
        description="Quarantine window for failed sandboxes before automated cleanup",
    )
    max_concurrent_sandboxes: int = Field(
        default=5,
        ge=1,
        le=50,
        description="Maximum simultaneous active sandboxes allowed",
    )
    max_total_storage_bytes: int = Field(
        default=10 * 1024 * 1024 * 1024,  # 10 GB
        ge=1024 * 1024,
        description="Workstation storage quota limit for all sandboxes combined",
    )


class ResourceOwnershipMetadata(BaseModel):
    """Tracked in database to guarantee compensation never deletes unverified resources."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_id: str = Field(..., description="Unique resource tracking identifier")
    request_id: str = Field(..., description="Associated bootstrap request ID")
    resource_type: str = Field(default="SANDBOX_DIRECTORY", description="Type of resource tracked")
    filesystem_path: str = Field(..., description="Absolute filesystem path to resource")
    ownership_token: str = Field(..., description="Unique UUID written to .sandbox-metadata.json")
    created_at: datetime = Field(..., description="Resource creation timestamp")
    expires_at: datetime = Field(..., description="Calculated expiration timestamp")
    is_quarantined: bool = Field(default=False, description="Flag indicating if resource is under quarantine")
