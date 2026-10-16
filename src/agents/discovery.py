"""Discovery Agent for Developer Sandbox Bootstrapper.

Discovers repository metadata, mock sandbox templates, and mock resources using
strictly allowlisted local adapters. Never inspects arbitrary host paths.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from src.core.exceptions import ResourceNotFoundError, SecurityViolationError
from src.models.enums import ProjectTemplate
from src.workflow.discovery import discover_local_repository, discover_mock_dashboard


class DiscoveredResource(BaseModel):
    """Resource metadata discovered in local environment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_id: str
    resource_type: str
    status: str
    warning: Optional[str] = None


class DiscoveryResult(BaseModel):
    """Structured discovery result produced by DiscoveryAgent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    template: ProjectTemplate
    repository_path: str
    detected_framework: str
    config_files_found: List[str]
    mock_network: str
    mock_dashboard_url: str
    available_resources: List[DiscoveredResource]
    unavailable_resources: List[DiscoveredResource]
    warnings: List[str]
    is_valid: bool = True


class DiscoveryAgent:
    """Agent 2: Discovers available mock resources and identifies missing dependencies."""

    def __init__(self, catalog_path: Path | str | None = None) -> None:
        self.catalog_path = Path(catalog_path or "data/mock_resources.json")

    def discover(
        self,
        template: ProjectTemplate,
        repository_path: str = "./",
        custom_root: Path | str | None = None,
    ) -> DiscoveryResult:
        """
        Execute safe local discovery.

        Inspects local repository and mock catalog without executing shell commands
        or accessing external networks.
        """
        repo_meta = discover_local_repository(repository_path)
        dashboard_meta = discover_mock_dashboard()

        # Load local mock catalog if available
        available_res: list[DiscoveredResource] = []
        unavailable_res: list[DiscoveredResource] = []
        warnings: list[str] = []

        if self.catalog_path.exists():
            try:
                data = json.loads(self.catalog_path.read_text(encoding="utf-8"))
                for res in data.get("mock_resources", []):
                    item = DiscoveredResource(
                        resource_id=res["resource_id"],
                        resource_type=res.get("type", "generic"),
                        status=res.get("status", "AVAILABLE"),
                        warning=res.get("warning"),
                    )
                    if item.status == "AVAILABLE":
                        available_res.append(item)
                    else:
                        unavailable_res.append(item)
                        if item.warning:
                            warnings.append(f"Unavailable resource '{item.resource_id}': {item.warning}")
            except Exception as exc:
                warnings.append(f"Failed to load mock catalog '{self.catalog_path}': {exc}")
        else:
            available_res.append(
                DiscoveredResource(
                    resource_id="mock-sqlite-db",
                    resource_type="database",
                    status="AVAILABLE",
                )
            )

        # Template availability verification
        if template not in ProjectTemplate:
            warnings.append(f"Requested template '{template}' is not in approved ProjectTemplate catalog.")

        return DiscoveryResult(
            template=template,
            repository_path=repository_path,
            detected_framework=repo_meta.detected_framework,
            config_files_found=repo_meta.config_files_found,
            mock_network=dashboard_meta.mock_network_range,
            mock_dashboard_url="http://127.0.0.1:8000/mock-dashboard",
            available_resources=available_res,
            unavailable_resources=unavailable_res,
            warnings=warnings,
            is_valid=True,
        )
