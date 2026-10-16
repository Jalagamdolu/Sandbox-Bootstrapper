"""Safe local repository and mock dashboard discovery module."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.models.requests import DashboardDiscoveryResult, RepoDiscoveryResult


def discover_local_repository(repo_path: str | Path) -> RepoDiscoveryResult:
    """
    Safely inspect local repository metadata and configuration files.
    Strictly read-only; never executes repository scripts or arbitrary shell commands.

    Args:
        repo_path: Path to the target local repository directory.

    Returns:
        RepoDiscoveryResult with detected framework and discovered configuration files.
    """
    path = Path(repo_path).resolve()
    config_files: list[str] = []
    inferred_deps: list[str] = []
    detected_framework = "unknown"
    doc_snippet: str | None = None

    if path.exists() and path.is_dir():
        # Check standard config files
        known_configs = [
            "pyproject.toml",
            "requirements.txt",
            "setup.py",
            "package.json",
            "pom.xml",
            "Dockerfile",
            "docker-compose.yml",
        ]
        for cfg in known_configs:
            cfg_file = path / cfg
            if cfg_file.exists() and cfg_file.is_file():
                config_files.append(cfg)

        # Detect framework
        if "pyproject.toml" in config_files or "requirements.txt" in config_files:
            detected_framework = "python-fastapi"
            inferred_deps = ["fastapi", "uvicorn", "pydantic", "sqlite3"]
        elif "package.json" in config_files:
            detected_framework = "node-microservice"
            inferred_deps = ["express", "dotenv"]

        # Read README snippet if present (safely truncated to 512 chars)
        readme = path / "README.md"
        if readme.exists() and readme.is_file():
            try:
                text = readme.read_text(encoding="utf-8")[:512]
                doc_snippet = text.strip()
            except Exception:
                doc_snippet = None

    return RepoDiscoveryResult(
        repository_path=str(path),
        detected_framework=detected_framework,
        config_files_found=config_files,
        inferred_dependencies=inferred_deps,
        untrusted_documentation_snippet=doc_snippet,
        discovery_timestamp=datetime.now(timezone.utc),
    )


def discover_mock_dashboard(tenant_id: str = "mock-tenant-01") -> DashboardDiscoveryResult:
    """
    Query mock enterprise dashboard for sandbox tenancy, quotas, and network ranges.
    Completely deterministic, local, and zero-cost.

    Args:
        tenant_id: Mock tenant identifier.

    Returns:
        DashboardDiscoveryResult containing mock quota and network configuration.
    """
    return DashboardDiscoveryResult(
        tenant_id=tenant_id,
        quota_available_sandboxes=10,
        existing_sandboxes_count=1,
        allowed_synthetic_fixtures=[
            "users.json",
            "teams.json",
            "projects.json",
            "configs.json",
        ],
        mock_network_range="10.0.0.0/24",
    )
