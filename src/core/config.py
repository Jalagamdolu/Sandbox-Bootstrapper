"""Typed application configuration with environment loading and startup validation."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal
from pydantic import BaseModel, Field, field_validator, ValidationError

from src.core.exceptions import ConfigurationError


class Settings(BaseModel):
    """Immutable application settings validated at startup."""

    environment: Literal["development", "test", "production"] = Field(
        default="development",
        description="Runtime environment name",
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Application logging verbosity",
    )
    database_path: Path = Field(
        default=Path("data/sandbox_bootstrapper.db"),
        description="Path to local SQLite database file",
    )

    # LLM Planning Settings (Disabled by default pending owner approval)
    enable_ollama_planner: bool = Field(
        default=False,
        description="Toggle local Ollama LLM planner (default: false)",
    )
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Base HTTP URL for local Ollama daemon",
    )
    ollama_model: str = Field(
        default="llama3.2",
        description="Model name to request from Ollama if enabled",
    )

    # Approval Governance Settings (Defaults pending owner approval)
    approval_ttl_minutes: int = Field(
        default=30,
        description="Lifetime of human approval records in minutes before expiry",
    )

    # Sandbox Retention & Capacity Controls (Defaults pending owner approval)
    sandbox_retention_hours: int = Field(
        default=24,
        description="Active sandbox lifetime in hours before automated cleanup",
    )
    sandbox_failure_quarantine_hours: int = Field(
        default=1,
        description="Duration to preserve failed sandboxes for debugging before compensation",
    )
    max_concurrent_sandboxes: int = Field(
        default=5,
        description="Maximum active sandboxes allowed concurrently",
    )
    max_storage_bytes: int = Field(
        default=10 * 1024 * 1024 * 1024,  # 10 GB
        description="Maximum total storage quota for sandboxes in bytes",
    )

    # Local Storage Directory Paths
    sandbox_storage_dir: Path = Field(
        default=Path("data/sandboxes"),
        description="Directory hosting local isolated sandbox filesystems",
    )
    manifest_storage_dir: Path = Field(
        default=Path("data/manifests"),
        description="Directory hosting finalized setup manifests",
    )

    # Network Binding Configuration
    local_api_host: str = Field(
        default="127.0.0.1",
        description="Host interface for FastAPI backend server",
    )
    local_api_port: int = Field(
        default=8000,
        description="Port for FastAPI backend server",
    )
    local_ui_port: int = Field(
        default=8501,
        description="Port for Streamlit frontend application",
    )

    @field_validator("approval_ttl_minutes")
    @classmethod
    def validate_approval_ttl(cls, v: int) -> int:
        if v < 1 or v > 1440:
            raise ValueError("approval_ttl_minutes must be between 1 and 1440 (24 hours).")
        return v

    @field_validator("sandbox_retention_hours")
    @classmethod
    def validate_retention_hours(cls, v: int) -> int:
        if v < 1 or v > 720:
            raise ValueError("sandbox_retention_hours must be between 1 and 720 (30 days).")
        return v

    @field_validator("sandbox_failure_quarantine_hours")
    @classmethod
    def validate_quarantine_hours(cls, v: int) -> int:
        if v < 0 or v > 168:
            raise ValueError("sandbox_failure_quarantine_hours must be between 0 and 168 (7 days).")
        return v

    @field_validator("max_concurrent_sandboxes")
    @classmethod
    def validate_max_sandboxes(cls, v: int) -> int:
        if v < 1 or v > 50:
            raise ValueError("max_concurrent_sandboxes must be between 1 and 50.")
        return v

    @field_validator("max_storage_bytes")
    @classmethod
    def validate_max_storage(cls, v: int) -> int:
        if v < 1024 * 1024:  # Minimum 1 MB
            raise ValueError("max_storage_bytes must be at least 1,048,576 bytes (1 MB).")
        return v

    @field_validator("database_path", "sandbox_storage_dir", "manifest_storage_dir", mode="after")
    @classmethod
    def normalize_paths(cls, v: Path) -> Path:
        return Path(os.path.normpath(str(v)))

    model_config = {
        "extra": "forbid",
        "frozen": True,
    }


def _parse_bool(val: str) -> bool:
    return val.strip().lower() in ("true", "1", "yes", "on")


def load_settings_from_env(env_file: Path | None = None) -> Settings:
    """Load and validate settings from environment variables and an optional .env file."""
    values: dict[str, object] = {}

    # Read .env file if it exists
    effective_env_file = env_file or Path(".env")
    if effective_env_file.is_file():
        try:
            with open(effective_env_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k = k.strip().lower()
                    v = v.strip().strip("'\"")
                    values[k] = v
        except OSError as e:
            raise ConfigurationError(f"Failed to read environment file {effective_env_file}: {e}") from e

    # System environment variables take precedence
    for field_name in Settings.model_fields:
        env_key = field_name.upper()
        if env_key in os.environ:
            values[field_name] = os.environ[env_key]

    # Convert known scalar types
    type_converters = {
        "enable_ollama_planner": lambda v: _parse_bool(str(v)) if isinstance(v, str) else bool(v),
        "approval_ttl_minutes": int,
        "sandbox_retention_hours": int,
        "sandbox_failure_quarantine_hours": int,
        "max_concurrent_sandboxes": int,
        "max_storage_bytes": int,
        "local_api_port": int,
        "local_ui_port": int,
        "database_path": Path,
        "sandbox_storage_dir": Path,
        "manifest_storage_dir": Path,
    }

    converted_values: dict[str, object] = {}
    for k, v in values.items():
        if k in type_converters:
            try:
                converted_values[k] = type_converters[k](v)
            except (ValueError, TypeError) as err:
                raise ConfigurationError(f"Invalid value for setting '{k}': {v}. Details: {err}") from err
        else:
            converted_values[k] = v

    try:
        return Settings(**converted_values)
    except ValidationError as e:
        raise ConfigurationError(f"Settings validation failed: {e}") from e


_CACHED_SETTINGS: Settings | None = None


def get_settings(reload: bool = False) -> Settings:
    """Retrieve global cached settings or load freshly if reload=True."""
    global _CACHED_SETTINGS
    if _CACHED_SETTINGS is None or reload:
        _CACHED_SETTINGS = load_settings_from_env()
    return _CACHED_SETTINGS
