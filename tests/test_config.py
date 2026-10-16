"""Tests for application configuration loading, defaults, and validation."""

from __future__ import annotations

import os
from pathlib import Path
import pytest
from pydantic import ValidationError

from src.core.config import Settings, load_settings_from_env, get_settings
from src.core.exceptions import ConfigurationError


def test_default_settings() -> None:
    """Verify safe local-development defaults as documented in architecture."""
    settings = Settings()

    assert settings.environment == "development"
    assert settings.log_level == "INFO"
    assert settings.enable_ollama_planner is False  # Safe default: Ollama disabled
    assert settings.ollama_base_url == "http://localhost:11434"
    assert settings.ollama_model == "llama3.2"
    assert settings.approval_ttl_minutes == 30  # Documented 30-min approval TTL
    assert settings.sandbox_retention_hours == 24  # Documented 24-hr retention
    assert settings.sandbox_failure_quarantine_hours == 1
    assert settings.max_concurrent_sandboxes == 5
    assert settings.max_storage_bytes == 10 * 1024 * 1024 * 1024  # 10 GB
    assert settings.local_api_host == "127.0.0.1"
    assert settings.local_api_port == 8000
    assert settings.local_ui_port == 8501


def test_custom_environment_loading(clean_env: dict[str, str], tmp_path: Path) -> None:
    """Verify typed environment variables override defaults correctly."""
    clean_env["ENVIRONMENT"] = "test"
    clean_env["LOG_LEVEL"] = "DEBUG"
    clean_env["ENABLE_OLLAMA_PLANNER"] = "true"
    clean_env["APPROVAL_TTL_MINUTES"] = "45"
    clean_env["SANDBOX_RETENTION_HOURS"] = "48"
    clean_env["MAX_CONCURRENT_SANDBOXES"] = "10"
    clean_env["MAX_STORAGE_BYTES"] = "21474836480"
    clean_env["DATABASE_PATH"] = str(tmp_path / "custom.db")

    settings = load_settings_from_env(env_file=tmp_path / "nonexistent.env")

    assert settings.environment == "test"
    assert settings.log_level == "DEBUG"
    assert settings.enable_ollama_planner is True
    assert settings.approval_ttl_minutes == 45
    assert settings.sandbox_retention_hours == 48
    assert settings.max_concurrent_sandboxes == 10
    assert settings.max_storage_bytes == 21474836480
    assert settings.database_path == (tmp_path / "custom.db")


def test_env_file_reading(tmp_path: Path) -> None:
    """Verify settings read correctly from an explicit .env file."""
    env_file = tmp_path / ".env.test"
    env_file.write_text(
        "APPROVAL_TTL_MINUTES=60\n"
        "ENABLE_OLLAMA_PLANNER=false\n"
        "SANDBOX_RETENTION_HOURS=72\n"
        "# Comment line\n"
        "ENVIRONMENT=production\n",
        encoding="utf-8",
    )

    settings = load_settings_from_env(env_file=env_file)

    assert settings.approval_ttl_minutes == 60
    assert settings.enable_ollama_planner is False
    assert settings.sandbox_retention_hours == 72
    assert settings.environment == "production"


def test_invalid_approval_ttl_low() -> None:
    """Verify rejection of approval TTL < 1 minute."""
    with pytest.raises(ValidationError):
        Settings(approval_ttl_minutes=0)


def test_invalid_approval_ttl_high() -> None:
    """Verify rejection of approval TTL > 1440 minutes (24 hours)."""
    with pytest.raises(ValidationError):
        Settings(approval_ttl_minutes=1441)


def test_invalid_retention_hours() -> None:
    """Verify rejection of retention hours outside valid bounds."""
    with pytest.raises(ValidationError):
        Settings(sandbox_retention_hours=0)

    with pytest.raises(ValidationError):
        Settings(sandbox_retention_hours=721)


def test_invalid_quarantine_hours() -> None:
    """Verify rejection of quarantine hours outside valid bounds."""
    with pytest.raises(ValidationError):
        Settings(sandbox_failure_quarantine_hours=-1)


def test_invalid_max_sandboxes() -> None:
    """Verify rejection of maximum sandboxes outside valid bounds."""
    with pytest.raises(ValidationError):
        Settings(max_concurrent_sandboxes=0)

    with pytest.raises(ValidationError):
        Settings(max_concurrent_sandboxes=51)


def test_invalid_max_storage() -> None:
    """Verify rejection of storage quota below 1 MB."""
    with pytest.raises(ValidationError):
        Settings(max_storage_bytes=500_000)


def test_invalid_environment_name() -> None:
    """Verify rejection of unlisted environment names."""
    with pytest.raises(ValidationError):
        Settings(environment="staging")  # type: ignore[arg-type]


def test_extra_fields_forbidden() -> None:
    """Verify rejection of unexpected configuration parameters."""
    with pytest.raises(ValidationError):
        Settings(unexpected_field="disallowed")  # type: ignore[call-arg]


def test_configuration_error_on_bad_env_value(clean_env: dict[str, str], tmp_path: Path) -> None:
    """Verify ConfigurationError raised when an environment variable contains non-integer."""
    clean_env["APPROVAL_TTL_MINUTES"] = "not-a-number"
    with pytest.raises(ConfigurationError):
        load_settings_from_env(env_file=tmp_path / "none.env")


def test_get_settings_caching() -> None:
    """Verify get_settings returns cached instance unless reload=True."""
    s1 = get_settings(reload=True)
    s2 = get_settings()
    assert s1 == s2
