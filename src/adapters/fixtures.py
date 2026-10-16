"""Registered synthetic fixtures and defense-in-depth safety validation."""

from __future__ import annotations

import re
from typing import Any
from src.core.exceptions import SyntheticDataSeedingError, UnknownFixtureError
from src.security.canonicalization import canonicalize

# Strictly closed allowlist of permitted synthetic fixture IDs
ALLOWED_FIXTURE_IDS: set[str] = {
    "users.json",
    "teams.json",
    "projects.json",
    "configs.json",
}

# Static, deterministic synthetic data payloads (100% synthetic, zero real credentials or PII)
STATIC_FIXTURES: dict[str, Any] = {
    "users.json": [
        {
            "user_id": "usr-mock-001",
            "username": "developer.mock",
            "email": "developer.mock@example.local",
            "role": "DEVELOPER",
            "is_mock": True,
        },
        {
            "user_id": "usr-mock-002",
            "username": "tester.mock",
            "email": "tester.mock@example.local",
            "role": "QA_ENGINEER",
            "is_mock": True,
        },
        {
            "user_id": "usr-mock-003",
            "username": "lead.mock",
            "email": "lead.mock@example.local",
            "role": "SECURITY_LEAD",
            "is_mock": True,
        },
    ],
    "teams.json": [
        {
            "team_id": "team-mock-001",
            "team_name": "Team-Alpha-Mock",
            "lead_user_id": "usr-mock-003",
            "department": "Core Engineering",
            "is_mock": True,
        },
        {
            "team_id": "team-mock-002",
            "team_name": "Team-Beta-Mock",
            "lead_user_id": "usr-mock-001",
            "department": "Platform Tools",
            "is_mock": True,
        },
    ],
    "projects.json": [
        {
            "project_id": "proj-mock-001",
            "project_name": "developer-sandbox-service",
            "team_id": "team-mock-001",
            "status": "ACTIVE",
            "is_mock": True,
        },
        {
            "project_id": "proj-mock-002",
            "project_name": "mock-analytics-worker",
            "team_id": "team-mock-002",
            "status": "ACTIVE",
            "is_mock": True,
        },
    ],
    "configs.json": {
        "app_name": "MockDeveloperSandboxApp",
        "environment": "local-mock",
        "mock_service_url": "http://127.0.0.1:9999",
        "debug_mode": True,
        "synthetic_marker": "SYNTHETIC_LOCAL_FIXTURE_V1",
        "allowed_hosts": ["localhost", "127.0.0.1"],
    },
}

# Regex patterns to intercept live credentials or sensitive secrets in fixture payloads
SUSPICIOUS_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Private Key Header", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("GitHub Personal Token", re.compile(r"gh[pous]_[A-Za-z0-9_]{36}")),
    ("Slack API Token", re.compile(r"xox[baprs]-[A-Za-z0-9_\-]{10,}")),
]


def scan_for_sensitive_secrets(text: str) -> None:
    """
    Defense-in-depth scanner ensuring fixture payloads contain zero live credentials.

    Args:
        text: Plaintext content to inspect.

    Raises:
        SyntheticDataSeedingError: If a suspicious live secret pattern is detected.
    """
    for label, pattern in SUSPICIOUS_PATTERNS:
        if pattern.search(text):
            raise SyntheticDataSeedingError(
                f"Defense-in-depth safety check failed: Suspicious credential pattern '{label}' detected in fixture."
            )


def get_canonical_fixture_bytes(fixture_id: str) -> tuple[bytes, str]:
    """
    Retrieve and canonicalize fixture payload, validating allowlist and scanning for secrets.

    Args:
        fixture_id: Registered fixture filename (e.g. 'users.json').

    Returns:
        Tuple of (canonical_utf8_bytes, sha256_digest).

    Raises:
        UnknownFixtureError: If fixture_id is not in allowlist.
        SyntheticDataSeedingError: If content fails defense-in-depth scanning.
    """
    if fixture_id not in ALLOWED_FIXTURE_IDS:
        raise UnknownFixtureError(
            f"Fixture '{fixture_id}' is not in the registered allowlist. Allowed: {sorted(ALLOWED_FIXTURE_IDS)}"
        )

    data = STATIC_FIXTURES[fixture_id]
    result = canonicalize(data)
    scan_for_sensitive_secrets(result.canonical_text)
    return result.canonical_bytes, result.sha256_digest
