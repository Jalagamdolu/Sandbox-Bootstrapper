"""Tests for server-side approver token lifecycle, identity resolution, and redaction."""

from __future__ import annotations

import sqlite3
from pathlib import Path
import pytest

from src.core.exceptions import TokenNotFoundError, TokenRevokedError
from src.models.enums import PermissionScope
from src.security.tokens import TokenService


def test_token_creation_entropy_and_non_persistence(
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify generated tokens have >= 256 bits entropy and raw token is NEVER persisted."""
    scopes = [PermissionScope.SANDBOX_CREATE, PermissionScope.DATA_SEED_SYNTHETIC]
    result = token_service.create_token(
        approver_id="approver-lead",
        role="SECURITY_LEAD",
        authorized_scopes=scopes,
        db_path=initialized_db_path,
    )

    # 32 url-safe bytes produces 43 characters (256 bits entropy)
    assert len(result.raw_token) >= 43
    assert result.approver_id == "approver-lead"
    assert len(result.token_hash) == 64

    # Verify database contents directly
    conn = sqlite3.connect(str(initialized_db_path))
    cursor = conn.cursor()
    cursor.execute("SELECT token_hash, approver_id FROM approver_tokens WHERE token_hash = ?;", (result.token_hash,))
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    # CRITICAL: Raw token must never be present in the database row or hash
    assert result.raw_token not in row[0]


def test_resolve_identity_success(
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify authentic raw token resolves the exact server-stored identity and scopes."""
    scopes = [PermissionScope.SANDBOX_CREATE, PermissionScope.SANDBOX_READ]
    created = token_service.create_token(
        approver_id="alice-admin",
        role="PROJECT_OWNER",
        authorized_scopes=scopes,
        db_path=initialized_db_path,
    )

    identity = token_service.resolve_identity(created.raw_token, db_path=initialized_db_path)
    assert identity.approver_id == "alice-admin"
    assert identity.role == "PROJECT_OWNER"
    assert identity.authorized_scopes == scopes
    assert identity.token_hash == created.token_hash
    assert identity.revoked_at is None


def test_client_supplied_identity_ignored(
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify client-supplied identity claim (e.g. X-Approver-Id) is strictly ignored."""
    created = token_service.create_token(
        approver_id="genuine-approver",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )

    # Attacker passes a spoofed client_claimed_id
    identity = token_service.resolve_identity(
        created.raw_token,
        client_claimed_id="attacker-claimed-admin",
        db_path=initialized_db_path,
    )

    # Must resolve genuine approver, NOT the attacker's claim
    assert identity.approver_id == "genuine-approver"
    assert identity.approver_id != "attacker-claimed-admin"


def test_invalid_token_rejected(
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify unknown or altered tokens are rejected with TokenNotFoundError."""
    with pytest.raises(TokenNotFoundError):
        token_service.resolve_identity("non-existent-token-1234567890", db_path=initialized_db_path)

    with pytest.raises(TokenNotFoundError):
        token_service.resolve_identity("", db_path=initialized_db_path)


def test_revoked_token_rejected(
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify a revoked token cannot be resolved or used."""
    created = token_service.create_token(
        approver_id="bob-dev",
        role="DEVELOPER",
        authorized_scopes=[PermissionScope.SANDBOX_READ],
        db_path=initialized_db_path,
    )

    # Revoke the token
    revoked = token_service.revoke_token(created.raw_token, db_path=initialized_db_path)
    assert revoked is True

    # Attempting to resolve must raise TokenRevokedError
    with pytest.raises(TokenRevokedError):
        token_service.resolve_identity(created.raw_token, db_path=initialized_db_path)


def test_token_rotation_invalidates_old_and_issues_new(
    token_service: TokenService,
    initialized_db_path: Path,
) -> None:
    """Verify token rotation revokes old token and issues a new active token for the same identity."""
    scopes = [PermissionScope.SANDBOX_CREATE]
    old = token_service.create_token(
        approver_id="charlie-lead",
        role="SECURITY_LEAD",
        authorized_scopes=scopes,
        db_path=initialized_db_path,
    )

    # Rotate token
    new = token_service.rotate_token(old.raw_token, db_path=initialized_db_path)

    # Old token is now revoked
    with pytest.raises(TokenRevokedError):
        token_service.resolve_identity(old.raw_token, db_path=initialized_db_path)

    # New token resolves successfully
    new_identity = token_service.resolve_identity(new.raw_token, db_path=initialized_db_path)
    assert new_identity.approver_id == "charlie-lead"
    assert new_identity.token_hash == new.token_hash
    assert new.raw_token != old.raw_token


def test_token_redaction_from_logs_and_headers(token_service: TokenService) -> None:
    """Verify sensitive tokens and authorization headers are scrubbed."""
    raw_sample = "User logged in with Bearer abcdef1234567890xyz and token=secret123456789"
    redacted = token_service.redact_token(raw_sample)
    assert "Bearer [REDACTED]" in redacted
    assert "token=[REDACTED]" in redacted
    assert "abcdef1234567890xyz" not in redacted
    assert "secret123456789" not in redacted

    headers = {
        "Host": "localhost:8000",
        "Authorization": "Bearer sensitive-token-string",
        "X-Approver-Token": "another-sensitive-token",
        "Content-Type": "application/json",
    }
    clean_headers = token_service.redact_sensitive_headers(headers)
    assert clean_headers["Authorization"] == "[REDACTED]"
    assert clean_headers["X-Approver-Token"] == "[REDACTED]"
    assert clean_headers["Content-Type"] == "application/json"
