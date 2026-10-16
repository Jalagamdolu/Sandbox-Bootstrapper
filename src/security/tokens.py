"""Server-side approver token lifecycle, identity resolution, and redaction service."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import sqlite3

from src.core.exceptions import (
    DatabaseError,
    SecurityViolationError,
    TokenNotFoundError,
    TokenRevokedError,
)
from src.models.approvals import ApproverIdentity
from src.models.enums import PermissionScope
from src.storage.connection import get_connection, transaction_scope


@dataclass(frozen=True)
class TokenCreationResult:
    """Returned ONLY ONCE during token generation or rotation. Never logged or persisted."""

    raw_token: str
    token_hash: str
    approver_id: str
    role: str
    authorized_scopes: list[PermissionScope]
    created_at: datetime


class TokenService:
    """Manages secure generation, constant-time resolution, rotation, and revocation of approver tokens."""

    @staticmethod
    def hash_token(raw_token: str) -> str:
        """Compute the SHA-256 digest of a raw token."""
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    @staticmethod
    def redact_token(text: str) -> str:
        """Scrub bearer tokens and sensitive authorization patterns from strings."""
        if not text:
            return text
        # Redact Bearer tokens
        text = re.sub(r"(Bearer\s+)[A-Za-z0-9_\-\.]{10,}", r"\1[REDACTED]", text, flags=re.IGNORECASE)
        # Redact explicit token query params or assignments
        text = re.sub(r"(token=)[A-Za-z0-9_\-\.]{10,}", r"\1[REDACTED]", text, flags=re.IGNORECASE)
        # Redact raw secret values in JSON-like structures
        text = re.sub(r'("(?:token|raw_token|secret|password)"\s*:\s*")[^"]+(")', r"\1[REDACTED]\2", text, flags=re.IGNORECASE)
        return text

    @staticmethod
    def redact_sensitive_headers(headers: dict[str, str]) -> dict[str, str]:
        """Redact sensitive authorization and identity claims from HTTP header dictionaries."""
        clean_headers: dict[str, str] = {}
        sensitive_keys = {"authorization", "x-approver-token", "proxy-authorization", "cookie"}
        for k, v in headers.items():
            if k.lower() in sensitive_keys:
                clean_headers[k] = "[REDACTED]"
            else:
                clean_headers[k] = v
        return clean_headers

    def create_token(
        self,
        approver_id: str,
        role: str,
        authorized_scopes: list[PermissionScope],
        db_path: Path | str | None = None,
    ) -> TokenCreationResult:
        """
        Generate a cryptographically secure token with at least 256 bits of entropy.
        Persists only the SHA-256 digest in the database. Returns raw token once.

        Args:
            approver_id: Unique human identifier (e.g. 'sec-lead-01').
            role: Security role (e.g. 'SECURITY_LEAD').
            authorized_scopes: Maximum permission scopes this token can authorize.
            db_path: Optional explicit database path.

        Returns:
            TokenCreationResult containing the raw token (displayed once) and metadata.
        """
        # 32 url-safe bytes provide 256 bits of cryptographic entropy
        raw_token = secrets.token_urlsafe(32)
        token_hash = self.hash_token(raw_token)
        now = datetime.now(timezone.utc)
        scopes_json = json.dumps([s.value for s in authorized_scopes])

        conn = get_connection(db_path)
        try:
            with transaction_scope(conn) as cursor:
                cursor.execute(
                    """
                    INSERT INTO approver_tokens (
                        token_hash, approver_id, role, authorized_scopes, created_at, revoked_at
                    ) VALUES (?, ?, ?, ?, ?, NULL);
                    """,
                    (token_hash, approver_id, role, scopes_json, now.isoformat()),
                )
        except sqlite3.IntegrityError as err:
            raise SecurityViolationError(f"Token generation collision or database constraint failure: {err}") from err
        finally:
            conn.close()

        return TokenCreationResult(
            raw_token=raw_token,
            token_hash=token_hash,
            approver_id=approver_id,
            role=role,
            authorized_scopes=authorized_scopes,
            created_at=now,
        )

    def resolve_identity(
        self,
        raw_token: str,
        client_claimed_id: str | None = None,
        db_path: Path | str | None = None,
    ) -> ApproverIdentity:
        """
        Resolve authenticated approver identity from a raw token.

        Guarantees:
        1. Client-supplied identity (e.g. X-Approver-Id) is structurally ignored.
        2. Computed SHA-256 hash is compared using constant-time comparison (hmac.compare_digest).
        3. Revoked tokens are rejected immediately.

        Args:
            raw_token: Plaintext bearer token provided by caller.
            client_claimed_id: Untrusted client-supplied identity claim (strictly ignored).
            db_path: Optional explicit database path.

        Returns:
            ApproverIdentity model verified server-side.

        Raises:
            TokenNotFoundError: If token does not exist.
            TokenRevokedError: If token has been revoked.
        """
        if not raw_token or not raw_token.strip():
            raise TokenNotFoundError("Empty or invalid bearer token provided.")

        computed_hash = self.hash_token(raw_token.strip())

        conn = get_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT token_hash, approver_id, role, authorized_scopes, created_at, revoked_at
                FROM approver_tokens
                WHERE token_hash = ?;
                """,
                (computed_hash,),
            )
            row = cursor.fetchone()
            cursor.close()
        finally:
            conn.close()

        if row is None:
            raise TokenNotFoundError("Invalid or unknown approver token.")

        # Constant-time comparison
        stored_hash: str = row["token_hash"]
        if not hmac.compare_digest(stored_hash, computed_hash):
            raise TokenNotFoundError("Approver token digest mismatch.")

        # Check revocation
        revoked_at_str = row["revoked_at"]
        if revoked_at_str is not None:
            raise TokenRevokedError(f"Approver token for '{row['approver_id']}' has been revoked.")

        scopes_raw = json.loads(row["authorized_scopes"])
        authorized_scopes = [PermissionScope(s) for s in scopes_raw]

        return ApproverIdentity(
            approver_id=row["approver_id"],
            role=row["role"],
            authorized_scopes=authorized_scopes,
            token_hash=stored_hash,
            created_at=datetime.fromisoformat(row["created_at"]),
            revoked_at=None,
        )

    def revoke_token(self, raw_token: str, db_path: Path | str | None = None) -> bool:
        """
        Revoke an active approver token so it can never be used again.

        Args:
            raw_token: Raw token to revoke.
            db_path: Optional explicit database path.

        Returns:
            True if token was found and revoked, False if token did not exist.
        """
        token_hash = self.hash_token(raw_token)
        return self.revoke_token_by_hash(token_hash, db_path=db_path)

    def revoke_token_by_hash(self, token_hash: str, db_path: Path | str | None = None) -> bool:
        """Revoke a token record by its SHA-256 digest."""
        now = datetime.now(timezone.utc).isoformat()
        conn = get_connection(db_path)
        try:
            with transaction_scope(conn) as cursor:
                cursor.execute(
                    """
                    UPDATE approver_tokens
                    SET revoked_at = ?
                    WHERE token_hash = ? AND revoked_at IS NULL;
                    """,
                    (now, token_hash),
                )
                return cursor.rowcount > 0
        finally:
            conn.close()

    def rotate_token(
        self,
        raw_old_token: str,
        db_path: Path | str | None = None,
    ) -> TokenCreationResult:
        """
        Rotate an existing active token: invalidates the old token and issues a new one
        with the same approver ID, role, and authorized scopes.

        Args:
            raw_old_token: The current valid raw token.
            db_path: Optional explicit database path.

        Returns:
            TokenCreationResult containing the new raw token.

        Raises:
            TokenNotFoundError: If old token does not exist.
            TokenRevokedError: If old token is already revoked.
        """
        # Resolve identity from old token (validates non-revocation)
        old_identity = self.resolve_identity(raw_old_token, db_path=db_path)

        # Generate new token
        raw_new_token = secrets.token_urlsafe(32)
        new_token_hash = self.hash_token(raw_new_token)
        now = datetime.now(timezone.utc)
        scopes_json = json.dumps([s.value for s in old_identity.authorized_scopes])

        conn = get_connection(db_path)
        try:
            with transaction_scope(conn) as cursor:
                # 1. Revoke old token
                cursor.execute(
                    """
                    UPDATE approver_tokens
                    SET revoked_at = ?
                    WHERE token_hash = ? AND revoked_at IS NULL;
                    """,
                    (now.isoformat(), old_identity.token_hash),
                )

                # 2. Insert new token
                cursor.execute(
                    """
                    INSERT INTO approver_tokens (
                        token_hash, approver_id, role, authorized_scopes, created_at, revoked_at
                    ) VALUES (?, ?, ?, ?, ?, NULL);
                    """,
                    (new_token_hash, old_identity.approver_id, old_identity.role, scopes_json, now.isoformat()),
                )
        finally:
            conn.close()

        return TokenCreationResult(
            raw_token=raw_new_token,
            token_hash=new_token_hash,
            approver_id=old_identity.approver_id,
            role=old_identity.role,
            authorized_scopes=old_identity.authorized_scopes,
            created_at=now,
        )
