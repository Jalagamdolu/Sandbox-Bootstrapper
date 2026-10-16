"""Server-side authorization guard enforcing mandatory just-in-time checks inside adapters."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3

from src.core.exceptions import AuthorizationDeniedError, TokenError
from src.models.approvals import AuthGuardEvaluationContext
from src.models.enums import StepActionType, WorkflowStatus
from src.security.tokens import TokenService
from src.storage.connection import get_connection


class ServerSideAuthGuard:
    """
    Shared server-side authorization guard.
    Embedded directly inside adapters (e.g. MockSandboxProvisioner, SyntheticDataSeeder)
    as the true security boundary, independent of LangGraph interrupts.
    """

    def __init__(self, token_service: TokenService | None = None) -> None:
        self.token_service = token_service or TokenService()

    def evaluate(
        self,
        context: AuthGuardEvaluationContext,
        caller_token: str | None = None,
        db_path: Path | str | None = None,
    ) -> bool:
        """
        Evaluate the 8 mandatory security parameters immediately before taking privileged action.
        Fails closed on any discrepancy, missing record, expiration, revocation, or mutation.

        Args:
            context: The 8 revalidation parameters.
            caller_token: Optional raw token of the actor invoking the privileged action.
            db_path: Optional explicit database path.

        Returns:
            True if all 8 security checks pass.

        Raises:
            AuthorizationDeniedError: If any condition fails (fails closed).
        """
        conn = get_connection(db_path)
        try:
            cursor = conn.cursor()

            # 1. Fetch approval record
            cursor.execute(
                """
                SELECT approval_id, request_id, approver_id, decision, canonical_plan_hash,
                       plan_version, target_environment, granted_scopes, created_at, expires_at,
                       is_revoked, execution_consumed
                FROM approval_records
                WHERE approval_id = ?;
                """,
                (context.approval_id,),
            )
            approval_row = cursor.fetchone()

            if approval_row is None:
                raise AuthorizationDeniedError(
                    f"Access Denied: Approval record '{context.approval_id}' does not exist."
                )

            # 2. Check approval decision outcome
            if approval_row["decision"] != "APPROVE":
                raise AuthorizationDeniedError(
                    f"Access Denied: Approval record '{context.approval_id}' outcome is '{approval_row['decision']}', not APPROVE."
                )

            # 3. Check revocation status
            if approval_row["is_revoked"]:
                raise AuthorizationDeniedError(
                    f"Access Denied: Approval record '{context.approval_id}' has been revoked."
                )

            # 4. Check expiration (TTL)
            expires_at = approval_row["expires_at"]
            if context.current_time.isoformat() > expires_at:
                raise AuthorizationDeniedError(
                    f"Access Denied: Approval record '{context.approval_id}' has expired."
                )

            # 5. Check exact request ID match
            if approval_row["request_id"] != context.request_id:
                raise AuthorizationDeniedError(
                    f"Access Denied: Request ID '{context.request_id}' does not match approval record request '{approval_row['request_id']}'."
                )

            # 6. Check canonical plan hash match
            if approval_row["canonical_plan_hash"] != context.active_plan_hash:
                raise AuthorizationDeniedError(
                    "Access Denied: Plan hash mismatch between execution context and approval record."
                )

            # 7. Check plan version match
            if approval_row["plan_version"] != context.active_plan_version:
                raise AuthorizationDeniedError(
                    f"Access Denied: Plan version {context.active_plan_version} does not match approval record version {approval_row['plan_version']}."
                )

            # 8. Check target environment match
            if approval_row["target_environment"] != context.target_environment:
                raise AuthorizationDeniedError(
                    f"Access Denied: Target environment '{context.target_environment}' does not match approval record '{approval_row['target_environment']}'."
                )

            # 9. Check required scope is granted
            granted_scopes = json.loads(approval_row["granted_scopes"])
            if context.required_scope.value not in granted_scopes:
                raise AuthorizationDeniedError(
                    f"Access Denied: Required scope '{context.required_scope.value}' is not granted in approval record."
                )

            # 10. Check active plan in setup_plans table (detect out-of-band plan mutation)
            cursor.execute(
                """
                SELECT canonical_plan_hash, plan_version, target_environment
                FROM setup_plans
                WHERE request_id = ?;
                """,
                (context.request_id,),
            )
            plan_row = cursor.fetchone()
            if plan_row is not None:
                if (
                    plan_row["canonical_plan_hash"] != context.active_plan_hash
                    or plan_row["plan_version"] != context.active_plan_version
                ):
                    raise AuthorizationDeniedError(
                        "Access Denied: Active setup plan in database has drifted from approved plan fingerprint."
                    )

            # 11. Check approver token status in approver_tokens table
            cursor.execute(
                """
                SELECT token_hash, approver_id, authorized_scopes, revoked_at
                FROM approver_tokens
                WHERE approver_id = ? AND revoked_at IS NULL;
                """,
                (approval_row["approver_id"],),
            )
            approver_token_row = cursor.fetchone()
            if approver_token_row is None:
                raise AuthorizationDeniedError(
                    f"Access Denied: Approver '{approval_row['approver_id']}' has no active (non-revoked) credential."
                )

            # 12. If caller token is supplied, verify caller identity and active status
            if caller_token is not None:
                try:
                    caller_identity = self.token_service.resolve_identity(caller_token, db_path=db_path)
                except TokenError as e:
                    raise AuthorizationDeniedError(f"Access Denied: Caller token invalid or revoked: {e}") from e

                if caller_identity.revoked_at is not None:
                    raise AuthorizationDeniedError("Access Denied: Caller token is revoked.")
                caller_scopes = [s.value for s in caller_identity.authorized_scopes]
                if context.required_scope.value not in caller_scopes:
                    raise AuthorizationDeniedError(
                        f"Access Denied: Caller '{caller_identity.approver_id}' lacks required scope '{context.required_scope.value}'."
                    )

            # 13. Verify workflow status permits this action
            cursor.execute(
                """
                SELECT status FROM bootstrap_requests WHERE request_id = ?;
                """,
                (context.request_id,),
            )
            req_row = cursor.fetchone()
            if req_row is not None:
                current_db_status = req_row["status"]
                # Incompatible statuses: FAILED, CANCELLED, REJECTED
                disallowed_statuses = {"FAILED", "CANCELLED", "REJECTED"}
                if current_db_status in disallowed_statuses:
                    raise AuthorizationDeniedError(
                        f"Access Denied: Operation not permitted while request is in '{current_db_status}' status."
                    )

            cursor.close()
            return True
        finally:
            conn.close()
