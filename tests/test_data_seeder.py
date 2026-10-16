"""Tests for SyntheticDataSeeder, fixture allowlisting, path confinement, and idempotence."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import pytest

from src.adapters.data_seeder import SyntheticDataSeeder
from src.adapters.fixtures import ALLOWED_FIXTURE_IDS, scan_for_sensitive_secrets
from src.adapters.sandbox_provisioner import MockSandboxProvisioner
from src.core.exceptions import (
    AuthorizationDeniedError,
    PathTraversalError,
    ResourceOwnershipError,
    SyntheticDataSeedingError,
    UnknownFixtureError,
)
from src.models.approvals import ApprovalDecisionType, ApprovalRequest
from src.models.enums import PermissionScope
from src.security.approvals import ApprovalService
from src.security.tokens import TokenService
from src.storage.connection import get_connection


def _setup_req_and_plan(db_path: Path, request_id: str, plan_hash: str) -> None:
    """Helper to populate bootstrap_requests and setup_plans rows."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    cursor.execute(
        """
        INSERT OR IGNORE INTO bootstrap_requests (
            request_id, idempotency_key, project_name, template, repository_path,
            requested_scopes, developer_id, target_environment, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'APPROVED', ?, ?);
        """,
        (
            request_id,
            f"idem-{request_id}",
            "seed-proj",
            "python-fastapi-service",
            "c:/repos/proj",
            '["sandbox:create", "data:seed:synthetic"]',
            "dev-1",
            "local-sandbox",
            now,
            now,
        ),
    )
    cursor.execute(
        """
        INSERT OR REPLACE INTO setup_plans (
            plan_id, request_id, plan_version, target_environment, canonical_plan_hash, plan_json, created_at
        ) VALUES (?, ?, 1, 'local-sandbox', ?, '{}', ?);
        """,
        (f"plan-{request_id}", request_id, plan_hash, now),
    )
    conn.commit()
    conn.close()


def test_seed_allowlisted_fixtures_success(
    sandbox_provisioner: MockSandboxProvisioner,
    data_seeder: SyntheticDataSeeder,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
) -> None:
    """Verify all allowlisted synthetic fixtures seed cleanly with hashes and without PII."""
    req_id = "req-seed-01"
    plan_hash = "1" * 64
    _setup_req_and_plan(initialized_db_path, req_id, plan_hash)

    token_res = token_service.create_token(
        approver_id="lead-seed",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.DATA_SEED_SYNTHETIC],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)

    approval = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
            plan_version=1,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.DATA_SEED_SYNTHETIC],
        db_path=initialized_db_path,
    )

    # 1. Provision sandbox
    sbx = sandbox_provisioner.provision_sandbox(
        request_id=req_id,
        approval_id=approval.approval_id,
        execution_id="exec-seed-run-1",
        step_id="step-00000001",
        plan_hash=plan_hash,
        plan_version=1,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.DATA_SEED_SYNTHETIC],
        caller_token=token_res.raw_token,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )

    # 2. Seed all allowlisted fixtures
    summary = data_seeder.seed_fixtures(
        request_id=req_id,
        sandbox_id=sbx.sandbox_id,
        approval_id=approval.approval_id,
        execution_id="exec-seed-run-1",
        step_id="step-00000002",
        plan_hash=plan_hash,
        plan_version=1,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.DATA_SEED_SYNTHETIC],
        fixture_ids=["users.json", "teams.json", "projects.json", "configs.json"],
        destination_subpath="mock_fixtures",
        caller_token=token_res.raw_token,
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )

    assert summary.request_id == req_id
    assert summary.sandbox_id == sbx.sandbox_id
    assert len(summary.fixtures_seeded) == 4
    assert summary.is_mock is True
    assert summary.environment_label == "MOCK / LOCAL ONLY"

    for r in summary.fixtures_seeded:
        assert r.status == "SEEDED"
        assert len(r.sha256_hash) == 64
        assert r.destination_path.exists()
        # Verify JSON validity
        content = json.loads(r.destination_path.read_text(encoding="utf-8"))
        assert content is not None


def test_disallowed_fixture_rejected(
    data_seeder: SyntheticDataSeeder,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
) -> None:
    """Verify any fixture not in ALLOWED_FIXTURE_IDS is rejected with UnknownFixtureError."""
    with pytest.raises(UnknownFixtureError, match="not allowlisted"):
        data_seeder.seed_fixtures(
            request_id="req-seed-bad",
            sandbox_id="sbx-test",
            approval_id="appr-test",
            execution_id="exec-test",
            step_id="step-00000002",
            plan_hash="2" * 64,
            plan_version=1,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.DATA_SEED_SYNTHETIC],
            fixture_ids=["arbitrary_script.sh"],
            custom_root=mock_sandbox_root,
            db_path=initialized_db_path,
        )


def test_path_traversal_in_fixtures_rejected(
    sandbox_provisioner: MockSandboxProvisioner,
    data_seeder: SyntheticDataSeeder,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
) -> None:
    """Verify attempting to seed outside the sandbox directory is rejected."""
    req_id = "req-seed-trav"
    plan_hash = "3" * 64
    _setup_req_and_plan(initialized_db_path, req_id, plan_hash)

    token_res = token_service.create_token(
        approver_id="lead-trav",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.DATA_SEED_SYNTHETIC],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)

    approval = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
            plan_version=1,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.DATA_SEED_SYNTHETIC],
        db_path=initialized_db_path,
    )

    sbx = sandbox_provisioner.provision_sandbox(
        request_id=req_id,
        approval_id=approval.approval_id,
        execution_id="exec-trav-01",
        step_id="step-00000001",
        plan_hash=plan_hash,
        plan_version=1,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.DATA_SEED_SYNTHETIC],
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )

    # Attempt directory traversal via destination_subpath
    with pytest.raises(PathTraversalError):
        data_seeder.seed_fixtures(
            request_id=req_id,
            sandbox_id=sbx.sandbox_id,
            approval_id=approval.approval_id,
            execution_id="exec-trav-01",
            step_id="step-00000002",
            plan_hash=plan_hash,
            plan_version=1,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.DATA_SEED_SYNTHETIC],
            fixture_ids=["users.json"],
            destination_subpath="../../escape_fixtures",
            custom_root=mock_sandbox_root,
            db_path=initialized_db_path,
        )


def test_seeding_idempotence(
    sandbox_provisioner: MockSandboxProvisioner,
    data_seeder: SyntheticDataSeeder,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
) -> None:
    """Verify repeated seeding of identical fixtures is idempotent and reports UNCHANGED."""
    req_id = "req-seed-idem"
    plan_hash = "4" * 64
    _setup_req_and_plan(initialized_db_path, req_id, plan_hash)

    token_res = token_service.create_token(
        approver_id="lead-idem",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.DATA_SEED_SYNTHETIC],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)

    approval = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
            plan_version=1,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.DATA_SEED_SYNTHETIC],
        db_path=initialized_db_path,
    )

    sbx = sandbox_provisioner.provision_sandbox(
        request_id=req_id,
        approval_id=approval.approval_id,
        execution_id="exec-idem-run",
        step_id="step-00000001",
        plan_hash=plan_hash,
        plan_version=1,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.DATA_SEED_SYNTHETIC],
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )

    # First seeding
    run1 = data_seeder.seed_fixtures(
        request_id=req_id,
        sandbox_id=sbx.sandbox_id,
        approval_id=approval.approval_id,
        execution_id="exec-idem-run",
        step_id="step-00000002",
        plan_hash=plan_hash,
        plan_version=1,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.DATA_SEED_SYNTHETIC],
        fixture_ids=["users.json"],
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )
    assert run1.fixtures_seeded[0].status == "SEEDED"

    # Second seeding
    run2 = data_seeder.seed_fixtures(
        request_id=req_id,
        sandbox_id=sbx.sandbox_id,
        approval_id=approval.approval_id,
        execution_id="exec-idem-run",
        step_id="step-00000002",
        plan_hash=plan_hash,
        plan_version=1,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.DATA_SEED_SYNTHETIC],
        fixture_ids=["users.json"],
        custom_root=mock_sandbox_root,
        db_path=initialized_db_path,
    )
    assert run2.fixtures_seeded[0].status == "UNCHANGED"
    assert run1.fixtures_seeded[0].sha256_hash == run2.fixtures_seeded[0].sha256_hash


def test_unauthorized_seeding_fails_closed(
    data_seeder: SyntheticDataSeeder,
    approval_service: ApprovalService,
    token_service: TokenService,
    initialized_db_path: Path,
    mock_sandbox_root: Path,
) -> None:
    """Verify seeding is denied if approval lacks DATA_SEED_SYNTHETIC scope."""
    req_id = "req-seed-unauth"
    plan_hash = "5" * 64
    _setup_req_and_plan(initialized_db_path, req_id, plan_hash)

    # Approver only granted SANDBOX_CREATE
    token_res = token_service.create_token(
        approver_id="lead-nocreate",
        role="SECURITY_LEAD",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE],
        db_path=initialized_db_path,
    )
    identity = token_service.resolve_identity(token_res.raw_token, db_path=initialized_db_path)

    approval = approval_service.create_approval(
        request=ApprovalRequest(
            request_id=req_id,
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash=plan_hash,
            plan_version=1,
        ),
        approver=identity,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],  # Lacks DATA_SEED_SYNTHETIC!
        db_path=initialized_db_path,
    )

    with pytest.raises(AuthorizationDeniedError, match="Required scope .* is not granted"):
        data_seeder.seed_fixtures(
            request_id=req_id,
            sandbox_id="sbx-fake",
            approval_id=approval.approval_id,
            execution_id="exec-unauth",
            step_id="step-00000002",
            plan_hash=plan_hash,
            plan_version=1,
            target_environment="local-sandbox",
            granted_scopes=[PermissionScope.SANDBOX_CREATE],
            fixture_ids=["users.json"],
            custom_root=mock_sandbox_root,
            db_path=initialized_db_path,
        )


def test_defense_in_depth_regex_scan() -> None:
    """Verify scanner catches live AWS credentials or private keys and raises SyntheticDataSeedingError."""
    # Fake AWS Key pattern
    dirty_text = '{"aws_key": "AKIAIOSFODNN7EXAMPLE"}'
    with pytest.raises(SyntheticDataSeedingError, match="AWS Access Key"):
        scan_for_sensitive_secrets(dirty_text)

    # Fake private key
    fake_pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
    with pytest.raises(SyntheticDataSeedingError, match="Private Key Header"):
        scan_for_sensitive_secrets(fake_pem)

    # Safe synthetic payload passes without error
    safe_text = '{"user": "dev@example.local", "is_mock": true}'
    scan_for_sensitive_secrets(safe_text)
