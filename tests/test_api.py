"""Integration tests for Developer Sandbox Bootstrapper REST API."""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from starlette.testclient import TestClient

from src.api.app import app
from src.core.config import get_settings
from src.models.enums import ApprovalDecisionType, PermissionScope, ProjectTemplate, WorkflowStatus
from src.storage.db_init import initialize_database


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolate SQLite database and sandbox directory for each test."""
    db_file = tmp_path / "test_bootstrapper.db"
    sbx_dir = tmp_path / "sandboxes"
    sbx_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("DATABASE_PATH", str(db_file))
    monkeypatch.setenv("SANDBOX_STORAGE_DIR", str(sbx_dir))

    get_settings(reload=True)
    initialize_database(db_file)
    yield
    get_settings(reload=True)


@pytest.fixture
def client():
    """FastAPI TestClient instance."""
    return TestClient(app)


def test_root_and_health_local_only(client: TestClient):
    """Verify root and health endpoints return MOCK / LOCAL ONLY metadata."""
    res_root = client.get("/")
    assert res_root.status_code == 200
    root_data = res_root.json()
    assert root_data["environment_label"] == "MOCK / LOCAL ONLY"
    assert root_data["local_only"] is True

    res_health = client.get("/health")
    assert res_health.status_code == 200
    health_data = res_health.json()
    assert health_data["status"] == "healthy"
    assert health_data["environment_label"] == "MOCK / LOCAL ONLY"
    assert health_data["mock_only"] is True
    assert health_data["cloud_provisioning"] is False


def test_create_request_success_and_idempotency(client: TestClient):
    """Verify request creation and idempotency enforcement."""
    payload = {
        "project_name": "checkout-service",
        "template": "python-fastapi-service",
        "repository_path": "./",
        "developer_id": "dev-bob",
        "target_environment": "local-mock-dev",
        "requested_scopes": ["sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"],
    }

    headers = {"Idempotency-Key": "idem-unique-12345"}
    res1 = client.post("/api/v1/requests", json=payload, headers=headers)
    assert res1.status_code == 201
    data1 = res1.json()
    assert data1["project_name"] == "checkout-service"
    assert data1["status"] == "DRAFT"
    req_id = data1["request_id"]

    # Repeat with same idempotency key -> returns existing request without error
    res2 = client.post("/api/v1/requests", json=payload, headers=headers)
    assert res2.status_code == 201
    data2 = res2.json()
    assert data2["request_id"] == req_id


def test_plan_retrieval_does_not_provision_or_seed(client: TestClient, tmp_path: Path):
    """Verify inspecting plan does not provision a sandbox or seed fixtures."""
    create_res = client.post(
        "/api/v1/requests",
        json={
            "project_name": "auth-service",
            "template": "python-fastapi-service",
            "repository_path": "./",
            "developer_id": "dev-charlie",
            "target_environment": "local-mock-dev",
            "requested_scopes": ["sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"],
        },
    )
    assert create_res.status_code == 201
    req_id = create_res.json()["request_id"]

    # Retrieve plan
    plan_res = client.get(f"/api/v1/requests/{req_id}/plan")
    assert plan_res.status_code == 200
    plan_data = plan_res.json()
    assert plan_data["canonical_plan_hash"]
    assert plan_data["plan_version"] == 1
    assert len(plan_data["steps"]) > 0

    # Verify zero sandboxes exist on disk
    sbx_base = tmp_path / "sandboxes"
    assert len(list(sbx_base.glob("*"))) == 0


def test_approval_state_endpoint(client: TestClient):
    """Verify approval state endpoint reflects pending approval."""
    create_res = client.post(
        "/api/v1/requests",
        json={
            "project_name": "billing-service",
            "template": "python-fastapi-service",
            "repository_path": "./",
            "developer_id": "dev-dan",
            "target_environment": "local-mock-dev",
            "requested_scopes": ["sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"],
        },
    )
    req_id = create_res.json()["request_id"]

    appr_state_res = client.get(f"/api/v1/requests/{req_id}/approval-state")
    assert appr_state_res.status_code == 200
    state_data = appr_state_res.json()
    assert state_data["request_id"] == req_id
    assert state_data["approval_required"] is True
    assert state_data["is_approved"] is False
    assert state_data["is_consumed"] is False
    assert state_data["canonical_plan_hash"] is not None


def test_unapproved_workflow_execution_pauses_at_await_approval(client: TestClient, tmp_path: Path):
    """Verify running a workflow without prior approval pauses and does NOT provision."""
    create_res = client.post(
        "/api/v1/requests",
        json={
            "project_name": "inventory-service",
            "template": "python-fastapi-service",
            "repository_path": "./",
            "developer_id": "dev-eve",
            "target_environment": "local-mock-dev",
            "requested_scopes": ["sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"],
        },
    )
    req_id = create_res.json()["request_id"]

    # Run workflow without approval
    run_res = client.post(f"/api/v1/requests/{req_id}/run", json={})
    assert run_res.status_code == 200
    run_data = run_res.json()
    assert run_data["approval_required"] is True
    assert run_data["is_completed"] is False
    assert run_data["current_status"] == "PENDING_APPROVAL"
    assert run_data["stage"] == "AWAIT_APPROVAL"

    # Verify zero sandboxes exist on disk
    sbx_base = tmp_path / "sandboxes"
    assert len(list(sbx_base.glob("*"))) == 0


def test_token_lifecycle_and_authentication(client: TestClient):
    """Verify approver token issuance, authentication, and revocation."""
    # 1. Issue token
    token_res = client.post(
        "/api/v1/tokens",
        json={
            "approver_id": "sec-lead-frank",
            "role": "SECURITY_LEAD",
            "authorized_scopes": ["sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"],
        },
    )
    assert token_res.status_code == 201
    token_data = token_res.json()
    raw_token = token_data["raw_token"]
    token_hash = token_data["token_hash"]
    assert len(raw_token) >= 32
    assert len(token_hash) == 64

    # 2. Test missing token on approval -> 401
    create_res = client.post(
        "/api/v1/requests",
        json={
            "project_name": "search-service",
            "template": "python-fastapi-service",
            "repository_path": "./",
            "developer_id": "dev-frank",
            "target_environment": "local-mock-dev",
            "requested_scopes": ["sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"],
        },
    )
    req_id = create_res.json()["request_id"]

    res_no_token = client.post(f"/api/v1/requests/{req_id}/approve", json={"decision": "APPROVE"})
    assert res_no_token.status_code == 401
    assert "error" in res_no_token.json()

    # 3. Test invalid token -> 401
    res_bad_token = client.post(
        f"/api/v1/requests/{req_id}/approve",
        json={"decision": "APPROVE", "approver_token": "invalid-random-token-xyz"},
    )
    assert res_bad_token.status_code == 401
    assert res_bad_token.json()["error"]["code"] == "TokenNotFoundError"

    # 4. Revoke token
    rev_res = client.post("/api/v1/tokens/revoke", json={"token_hash": token_hash})
    assert rev_res.status_code == 200
    assert rev_res.json()["status"] == "revoked"

    # 5. Using revoked token -> 403
    res_revoked = client.post(
        f"/api/v1/requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {raw_token}"},
        json={"decision": "APPROVE"},
    )
    assert res_revoked.status_code == 403
    assert res_revoked.json()["error"]["code"] == "TokenRevokedError"


def test_insufficient_scope_rejection(client: TestClient):
    """Verify approver with insufficient scopes cannot grant approval."""
    # Token only has sandbox:provision, missing fixtures:seed
    tok_res = client.post(
        "/api/v1/tokens",
        json={
            "approver_id": "junior-approver",
            "role": "JUNIOR_ENG",
            "authorized_scopes": ["sandbox:create"],
        },
    )
    raw_token = tok_res.json()["raw_token"]

    create_res = client.post(
        "/api/v1/requests",
        json={
            "project_name": "metrics-service",
            "template": "python-fastapi-service",
            "repository_path": "./",
            "developer_id": "dev-grace",
            "target_environment": "local-mock-dev",
            "requested_scopes": ["sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"],
        },
    )
    req_id = create_res.json()["request_id"]

    res = client.post(
        f"/api/v1/requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {raw_token}"},
        json={"decision": "APPROVE"},
    )
    assert res.status_code == 403
    assert res.json()["error"]["code"] == "TokenScopeError"


def test_full_workflow_lifecycle_and_manifest(client: TestClient):
    """Verify complete lifecycle: create -> approve -> run -> verify -> manifest."""
    # 1. Create request
    create_res = client.post(
        "/api/v1/requests",
        json={
            "project_name": "notification-service",
            "template": "python-fastapi-service",
            "repository_path": "./",
            "developer_id": "dev-heidi",
            "target_environment": "local-mock-dev",
            "requested_scopes": ["sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"],
        },
    )
    req_id = create_res.json()["request_id"]

    # 2. Issue valid token with required scopes
    tok_res = client.post(
        "/api/v1/tokens",
        json={
            "approver_id": "sec-lead-heidi",
            "role": "SECURITY_LEAD",
            "authorized_scopes": ["sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"],
        },
    )
    raw_token = tok_res.json()["raw_token"]

    # 3. Submit approval
    appr_res = client.post(
        f"/api/v1/requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {raw_token}"},
        json={"decision": "APPROVE"},
    )
    assert appr_res.status_code == 200
    appr_data = appr_res.json()
    assert appr_data["decision"] == "APPROVE"
    approval_id = appr_data["approval_id"]

    # 4. Run workflow to completion
    run_res = client.post(f"/api/v1/requests/{req_id}/run", json={"caller_token": raw_token})
    assert run_res.status_code == 200
    run_data = run_res.json()
    assert run_data["is_completed"] is True
    assert run_data["current_status"] == "COMPLETED"
    assert run_data["stage"] == "FINALIZE"
    assert run_data["manifest"] is not None

    # 5. Fetch manifest via API
    mani_res = client.get(f"/api/v1/requests/{req_id}/manifest")
    assert mani_res.status_code == 200
    manifest = mani_res.json()
    assert manifest["environment_label"] == "MOCK / LOCAL ONLY"
    assert manifest["workflow_status"] == "COMPLETED"
    assert sorted(manifest["data_seeding"]["fixtures_loaded"]) == sorted(["users.json", "teams.json", "projects.json", "configs.json"])
    assert manifest["integrity"]["manifest_sha256"]

    # 6. Verify audit chain via API
    audit_res = client.get(f"/api/v1/requests/{req_id}/audit")
    assert audit_res.status_code == 200
    audit_data = audit_res.json()
    assert audit_data["chain_valid"] is True
    assert len(audit_data["events"]) >= 5


def test_cleanup_authorization_enforcement(client: TestClient):
    """Verify sandbox cleanup strictly enforces SANDBOX_DELETE permission scope."""
    # 1. Setup completed workflow
    create_res = client.post(
        "/api/v1/requests",
        json={
            "project_name": "cleanup-test-service",
            "template": "python-fastapi-service",
            "repository_path": "./",
            "developer_id": "dev-ian",
            "target_environment": "local-mock-dev",
            "requested_scopes": ["sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"],
        },
    )
    req_id = create_res.json()["request_id"]

    # Provision token without delete
    tok_res = client.post(
        "/api/v1/tokens",
        json={
            "approver_id": "sec-lead-ian",
            "role": "SECURITY_LEAD",
            "authorized_scopes": ["sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"],
        },
    )
    raw_token = tok_res.json()["raw_token"]

    # Approve and run
    appr_res = client.post(
        f"/api/v1/requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {raw_token}"},
        json={"decision": "APPROVE"},
    )
    approval_id = appr_res.json()["approval_id"]

    run_res = client.post(f"/api/v1/requests/{req_id}/run", json={"caller_token": raw_token})
    manifest = run_res.json()["manifest"]
    sandbox_id = manifest["environment"]["sandbox_id"]

    # Attempt cleanup without SANDBOX_DELETE scope -> 403
    cleanup_fail_res = client.post(
        f"/api/v1/requests/{req_id}/cleanup",
        headers={"Authorization": f"Bearer {raw_token}"},
        json={
            "sandbox_id": sandbox_id,
            "approval_id": approval_id,
            "execution_id": "cleanup-exec-1",
        },
    )
    assert cleanup_fail_res.status_code == 403
    assert cleanup_fail_res.json()["error"]["code"] == "TokenScopeError"

    # Issue token with SANDBOX_DELETE scope
    admin_tok_res = client.post(
        "/api/v1/tokens",
        json={
            "approver_id": "platform-admin",
            "role": "PLATFORM_ADMIN",
            "authorized_scopes": ["sandbox:delete", "sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"],
        },
    )
    admin_token = admin_tok_res.json()["raw_token"]

    # Also update approval to include SANDBOX_DELETE
    admin_appr_res = client.post(
        f"/api/v1/requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "decision": "APPROVE",
            "granted_scopes": ["sandbox:delete", "sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"],
        },
    )
    delete_approval_id = admin_appr_res.json()["approval_id"]

    # Cleanup with authorized token -> 200
    cleanup_success_res = client.post(
        f"/api/v1/requests/{req_id}/cleanup",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "sandbox_id": sandbox_id,
            "approval_id": delete_approval_id,
            "execution_id": "cleanup-exec-2",
        },
    )
    assert cleanup_success_res.status_code == 200
    assert cleanup_success_res.json()["status"] == "deleted"


def test_plan_mutation_and_mismatch_rejection(client: TestClient):
    """Verify that submitting an approval with drifted plan hash is rejected with 400 ApprovalMismatchError."""
    # 1. Create request
    create_res = client.post(
        "/api/v1/requests",
        json={
            "project_name": "tamper-service",
            "template": "python-fastapi-service",
            "repository_path": "./",
            "developer_id": "dev-tamper",
            "target_environment": "local-mock-dev",
            "requested_scopes": ["sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"],
        },
    )
    req_id = create_res.json()["request_id"]

    # 2. Issue valid token
    tok_res = client.post(
        "/api/v1/tokens",
        json={
            "approver_id": "sec-lead-tamper",
            "role": "SECURITY_LEAD",
            "authorized_scopes": ["sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"],
        },
    )
    raw_token = tok_res.json()["raw_token"]

    # Fetch real plan
    plan_res = client.get(f"/api/v1/requests/{req_id}/plan")
    real_hash = plan_res.json()["canonical_plan_hash"]

    # Mutate plan directly in database to simulate backend drift
    from src.storage.connection import get_connection
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE setup_plans SET canonical_plan_hash = ? WHERE request_id = ?",
        ("mutated_hash_" + "0" * 51, req_id),
    )
    conn.commit()
    conn.close()

    # Try to approve with original plan hash -> must fail with ApprovalMismatchError
    appr_res = client.post(
        f"/api/v1/requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {raw_token}"},
        json={"decision": "APPROVE"},
    )
    assert appr_res.status_code == 400
    assert appr_res.json()["error"]["code"] == "ApprovalMismatchError"


def test_expired_approval_rejection_in_workflow(client: TestClient):
    """Verify that an expired approval prevents workflow execution."""
    create_res = client.post(
        "/api/v1/requests",
        json={
            "project_name": "expiry-service",
            "template": "python-fastapi-service",
            "repository_path": "./",
            "developer_id": "dev-expiry",
            "target_environment": "local-mock-dev",
            "requested_scopes": ["sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"],
        },
    )
    req_id = create_res.json()["request_id"]

    tok_res = client.post(
        "/api/v1/tokens",
        json={
            "approver_id": "sec-lead-exp",
            "role": "SECURITY_LEAD",
            "authorized_scopes": ["sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"],
        },
    )
    raw_token = tok_res.json()["raw_token"]

    appr_res = client.post(
        f"/api/v1/requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {raw_token}"},
        json={"decision": "APPROVE"},
    )
    approval_id = appr_res.json()["approval_id"]

    # Expire approval in database
    from src.storage.connection import get_connection
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE approval_records SET expires_at = '2020-01-01T00:00:00+00:00' WHERE approval_id = ?",
        (approval_id,),
    )
    conn.commit()
    conn.close()

    # Run workflow -> must pause or fail closed because approval is expired
    run_res = client.post(f"/api/v1/requests/{req_id}/run", json={"caller_token": raw_token})
    assert run_res.status_code == 200
    run_data = run_res.json()
    assert run_data["is_completed"] is False
    assert run_data["current_status"] == "EXPIRED"
    assert run_data["error_category"] == "ApprovalExpiredError"


def test_secret_redaction_and_no_leakage(client: TestClient):
    """Verify responses do not leak raw tokens, private keys, or passwords."""
    tok_res = client.post(
        "/api/v1/tokens",
        json={
            "approver_id": "sec-lead-leaktest",
            "role": "SECURITY_LEAD",
            "authorized_scopes": ["sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"],
        },
    )
    raw_token = tok_res.json()["raw_token"]

    create_res = client.post(
        "/api/v1/requests",
        json={
            "project_name": "redact-service",
            "template": "python-fastapi-service",
            "repository_path": "./",
            "developer_id": "dev-leaktest",
            "target_environment": "local-mock-dev",
            "requested_scopes": ["sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"],
        },
    )
    req_id = create_res.json()["request_id"]

    # Approving with header
    appr_res = client.post(
        f"/api/v1/requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {raw_token}"},
        json={"decision": "APPROVE"},
    )
    body_text = appr_res.text
    # Raw token must NEVER appear in approval response body
    assert raw_token not in body_text

    # Manifest must not contain private keys or password patterns
    run_res = client.post(f"/api/v1/requests/{req_id}/run", json={"caller_token": raw_token})
    mani_res = client.get(f"/api/v1/requests/{req_id}/manifest")
    manifest_text = mani_res.text
    assert "BEGIN RSA PRIVATE KEY" not in manifest_text
    assert "BEGIN OPENSSH PRIVATE KEY" not in manifest_text
    assert "aws_secret_access_key" not in manifest_text


def test_deps_functions_directly():
    """Verify all dependency injection helper functions in src.api.deps."""
    from fastapi import HTTPException
    from src.api.deps import (
        extract_bearer_token,
        get_api_settings,
        get_approval_service,
        get_audit_service,
        get_current_approver,
        get_orchestrator,
        get_token_service,
    )

    # 1. Getters
    settings = get_api_settings()
    assert settings is not None
    appr_svc = get_approval_service()
    tok_svc = get_token_service()
    audit_svc = get_audit_service()
    orch = get_orchestrator(appr_svc, audit_svc)
    assert orch.approval_service is appr_svc

    # 2. extract_bearer_token
    assert extract_bearer_token("Bearer secret_tok") == "secret_tok"
    assert extract_bearer_token(None) is None
    assert extract_bearer_token("Basic dXNlcjpwYXNz") is None
    assert extract_bearer_token("Bearer") is None

    # 3. get_current_approver missing token
    with pytest.raises(HTTPException) as exc_info:
        get_current_approver(None, tok_svc)
    assert exc_info.value.status_code == 401

    # 4. get_current_approver valid token
    tok_res = tok_svc.create_token("sec-lead-deps", "SECURITY_LEAD", [PermissionScope.SANDBOX_READ])
    identity = get_current_approver(tok_res.raw_token, tok_svc)
    assert identity.approver_id == "sec-lead-deps"

    # 5. get_current_approver revoked token
    tok_svc.revoke_token_by_hash(tok_res.token_hash)
    with pytest.raises(HTTPException) as exc_info_rev:
        get_current_approver(tok_res.raw_token, tok_svc)
    assert exc_info_rev.value.status_code == 403

    # 6. get_current_approver unknown token
    with pytest.raises(HTTPException) as exc_info_bad:
        get_current_approver("unknown-token-12345", tok_svc)
    assert exc_info_bad.value.status_code == 401
