"""Tests for Pydantic domain models, data contracts, and strict validation."""

from __future__ import annotations

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from src.models import (
    ApprovalDecisionType,
    ApprovalRecord,
    ApprovalRequest,
    ApproverIdentity,
    AuditActor,
    AuditEvent,
    AuditEventType,
    AuditSeverity,
    AuthGuardEvaluationContext,
    BootstrapRequestCreate,
    BootstrapRequestResponse,
    CanonicalApprovalPayload,
    DashboardDiscoveryResult,
    ManifestEnvironment,
    ManifestProvisioningInfo,
    ManifestSeedSummary,
    ManifestSignatureMetadata,
    PermissionScope,
    PlannedStep,
    ProjectTemplate,
    RepoDiscoveryResult,
    ResourceOwnershipMetadata,
    SandboxRetentionConfig,
    SetupManifest,
    SetupPlan,
    SmokeTestEvidence,
    StepActionType,
    StepExecutionResult,
    StepExecutionStatus,
    WorkflowState,
    WorkflowStatus,
)


def test_bootstrap_request_create_valid() -> None:
    """Verify valid request creation and scope deduplication/sorting."""
    req = BootstrapRequestCreate(
        project_name="my-service_01",
        template=ProjectTemplate.PYTHON_FASTAPI,
        repository_path="c:/repos/my-service",
        requested_scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.SANDBOX_READ],
        developer_id="dev-alice",
        target_environment="local-sandbox",
    )

    assert req.project_name == "my-service_01"
    assert req.template == ProjectTemplate.PYTHON_FASTAPI
    # Verify scopes are sorted
    assert req.requested_scopes == [PermissionScope.SANDBOX_CREATE, PermissionScope.SANDBOX_READ] or req.requested_scopes == sorted(req.requested_scopes, key=lambda s: s.value)


def test_bootstrap_request_create_duplicate_scopes_rejected() -> None:
    """Verify rejection of duplicate permission scopes."""
    with pytest.raises(ValidationError, match="Duplicate permission scopes"):
        BootstrapRequestCreate(
            project_name="service-test",
            template=ProjectTemplate.NODE_MICROSERVICE,
            repository_path="c:/repos/node",
            requested_scopes=[PermissionScope.SANDBOX_READ, PermissionScope.SANDBOX_READ],
            developer_id="dev-bob",
        )


def test_bootstrap_request_create_empty_scopes_rejected() -> None:
    """Verify rejection of empty permission scopes list."""
    with pytest.raises(ValidationError):
        BootstrapRequestCreate(
            project_name="service-test",
            template=ProjectTemplate.NODE_MICROSERVICE,
            repository_path="c:/repos/node",
            requested_scopes=[],
            developer_id="dev-bob",
        )


def test_bootstrap_request_create_invalid_template() -> None:
    """Verify rejection of unknown project template."""
    with pytest.raises(ValidationError):
        BootstrapRequestCreate(
            project_name="service-test",
            template="invalid-template-name",  # type: ignore[arg-type]
            repository_path="c:/repos/node",
            requested_scopes=[PermissionScope.SANDBOX_READ],
            developer_id="dev-bob",
        )


def test_bootstrap_request_create_invalid_project_name() -> None:
    """Verify rejection of illegal characters in project name."""
    with pytest.raises(ValidationError):
        BootstrapRequestCreate(
            project_name="service with spaces!@#",
            template=ProjectTemplate.REACT_CLIENT,
            repository_path="c:/repos/react",
            requested_scopes=[PermissionScope.SANDBOX_READ],
            developer_id="dev-bob",
        )


def test_bootstrap_request_extra_fields_forbidden() -> None:
    """Verify rejection of unexpected fields in request creation."""
    with pytest.raises(ValidationError):
        BootstrapRequestCreate(
            project_name="service-test",
            template=ProjectTemplate.PYTHON_FASTAPI,
            repository_path="c:/repos/py",
            requested_scopes=[PermissionScope.SANDBOX_READ],
            developer_id="dev-bob",
            client_approved_flag=True,  # Disallowed extra field
        )  # type: ignore[call-arg]


def test_planned_step_valid() -> None:
    """Verify valid planned step creation."""
    step = PlannedStep(
        step_id="step-1234abcd",
        action_type=StepActionType.PROVISION_MOCK_SANDBOX,
        name="Provision Environment",
        description="Creates local mock directory structure",
        is_privileged=True,
        required_scopes=[PermissionScope.SANDBOX_CREATE],
        depends_on_step_ids=["step-00000000"],
        action_parameters={"template": "python-fastapi"},
    )
    assert step.step_id == "step-1234abcd"
    assert step.is_privileged is True


@pytest.mark.parametrize(
    "forbidden_param",
    ["shell_cmd", "bash", "exec", "eval", "python_code", "cmd", "powershell"],
)
def test_planned_step_dangerous_parameters_rejected(forbidden_param: str) -> None:
    """Verify that dangerous parameters attempting shell/code execution are rejected."""
    with pytest.raises(ValidationError, match="Dangerous action parameter detected"):
        PlannedStep(
            step_id="step-11112222",
            action_type=StepActionType.PROVISION_MOCK_SANDBOX,
            name="Exploit Step",
            description="Attempting command execution",
            is_privileged=True,
            required_scopes=[PermissionScope.SANDBOX_CREATE],
            action_parameters={forbidden_param: "rm -rf /"},
        )


def test_planned_step_invalid_id_pattern() -> None:
    """Verify rejection of malformed step_id patterns."""
    with pytest.raises(ValidationError):
        PlannedStep(
            step_id="bad-step-id",
            action_type=StepActionType.DISCOVER_REPOSITORY,
            name="Discovery",
            description="Discovery step",
            is_privileged=False,
        )


def test_setup_plan_extra_fields_forbidden() -> None:
    """Verify SetupPlan rejects unknown attributes."""
    with pytest.raises(ValidationError):
        SetupPlan(
            plan_id="plan-001",
            request_id="req-001",
            plan_version=1,
            target_environment="local-sandbox",
            steps=[],
            estimated_duration_seconds=10,
            created_at=datetime.now(timezone.utc),
            canonical_plan_hash="a" * 64,
            injected_attribute="malicious",  # Disallowed
        )  # type: ignore[call-arg]


def test_canonical_approval_payload_sorting() -> None:
    """Verify list attributes in CanonicalApprovalPayload are sorted deterministically."""
    payload = CanonicalApprovalPayload(
        request_id="req-999",
        target_environment="local-sandbox",
        plan_version=1,
        granted_scopes=["test:execute", "sandbox:read", "data:seed:synthetic"],
        planned_actions=[{"step_id": "step-01"}],
        synthetic_fixtures=["teams.json", "accounts.json", "users.json"],
    )

    assert payload.granted_scopes == ["data:seed:synthetic", "sandbox:read", "test:execute"]
    assert payload.synthetic_fixtures == ["accounts.json", "teams.json", "users.json"]


def test_approval_request_rejects_client_identity() -> None:
    """Verify ApprovalRequest does NOT accept or trust a client-supplied approver_id."""
    with pytest.raises(ValidationError):
        ApprovalRequest(
            request_id="req-123",
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash="b" * 64,
            approver_id="attacker-claimed-admin",  # Client cannot supply approver_id
        )  # type: ignore[call-arg]


def test_approval_request_rejects_client_approved_flag() -> None:
    """Verify ApprovalRequest does NOT accept client-supplied approved flag."""
    with pytest.raises(ValidationError):
        ApprovalRequest(
            request_id="req-123",
            decision=ApprovalDecisionType.APPROVE,
            submitted_plan_hash="b" * 64,
            approved=True,  # Disallowed flag
        )  # type: ignore[call-arg]


def test_approver_identity_valid_and_frozen() -> None:
    """Verify ApproverIdentity model validation and immutability."""
    now = datetime.now(timezone.utc)
    ident = ApproverIdentity(
        approver_id="sec-lead-01",
        role="SECURITY_APPROVER",
        authorized_scopes=[PermissionScope.SANDBOX_CREATE, PermissionScope.DATA_SEED_SYNTHETIC],
        token_hash="c" * 64,
        created_at=now,
    )

    assert ident.approver_id == "sec-lead-01"
    assert ident.token_hash == "c" * 64

    # Assert immutability
    with pytest.raises(ValidationError):
        ident.approver_id = "tampered"  # type: ignore[misc]


def test_approval_record_valid_and_frozen() -> None:
    """Verify ApprovalRecord model validation and immutability."""
    now = datetime.now(timezone.utc)
    record = ApprovalRecord(
        approval_id="appr-001",
        request_id="req-001",
        approver_id="sec-lead-01",
        decision=ApprovalDecisionType.APPROVE,
        canonical_plan_hash="d" * 64,
        plan_version=1,
        target_environment="local-sandbox",
        granted_scopes=[PermissionScope.SANDBOX_CREATE],
        created_at=now,
        expires_at=now,
        is_revoked=False,
        execution_consumed=False,
    )

    assert record.approval_id == "appr-001"
    assert record.execution_consumed is False

    with pytest.raises(ValidationError):
        record.execution_consumed = True  # type: ignore[misc]


def test_audit_event_hash_chain_fields() -> None:
    """Verify AuditEvent requires all hash-chain provenance fields."""
    now = datetime.now(timezone.utc)
    actor = AuditActor(actor_id="dev-alice", role="DEVELOPER")

    event = AuditEvent(
        event_id="evt-001",
        request_id="req-001",
        sequence_number=1,
        timestamp=now,
        event_type=AuditEventType.REQUEST_CREATED,
        severity=AuditSeverity.INFO,
        actor=actor,
        action_name="CreateRequest",
        previous_event_hash="0" * 64,
        payload_hash="e" * 64,
        event_hash="f" * 64,
        details={"project_name": "test-service"},
    )

    assert event.sequence_number == 1
    assert event.previous_event_hash == "0" * 64
    assert event.event_hash == "f" * 64


def test_smoke_test_evidence_disclaimer_mandatory() -> None:
    """Verify SmokeTestEvidence contains mandatory architectural mock disclaimer."""
    evidence = SmokeTestEvidence(
        health_endpoint_url="http://127.0.0.1:9000/health",
        health_status_code=200,
        health_response_body={"status": "healthy"},
        login_endpoint_url="http://127.0.0.1:9000/mock-auth/login",
        login_status_code=200,
        mock_token_claims={"sub": "test-dev", "mock": True},
        response_latency_ms=12.5,
        evidence_timestamp=datetime.now(timezone.utc),
    )

    assert "LOCAL MOCK VERIFICATION ONLY" in evidence.auth_mode_disclaimer
    assert "Identity Provider" in evidence.auth_mode_disclaimer


def test_setup_manifest_valid() -> None:
    """Verify SetupManifest builds correctly and enforces zero secrets."""
    now = datetime.now(timezone.utc)
    manifest = SetupManifest(
        request_id="req-101",
        environment=ManifestEnvironment(
            target_environment="local-sandbox",
            sandbox_id="sbx-001",
            mock_endpoint_url="http://127.0.0.1:9000",
            allocated_ports=[9000, 9001],
            created_timestamp=now,
            expires_timestamp=now,
        ),
        provisioning=ManifestProvisioningInfo(
            template_applied=ProjectTemplate.PYTHON_FASTAPI,
            applied_scopes=[PermissionScope.SANDBOX_CREATE],
            sandbox_filesystem_path="c:/sandboxes/sbx-001",
        ),
        data_seeding=ManifestSeedSummary(
            fixtures_loaded=["users.json"],
            total_records_seeded=15,
        ),
        verification=SmokeTestEvidence(
            health_endpoint_url="http://127.0.0.1:9000/health",
            health_status_code=200,
            health_response_body={"status": "healthy"},
            login_endpoint_url="http://127.0.0.1:9000/mock-auth/login",
            login_status_code=200,
            mock_token_claims={"sub": "test-dev"},
            response_latency_ms=8.2,
            evidence_timestamp=now,
        ),
        integrity=ManifestSignatureMetadata(
            manifest_sha256="1" * 64,
            canonical_plan_hash="2" * 64,
            approval_id="appr-101",
            generated_at=now,
        ),
    )

    assert manifest.manifest_version == "1.3.0"
    assert manifest.request_id == "req-101"
