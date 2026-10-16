# Data Contracts & Schemas Specification: Developer Sandbox Bootstrapper

**Document Version:** 1.3.0  
**Status:** PROPOSED FOR REVIEW (ARCHITECTURE PLANNING ONLY)  
**Date:** 2026-10-16  
**Schema Standard:** Pydantic v2.x / OpenAPI 3.1 / Genuine RFC 8785 (JCS)  

---

## 1. Overview & Data Flow Principles

This document defines the definitive data contracts, serialization formats, validation constraints, database schemas, and REST API payload definitions for the Developer Sandbox Bootstrapper.

The system enforces five strict data management invariants:
1. **Type Strictness & Immutability:** All domain entities are parsed through Pydantic v2 models with `extra="forbid"` and frozen attributes where tamper resistance is required.
2. **Genuine RFC 8785 Canonical Hashing:** Approval payloads are canonicalized using RFC 8785 (JSON Canonicalization Scheme) without custom Unicode normalization before generating a SHA-256 fingerprint.
3. **Server-Side Token Identity Resolution:** Client-supplied identity headers or body fields are structurally ignored. The server resolves caller identity strictly via hashed token lookup.
4. **Atomic CAS Approval Consumption:** Approvals are consumed atomically inside a `BEGIN IMMEDIATE` transaction bound to all 8 parameters, preventing concurrent double-execution.
5. **Multi-Layered Audit Integrity with Documented Assumptions:** Audit records are linked via a SHA-256 cryptographic hash chain and protected by application-level SQLite triggers, with external anchor specifications for high-assurance environments.

---

## 2. Core Domain Models & Pydantic v2 Specifications

### 2.1 Enums & Primitive Value Objects

```python
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict, field_validator
from datetime import datetime

class ProjectTemplate(str, Enum):
    PYTHON_FASTAPI = "python-fastapi-service"
    NODE_MICROSERVICE = "node-microservice"
    REACT_CLIENT = "react-client"
    DATA_PIPELINE = "data-pipeline"

class PermissionScope(str, Enum):
    SANDBOX_READ = "sandbox:read"
    SANDBOX_CREATE = "sandbox:create"
    DATA_SEED_SYNTHETIC = "data:seed:synthetic"
    TEST_EXECUTE = "test:execute"
    AUDIT_READ = "audit:read"

class StepActionType(str, Enum):
    """Closed allowlist of permitted execution actions. Arbitrary commands are strictly forbidden."""
    DISCOVER_REPOSITORY = "DISCOVER_REPOSITORY"
    DISCOVER_DASHBOARD = "DISCOVER_DASHBOARD"
    VALIDATE_DEPENDENCIES = "VALIDATE_DEPENDENCIES"
    PROVISION_MOCK_SANDBOX = "PROVISION_MOCK_SANDBOX"      # Privileged action
    SEED_SYNTHETIC_DATA = "SEED_SYNTHETIC_DATA"            # Privileged action
    EXECUTE_SMOKE_TEST = "EXECUTE_SMOKE_TEST"
    GENERATE_MANIFEST = "GENERATE_MANIFEST"

class WorkflowStatus(str, Enum):
    DRAFT = "DRAFT"
    DISCOVERY_IN_PROGRESS = "DISCOVERY_IN_PROGRESS"
    PLANNING = "PLANNING"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    PROVISIONING = "PROVISIONING"
    PROVISIONED = "PROVISIONED"
    SEEDING = "SEEDING"
    SEEDED = "SEEDED"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    PARTIALLY_FAILED = "PARTIALLY_FAILED"

class StepExecutionStatus(str, Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"

class ApprovalDecisionType(str, Enum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"

class AuditEventType(str, Enum):
    REQUEST_CREATED = "REQUEST_CREATED"
    DISCOVERY_COMPLETED = "DISCOVERY_COMPLETED"
    PLAN_GENERATED = "PLAN_GENERATED"
    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    APPROVAL_SUBMITTED = "APPROVAL_SUBMITTED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    PRE_ACTION_VERIFIED = "PRE_ACTION_VERIFIED"
    PRE_ACTION_FAILED = "PRE_ACTION_FAILED"
    STEP_STARTED = "STEP_STARTED"
    STEP_COMPLETED = "STEP_COMPLETED"
    STEP_FAILED = "STEP_FAILED"
    MANIFEST_GENERATED = "MANIFEST_GENERATED"
    SMOKE_TEST_VERIFIED = "SMOKE_TEST_VERIFIED"
    COMPENSATION_TRIGGERED = "COMPENSATION_TRIGGERED"
    WORKFLOW_TERMINATED = "WORKFLOW_TERMINATED"

class AuditSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    SECURITY = "SECURITY"
    CRITICAL = "CRITICAL"
```

---

### 2.2 Request & Discovery Schemas

```python
class BootstrapRequestCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    project_name: str = Field(..., min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$")
    template: ProjectTemplate
    repository_path: str = Field(..., min_length=1, max_length=512)
    requested_scopes: List[PermissionScope] = Field(..., min_items=1)
    developer_id: str = Field(..., min_length=2, max_length=64)
    target_environment: str = Field("local-sandbox", min_length=2, max_length=32)

    @field_validator("requested_scopes")
    @classmethod
    def ensure_unique_scopes(cls, v: List[PermissionScope]) -> List[PermissionScope]:
        if len(v) != len(set(v)):
            raise ValueError("Duplicate permission scopes requested.")
        return sorted(v, key=lambda s: s.value)

class BootstrapRequestResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str
    status: WorkflowStatus
    project_name: str
    template: ProjectTemplate
    requested_scopes: List[PermissionScope]
    developer_id: str
    target_environment: str
    created_at: datetime
    updated_at: datetime

class RepoDiscoveryResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repository_path: str
    detected_framework: str
    config_files_found: List[str]
    inferred_dependencies: List[str]
    untrusted_documentation_snippet: Optional[str] = None
    discovery_timestamp: datetime

class DashboardDiscoveryResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    quota_available_sandboxes: int
    existing_sandboxes_count: int
    allowed_synthetic_fixtures: List[str]
    mock_network_range: str
```

---

### 2.3 Planning & DAG Schemas

```python
class PlannedStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    step_id: str = Field(..., pattern=r"^step-[0-9a-f]{8}$")
    action_type: StepActionType
    name: str = Field(..., max_length=128)
    description: str = Field(..., max_length=256)
    is_privileged: bool
    required_scopes: List[PermissionScope]
    depends_on_step_ids: List[str] = Field(default_factory=list)
    action_parameters: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("action_parameters")
    @classmethod
    def reject_code_snippets(cls, params: Dict[str, Any]) -> Dict[str, Any]:
        forbidden_keys = {"shell_cmd", "bash", "exec", "eval", "python_code", "cmd", "powershell"}
        if any(k.lower() in forbidden_keys for k in params.keys()):
            raise ValueError("Dangerous action parameter detected in planned step.")
        return params

class SetupPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: str
    request_id: str
    plan_version: int = 1
    target_environment: str
    steps: List[PlannedStep]
    estimated_duration_seconds: int
    created_at: datetime
    canonical_plan_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
```

---

### 2.4 Genuine RFC 8785 Canonical Hashing Specification

Canonicalization conforms strictly to **RFC 8785 (JSON Canonicalization Scheme - JCS)**.

```python
class CanonicalApprovalPayload(BaseModel):
    """
    The exact canonical structure serialized and hashed for human sign-off.
    Must be serialized using an established RFC 8785 package (e.g., rfc8785 or canonicaljson).
    Custom serializers are prohibited.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    target_environment: str
    plan_version: int = 1
    granted_scopes: List[str]
    planned_actions: List[Dict[str, Any]]
    synthetic_fixtures: List[str]

    @field_validator("granted_scopes", "synthetic_fixtures")
    @classmethod
    def sort_lists(cls, v: List[str]) -> List[str]:
        return sorted(v)
```

#### RFC 8785 JCS Rules:
1. **Unicode Handling (RFC 8785 Section 3.2.2):**
   - Strings are serialized as UTF-8 without BOM.
   - **No Character Normalization:** RFC 8785 explicitly states that Unicode characters are **not normalized** (no NFC or NFD transforms). Code points must remain exactly as input.
   - **Escaping:** Only quotation mark `\"`, reverse solidus `\\`, and C0 control characters (`\u0000` through `\u001f`) are escaped. All other Unicode characters are output as raw UTF-8 bytes.
2. **Key Ordering (RFC 8785 Section 3.2.3):**
   - Object keys are sorted lexicographically by UTF-16 code units.
3. **Number Representation (RFC 8785 Section 3.2.2.3):**
   - Integers in range $[-2^{53}+1, 2^{53}-1]$ format without decimal point or exponent.
   - Floats use shortest-round-trip representation; trailing zeros omitted; positive exponents format without `+`.
4. **Whitespace:** Zero whitespace outside string literals.
5. **Absent Fields:** Optional fields with `None` value are omitted rather than serialized as `null`.

---

### 2.5 Approver Token, Server-Side Identity & Approval Models

```python
class ApproverIdentity(BaseModel):
    """Server-side record mapping a hashed token to a verified approver identity."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    approver_id: str
    role: str
    authorized_scopes: List[PermissionScope]
    token_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    revoked_at: Optional[datetime] = None

class ApprovalRequest(BaseModel):
    """
    Submitted by client to approve/reject a plan.
    Notice: NO approver_id field exists here. Identity is strictly derived
    by the server from the Authorization / X-Approver-Token header.
    """
    model_config = ConfigDict(extra="forbid")

    request_id: str
    decision: ApprovalDecisionType
    submitted_plan_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    plan_version: int = 1
    rejection_reason: Optional[str] = None

class ApprovalRecord(BaseModel):
    """Server-side authenticated database record. The only source of approval truth."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: str
    request_id: str
    approver_id: str = Field(..., description="Established exclusively by server via token resolution")
    decision: ApprovalDecisionType
    canonical_plan_hash: str
    plan_version: int
    target_environment: str
    granted_scopes: List[PermissionScope]
    created_at: datetime
    expires_at: datetime
    is_revoked: bool = False
    execution_consumed: bool = False
    consumed_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None

class AuthGuardEvaluationContext(BaseModel):
    """The 8 parameters revalidated by ServerSideAuthGuard inside adapters."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: str
    request_id: str
    action_type: StepActionType
    target_environment: str
    required_scope: PermissionScope
    active_plan_hash: str
    active_plan_version: int
    current_status: WorkflowStatus
    current_time: datetime
```

---

### 2.6 Retention, Resource Ownership & Workflow State

```python
class SandboxRetentionConfig(BaseModel):
    """Configuration governing sandbox lifecycle, disk quotas, and retention."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    active_sandbox_ttl_hours: int = Field(24, description="Owner-selected active sandbox TTL")
    failure_quarantine_hours: int = Field(1, description="Quarantine window for failed sandboxes before cleanup")
    max_concurrent_sandboxes: int = Field(5, description="Maximum simultaneous active sandboxes")
    max_total_storage_bytes: int = Field(10 * 1024 * 1024 * 1024, description="10GB disk limit")

class ResourceOwnershipMetadata(BaseModel):
    """Tracked in SQLite to ensure compensation never deletes unverified resources."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_id: str
    request_id: str
    resource_type: str = "SANDBOX_DIRECTORY"
    filesystem_path: str
    ownership_token: str = Field(..., description="Unique UUID written to .sandbox-metadata.json")
    created_at: datetime
    expires_at: datetime
    is_quarantined: bool = False

class StepExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step_id: str
    action_type: StepActionType
    status: StepExecutionStatus
    retry_count: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    output_summary: Dict[str, Any] = Field(default_factory=dict)

class WorkflowState(BaseModel):
    """State dictionary maintained by LangGraph checkpointing."""
    model_config = ConfigDict(extra="forbid")

    request_id: str
    current_status: WorkflowStatus
    plan: Optional[SetupPlan] = None
    approval: Optional[ApprovalRecord] = None
    step_results: Dict[str, StepExecutionResult] = Field(default_factory=dict)
    tracked_resources: List[ResourceOwnershipMetadata] = Field(default_factory=list)
    active_step_id: Optional[str] = None
    compensation_required: bool = False
    sandbox_id: Optional[str] = None
    manifest_id: Optional[str] = None
    last_error: Optional[str] = None
    iteration_counter: int = 0
```

---

### 2.7 Hash-Chained Audit Event Schema

```python
class AuditActor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    actor_id: str
    role: str
    ip_address: str = "127.0.0.1"

class AuditEvent(BaseModel):
    """Cryptographically hash-chained audit record."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str
    request_id: str
    sequence_number: int
    timestamp: datetime
    event_type: AuditEventType
    severity: AuditSeverity
    actor: AuditActor
    action_name: str
    state_before: Optional[WorkflowStatus] = None
    state_after: Optional[WorkflowStatus] = None
    previous_event_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    payload_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    event_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    details: Dict[str, Any] = Field(default_factory=dict)
```

---

### 2.8 Smoke Test Evidence & Setup Manifest Schemas

```python
class SmokeTestEvidence(BaseModel):
    """Concrete evidence collected during local mock smoke-login execution."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    health_endpoint_url: str
    health_status_code: int
    health_response_body: Dict[str, Any]
    login_endpoint_url: str
    login_status_code: int
    mock_token_claims: Dict[str, Any]
    response_latency_ms: float
    evidence_timestamp: datetime
    auth_mode_disclaimer: str = (
        "LOCAL MOCK VERIFICATION ONLY: This authentication check validates internal "
        "sandbox readiness using simulated credentials and does NOT authenticate against "
        "an enterprise Identity Provider (OAuth2/SAML/OIDC)."
    )

class ManifestEnvironment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    target_environment: str
    sandbox_id: str
    mock_endpoint_url: str
    allocated_ports: List[int]
    created_timestamp: datetime
    expires_timestamp: datetime

class ManifestProvisioningInfo(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    template_applied: ProjectTemplate
    applied_scopes: List[PermissionScope]
    sandbox_filesystem_path: str

class ManifestSeedSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    fixtures_loaded: List[str]
    total_records_seeded: int
    generation_mode: str = "DETERMINISTIC_SYNTHETIC_GENERATOR"
    pii_scan_status: str = "PASSED_DEFENSE_IN_DEPTH_SCAN"

class ManifestSignatureMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    manifest_sha256: str
    canonical_plan_hash: str
    approval_id: str
    generated_at: datetime
    generator_version: str = "1.3.0"

class SetupManifest(BaseModel):
    """The canonical, finalized setup manifest saved to disk (strictly 0 secrets)."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest_version: str = "1.3.0"
    request_id: str
    environment: ManifestEnvironment
    provisioning: ManifestProvisioningInfo
    data_seeding: ManifestSeedSummary
    verification: SmokeTestEvidence
    integrity: ManifestSignatureMetadata
```

---

## 3. SQLite Database Schema (DDL)

```sql
-- SQLite Configuration for Windows Concurrency
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

-- 1. Approver Tokens (Stored Hashed at Rest)
CREATE TABLE IF NOT EXISTS approver_tokens (
    token_hash TEXT PRIMARY KEY,
    approver_id TEXT NOT NULL,
    role TEXT NOT NULL,
    authorized_scopes TEXT NOT NULL, -- JSON array
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

-- 2. Bootstrap Requests
CREATE TABLE IF NOT EXISTS bootstrap_requests (
    request_id TEXT PRIMARY KEY,
    idempotency_key TEXT UNIQUE NOT NULL,
    project_name TEXT NOT NULL,
    template TEXT NOT NULL,
    repository_path TEXT NOT NULL,
    requested_scopes TEXT NOT NULL,
    developer_id TEXT NOT NULL,
    target_environment TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_requests_status ON bootstrap_requests(status);
CREATE INDEX IF NOT EXISTS idx_requests_idempotency ON bootstrap_requests(idempotency_key);

-- 3. Setup Plans
CREATE TABLE IF NOT EXISTS setup_plans (
    plan_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    plan_version INTEGER NOT NULL DEFAULT 1,
    target_environment TEXT NOT NULL,
    canonical_plan_hash TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (request_id) REFERENCES bootstrap_requests(request_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_plans_request ON setup_plans(request_id);
CREATE INDEX IF NOT EXISTS idx_plans_hash ON setup_plans(canonical_plan_hash);

-- Automated Invalidation Trigger: Plan or scope change immediately revokes prior approvals
CREATE TRIGGER IF NOT EXISTS revoke_approvals_on_plan_change
AFTER UPDATE ON setup_plans
BEGIN
    UPDATE approval_records 
    SET is_revoked = 1,
        rejection_reason = 'AUTOMATICALLY_REVOKED: Plan altered post-approval'
    WHERE request_id = NEW.request_id AND execution_consumed = 0;
END;

-- 4. Approval Records (Server-Side Authenticated Source of Truth)
CREATE TABLE IF NOT EXISTS approval_records (
    approval_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    approver_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('APPROVE', 'REJECT')),
    canonical_plan_hash TEXT NOT NULL,
    plan_version INTEGER NOT NULL DEFAULT 1,
    target_environment TEXT NOT NULL,
    granted_scopes TEXT NOT NULL, -- JSON array
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    rejection_reason TEXT,
    is_revoked INTEGER NOT NULL DEFAULT 0 CHECK(is_revoked IN (0, 1)),
    execution_consumed INTEGER NOT NULL DEFAULT 0 CHECK(execution_consumed IN (0, 1)),
    consumed_at TEXT,
    FOREIGN KEY (request_id) REFERENCES bootstrap_requests(request_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_approvals_request ON approval_records(request_id);
CREATE INDEX IF NOT EXISTS idx_approvals_hash ON approval_records(canonical_plan_hash);

-- 5. Resource Ownership (Safe Compensation & Retention)
CREATE TABLE IF NOT EXISTS tracked_resources (
    resource_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    filesystem_path TEXT NOT NULL,
    ownership_token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    is_quarantined INTEGER NOT NULL DEFAULT 0 CHECK(is_quarantined IN (0, 1)),
    FOREIGN KEY (request_id) REFERENCES bootstrap_requests(request_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_resources_request ON tracked_resources(request_id);
CREATE INDEX IF NOT EXISTS idx_resources_expires ON tracked_resources(expires_at);

-- 6. Workflow Checkpoints (LangGraph State)
CREATE TABLE IF NOT EXISTS workflow_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    current_status TEXT NOT NULL,
    state_payload TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (request_id) REFERENCES bootstrap_requests(request_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_checkpoints_request ON workflow_checkpoints(request_id);

-- 7. Step Executions
CREATE TABLE IF NOT EXISTS step_executions (
    execution_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    status TEXT NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    started_at TEXT,
    completed_at TEXT,
    error_message TEXT,
    output_summary TEXT,
    FOREIGN KEY (request_id) REFERENCES bootstrap_requests(request_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_steps_request ON step_executions(request_id);

-- 8. Hash-Chained Audit Log
CREATE TABLE IF NOT EXISTS audit_log (
    event_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    sequence_number INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    action_name TEXT NOT NULL,
    state_before TEXT,
    state_after TEXT,
    previous_event_hash TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    details TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_seq ON audit_log(sequence_number);
CREATE INDEX IF NOT EXISTS idx_audit_request ON audit_log(request_id);

-- Application-Level Triggers Blocking Audit Alteration
CREATE TRIGGER IF NOT EXISTS prevent_audit_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(FAIL, 'SECURITY VIOLATION: Updates to audit_log table are forbidden.');
END;

CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(FAIL, 'SECURITY VIOLATION: Deletions from audit_log table are forbidden.');
END;
```

---

## 4. REST API Contracts & Endpoints

### 4.1 Error Response Envelope (RFC 7807)
```json
{
  "type": "https://api.sandbox-bootstrapper.local/errors/plan-drift",
  "title": "Approval Rejected: Plan Drift Detected",
  "status": 409,
  "detail": "Submitted plan hash does not match stored canonical hash.",
  "instance": "/api/v1/bootstrap/requests/req-87a19c/approvals",
  "error_code": "ERR_PLAN_DRIFT_DETECTED",
  "timestamp": "2026-10-16T11:05:00Z"
}
```

### 4.2 Endpoint Catalog

| Endpoint | Method | Input Payload | Output Payload | Security Gate |
| :--- | :--- | :--- | :--- | :--- |
| `/api/v1/bootstrap/requests` | `POST` | `BootstrapRequestCreate` (Header: `Idempotency-Key`) | `BootstrapRequestResponse` (201 Created) | Unique idempotency validation. |
| `/api/v1/bootstrap/requests/{id}` | `GET` | None | `BootstrapRequestResponse` (200 OK) | Read-only. |
| `/api/v1/bootstrap/requests/{id}/plan` | `GET` | None | `SetupPlan` (200 OK) | Read-only. |
| `/api/v1/bootstrap/requests/{id}/approvals` | `POST` | `ApprovalRequest` (Header: `Authorization: Bearer <token>`) | `ApprovalRecord` (200 OK) | Server-side token resolution, hash match, TTL check. |
| `/api/v1/bootstrap/requests/{id}/execute` | `POST` | None (Atomic resume trigger) | `{"status": "PROVISIONING"}` (202 Accepted) | State transition gate (`APPROVED`). Atomic CAS 8-parameter single-use consumption. |
| `/api/v1/bootstrap/requests/{id}/manifest` | `GET` | None | `SetupManifest` (200 OK) | Zero secrets verified. |
| `/api/v1/bootstrap/requests/{id}/audit` | `GET` | Query: `?verify_chain=true` | `List[AuditEvent]` + `{"chain_valid": bool}` | Hash chain verification. |
