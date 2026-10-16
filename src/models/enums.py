"""Domain enumeration types for Developer Sandbox Bootstrapper."""

from enum import Enum


class ProjectTemplate(str, Enum):
    """Supported project starter templates."""
    PYTHON_FASTAPI = "python-fastapi-service"
    NODE_MICROSERVICE = "node-microservice"
    REACT_CLIENT = "react-client"
    DATA_PIPELINE = "data-pipeline"


class PermissionScope(str, Enum):
    """Least-privilege permission scopes."""
    SANDBOX_READ = "sandbox:read"
    SANDBOX_CREATE = "sandbox:create"
    SANDBOX_DELETE = "sandbox:delete"
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
    CLEANUP_MOCK_SANDBOX = "CLEANUP_MOCK_SANDBOX"          # Privileged action


class WorkflowStatus(str, Enum):
    """Finite lifecycle states of a bootstrap request."""
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


class WorkflowStage(str, Enum):
    """Named orchestration stages of the bootstrapper workflow."""
    COLLECT_REQUEST = "COLLECT_REQUEST"
    DISCOVER = "DISCOVER"
    BUILD_PLAN = "BUILD_PLAN"
    VALIDATE_PLAN = "VALIDATE_PLAN"
    GENERATE_MANIFEST = "GENERATE_MANIFEST"
    AWAIT_APPROVAL = "AWAIT_APPROVAL"
    PROVISION_MOCK_SANDBOX = "PROVISION_MOCK_SANDBOX"
    SEED_SYNTHETIC_DATA = "SEED_SYNTHETIC_DATA"
    VERIFY_SANDBOX = "VERIFY_SANDBOX"
    FINALIZE = "FINALIZE"


class StepExecutionStatus(str, Enum):
    """Execution status of an individual planned step."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"



class ApprovalDecisionType(str, Enum):
    """Human approval decisions."""
    APPROVE = "APPROVE"
    REJECT = "REJECT"


class AuditEventType(str, Enum):
    """Auditable state transition and lifecycle event types."""
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
    """Severity levels for audit events."""
    INFO = "INFO"
    WARNING = "WARNING"
    SECURITY = "SECURITY"
    CRITICAL = "CRITICAL"
