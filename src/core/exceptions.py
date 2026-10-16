"""Domain and system exceptions for Developer Sandbox Bootstrapper."""


class BootstrapError(Exception):
    """Base exception for all Developer Sandbox Bootstrapper errors."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ConfigurationError(BootstrapError):
    """Raised when application configuration is missing or invalid."""


class DatabaseError(BootstrapError):
    """Raised when a database operation fails."""


class DatabaseIntegrityError(DatabaseError):
    """Raised when a database constraint or immutability rule is violated."""


class SecurityViolationError(BootstrapError):
    """Raised when an unauthorized or potentially hostile action is attempted."""


class ModelValidationError(BootstrapError):
    """Raised when domain data contract validation fails."""


class ResourceOwnershipError(BootstrapError):
    """Raised when resource ownership cannot be verified before compensation."""


class PlanTamperingError(SecurityViolationError):
    """Raised when plan hash or parameters have drifted post-approval."""


class CanonicalizationError(BootstrapError):
    """Raised when canonical serialization of a payload fails or payload contains unsupported values."""


class TokenError(SecurityViolationError):
    """Base exception for approver token authentication errors."""


class TokenNotFoundError(TokenError):
    """Raised when an approver token hash is not found in the database."""


class TokenRevokedError(TokenError):
    """Raised when an approver token has been revoked."""


class TokenScopeError(SecurityViolationError):
    """Raised when an approver lacks authorization for the requested scopes."""


class ApprovalError(SecurityViolationError):
    """Base exception for approval verification and consumption errors."""


class ApprovalNotFoundError(ApprovalError):
    """Raised when an approval record is not found."""


class ApprovalExpiredError(ApprovalError):
    """Raised when an approval record has passed its TTL."""


class ApprovalRevokedError(ApprovalError):
    """Raised when an approval record has been marked as revoked."""


class ApprovalAlreadyConsumedError(ApprovalError):
    """Raised when an approval record has already been consumed (replay prevention)."""


class ApprovalMismatchError(ApprovalError):
    """Raised when an approval record does not match the requested plan, version, environment, or scope."""


class ApprovalRejectedError(ApprovalError):
    """Raised when an approval decision is REJECT."""


class RequestValidationError(ModelValidationError):
    """Raised when incoming intake request validation fails."""


class AuthorizationDeniedError(SecurityViolationError):
    """Raised by ServerSideAuthGuard when a privileged action is denied (fails closed)."""


class AuditChainIntegrityError(SecurityViolationError):
    """Raised when audit log hash-chain verification detects tampering, corruption, or missing events."""


class PathTraversalError(SecurityViolationError):
    """Raised when an operation attempts directory traversal or escaping the sandbox root."""


class SandboxProvisioningError(BootstrapError):
    """Raised when sandbox provisioning fails."""


class SyntheticDataSeedingError(BootstrapError):
    """Raised when synthetic data seeding fails."""


class UnknownFixtureError(SecurityViolationError):
    """Raised when an unregistered or non-allowlisted fixture ID is requested."""


class ExecutionConflictError(SecurityViolationError):
    """Raised when conflicting execution IDs, mismatched plan hashes, or concurrent runs collide."""


class StepExecutionError(BootstrapError):
    """Raised when a planned step fails execution."""


class SandboxVerificationError(BootstrapError):
    """Raised when post-provisioning/seeding sandbox verification fails."""


class PlanValidationError(SecurityViolationError):
    """Raised when setup plan structure, action allowlist, or permission scopes fail validation."""


class WorkflowError(BootstrapError):
    """Base exception for workflow orchestration and state transition errors."""


class WorkflowExecutionError(WorkflowError):
    """Raised when an unrecoverable failure occurs during workflow execution."""


class WorkflowInterruptedError(WorkflowError):
    """Raised when workflow pauses or is interrupted awaiting human approval."""


class PolicyViolationError(SecurityViolationError):
    """Raised when an operation violates security policy or action allowlists."""


class ResourceNotFoundError(BootstrapError):
    """Raised when a requested local or mock resource cannot be found."""

