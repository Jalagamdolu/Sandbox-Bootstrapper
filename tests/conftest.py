"""Pytest fixtures for Developer Sandbox Bootstrapper Phase 1 and Phase 2 tests."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Generator

import pytest

from src.security.approvals import ApprovalService
from src.security.audit_chain import AuditChainService
from src.security.guard import ServerSideAuthGuard
from src.security.tokens import TokenService
from src.storage.connection import get_connection
from src.storage.db_init import initialize_database


@pytest.fixture
def isolated_db_path(tmp_path: Path) -> Path:
    """Provide an isolated, temporary SQLite database path for testing."""
    return tmp_path / "test_sandbox_bootstrapper.db"


@pytest.fixture
def initialized_db_path(isolated_db_path: Path) -> Path:
    """Provide an isolated, fully initialized SQLite database path for service testing."""
    initialize_database(isolated_db_path)
    return isolated_db_path


@pytest.fixture
def initialized_db(initialized_db_path: Path) -> Generator[sqlite3.Connection, None, None]:
    """Provide a connection to a fully initialized, temporary SQLite database."""
    conn = get_connection(initialized_db_path)
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def clean_env() -> Generator[dict[str, str], None, None]:
    """Provide an environment where modified environment variables are restored."""
    old_env = os.environ.copy()
    try:
        yield os.environ
    finally:
        os.environ.clear()
        os.environ.update(old_env)


@pytest.fixture
def token_service() -> TokenService:
    """Provide a TokenService instance."""
    return TokenService()


@pytest.fixture
def approval_service() -> ApprovalService:
    """Provide an ApprovalService instance."""
    return ApprovalService()


@pytest.fixture
def auth_guard(token_service: TokenService) -> ServerSideAuthGuard:
    """Provide a ServerSideAuthGuard instance."""
    return ServerSideAuthGuard(token_service=token_service)


@pytest.fixture
def audit_service() -> AuditChainService:
    """Provide an AuditChainService instance."""
    return AuditChainService()


@pytest.fixture
def execution_tracker() -> StepExecutionTracker:
    """Provide a StepExecutionTracker instance."""
    from src.adapters.execution_tracker import StepExecutionTracker
    return StepExecutionTracker()


@pytest.fixture
def mock_sandbox_root(tmp_path: Path) -> Path:
    """Provide an isolated sandbox storage root directory."""
    sbx_root = tmp_path / "sandboxes"
    sbx_root.mkdir(parents=True, exist_ok=True)
    return sbx_root


@pytest.fixture
def sandbox_provisioner(
    auth_guard: ServerSideAuthGuard,
    approval_service: ApprovalService,
    execution_tracker: StepExecutionTracker,
    audit_service: AuditChainService,
) -> MockSandboxProvisioner:
    """Provide a MockSandboxProvisioner instance."""
    from src.adapters.sandbox_provisioner import MockSandboxProvisioner
    return MockSandboxProvisioner(
        auth_guard=auth_guard,
        approval_service=approval_service,
        execution_tracker=execution_tracker,
        audit_service=audit_service,
    )


@pytest.fixture
def data_seeder(
    auth_guard: ServerSideAuthGuard,
    approval_service: ApprovalService,
    execution_tracker: StepExecutionTracker,
    audit_service: AuditChainService,
) -> SyntheticDataSeeder:
    """Provide a SyntheticDataSeeder instance."""
    from src.adapters.data_seeder import SyntheticDataSeeder
    return SyntheticDataSeeder(
        auth_guard=auth_guard,
        approval_service=approval_service,
        execution_tracker=execution_tracker,
        audit_service=audit_service,
    )

