"""Integration and unit tests for Streamlit UI logic."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from src.core.config import get_settings
from src.models.enums import ApprovalDecisionType, PermissionScope, ProjectTemplate, WorkflowStatus
from src.models.requests import BootstrapRequestCreate
from src.storage.db_init import initialize_database
from src.ui.app import get_services


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolate SQLite database and sandbox directory for each test."""
    db_file = tmp_path / "test_ui.db"
    sbx_dir = tmp_path / "sandboxes"
    sbx_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("DATABASE_PATH", str(db_file))
    monkeypatch.setenv("SANDBOX_STORAGE_DIR", str(sbx_dir))

    get_settings(reload=True)
    initialize_database(db_file)
    yield
    get_settings(reload=True)


def test_ui_services_wiring():
    """Verify get_services returns correctly configured service instances."""
    orchestrator, approval_svc, token_svc, audit_svc = get_services()
    assert orchestrator is not None
    assert approval_svc is not None
    assert token_svc is not None
    assert audit_svc is not None
    assert orchestrator.approval_service is approval_svc
    assert orchestrator.audit_service is audit_svc


def test_ui_end_to_end_flow(tmp_path: Path):
    """Test full flow through the services as consumed by UI tabs."""
    orchestrator, approval_svc, token_svc, audit_svc = get_services()

    # 1. Create request (Tab 1)
    req_in = BootstrapRequestCreate(
        project_name="ui-service",
        template=ProjectTemplate.PYTHON_FASTAPI,
        repository_path="./",
        developer_id="dev-ui",
        target_environment="local-mock-dev",
        requested_scopes=[
            PermissionScope.SANDBOX_READ,
            PermissionScope.SANDBOX_CREATE,
            PermissionScope.DATA_SEED_SYNTHETIC,
            PermissionScope.TEST_EXECUTE,
            PermissionScope.AUDIT_READ,
        ],
    )
    req = orchestrator.create_request(req_in)
    assert req.request_id.startswith("req-")

    # 2. Inspect plan (Tab 2)
    plan = orchestrator._get_or_create_plan(req)
    assert plan.canonical_plan_hash
    assert len(plan.steps) == 7

    # 3. Unapproved execution pauses at AWAIT_APPROVAL (Tab 4)
    run1 = orchestrator.run_workflow(req.request_id, raise_on_failure=False)
    assert run1.approval_required is True
    assert run1.current_status == WorkflowStatus.PENDING_APPROVAL

    # 4. Issue token and approve plan (Tab 3)
    token_res = token_svc.create_token(
        approver_id="sec-lead-ui",
        role="SECURITY_LEAD",
        authorized_scopes=[
            PermissionScope.SANDBOX_READ,
            PermissionScope.SANDBOX_CREATE,
            PermissionScope.DATA_SEED_SYNTHETIC,
            PermissionScope.TEST_EXECUTE,
            PermissionScope.AUDIT_READ,
        ],
    )
    identity = token_svc.resolve_identity(token_res.raw_token)
    assert identity.approver_id == "sec-lead-ui"

    from src.models.approvals import ApprovalRequest
    appr_req = ApprovalRequest(
        request_id=req.request_id,
        submitted_plan_hash=plan.canonical_plan_hash,
        plan_version=plan.plan_version,
        decision=ApprovalDecisionType.APPROVE,
    )
    appr_record = approval_svc.create_approval(
        request=appr_req,
        approver=identity,
        target_environment=plan.target_environment,
        granted_scopes=req.requested_scopes,
    )
    assert appr_record.decision == ApprovalDecisionType.APPROVE

    # 5. Resume execution to completion (Tab 4)
    run2 = orchestrator.run_workflow(req.request_id, caller_token=token_res.raw_token, raise_on_failure=False)
    assert run2.is_completed is True
    assert run2.current_status == WorkflowStatus.COMPLETED

    # 6. Verify manifest generation (Tab 5)
    settings = get_settings()
    sandbox_root = Path(settings.sandbox_storage_dir)
    tracked = orchestrator._find_tracked_sandbox(req.request_id, sandbox_root)
    assert tracked is not None
    manifest_file = tracked.sandbox_dir / "manifest.json"
    assert manifest_file.exists()

    # 7. Audit log verification (Tab 6)
    report = audit_svc.verify_chain()
    assert report.is_valid is True
    assert report.events_inspected >= 5


def test_ui_components_rendering(monkeypatch: pytest.MonkeyPatch):
    """Verify header, page config, and tab components execute cleanly."""
    from unittest.mock import MagicMock, patch
    import streamlit as st
    from src.ui.app import (
        init_page_config,
        render_header,
        tab_create_request,
        tab_discovery_and_plan,
        tab_approvals,
        tab_execution,
        tab_manifest_and_verification,
        tab_audit_and_cleanup,
    )

    with patch.object(st, "set_page_config") as mock_cfg:
        init_page_config()
        mock_cfg.assert_called_once()

    with patch.object(st, "error") as mock_err, patch.object(st, "title") as mock_title:
        render_header()
        mock_err.assert_called_once()
        mock_title.assert_called_once()

    orchestrator, approval_svc, token_svc, audit_svc = get_services()

    # Create real token
    tok = token_svc.create_token(
        "sec-lead-ui2", "SECURITY_LEAD",
        [PermissionScope.SANDBOX_READ, PermissionScope.SANDBOX_CREATE, PermissionScope.DATA_SEED_SYNTHETIC, PermissionScope.TEST_EXECUTE, PermissionScope.AUDIT_READ, PermissionScope.SANDBOX_DELETE]
    )

    req_id = ""

    def mock_input(label, value="", **kwargs):
        nonlocal req_id
        if "Request ID" in label:
            return req_id or "req-default"
        if "Approver ID" in label:
            return "sec-lead-ui2"
        if "Token" in label:
            return tok.raw_token
        if "Project Name" in label:
            return "test-ui-proj"
        if "Repository Path" in label:
            return "./"
        if "Developer ID" in label:
            return "dev-test"
        if "Target Environment" in label:
            return "local-mock-dev"
        return value or "val"

    # 1. Create request tab
    with patch.object(st, "form_submit_button", return_value=True), \
         patch.object(st, "text_input", side_effect=mock_input), \
         patch.object(st, "selectbox", return_value="python-fastapi-service"), \
         patch.object(st, "multiselect", return_value=["sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"]), \
         patch.object(st, "success") as mock_suc:
        tab_create_request(orchestrator)
        assert mock_suc.called

    req_id = st.session_state.get("selected_request_id", "")
    assert req_id != ""

    # 2. Plan and discovery tab
    with patch.object(st, "text_input", side_effect=mock_input), \
         patch.object(st, "table") as mock_table, \
         patch.object(st, "json") as mock_json:
        tab_discovery_and_plan(orchestrator)
        assert mock_table.called

    # 3. Approvals tab
    # Token generation sub-action
    with patch.object(st, "button", return_value=True), \
         patch.object(st, "text_input", side_effect=mock_input), \
         patch.object(st, "selectbox", return_value="SECURITY_LEAD"), \
         patch.object(st, "multiselect", return_value=["sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read", "sandbox:delete"]), \
         patch.object(st, "form_submit_button", return_value=False):
        tab_approvals(orchestrator, approval_svc, token_svc)

    # Approval submission sub-action
    with patch.object(st, "button", return_value=False), \
         patch.object(st, "text_input", side_effect=mock_input), \
         patch.object(st, "radio", return_value="APPROVE"), \
         patch.object(st, "form_submit_button", return_value=True), \
         patch.object(st, "rerun"):
        tab_approvals(orchestrator, approval_svc, token_svc)

    # 4. Execution tab
    with patch.object(st, "text_input", side_effect=mock_input), \
         patch.object(st, "button", return_value=True), \
         patch.object(st, "success") as mock_exec_suc:
        tab_execution(orchestrator)
        assert mock_exec_suc.called

    # 5. Manifest tab
    with patch.object(st, "text_input", side_effect=mock_input), \
         patch.object(st, "json") as mock_mani_json:
        tab_manifest_and_verification(orchestrator)
        assert mock_mani_json.called

    # 6. Audit & Cleanup tab
    with patch.object(st, "text_input", side_effect=mock_input), \
         patch.object(st, "form_submit_button", return_value=False), \
         patch.object(st, "success") as mock_aud_suc:
        tab_audit_and_cleanup(orchestrator, audit_svc, token_svc)
        assert mock_aud_suc.called
