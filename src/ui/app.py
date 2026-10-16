"""Streamlit UI for Developer Sandbox Bootstrapper.

Production-quality enterprise developer console.
100% local, zero cloud infrastructure, strictly simulated mock environment.
Provides human-in-the-loop review, gated approval controls, and full audit visibility.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure repository root is on sys.path so 'src' packages resolve regardless of
# execution context (e.g. Streamlit Community Cloud launching from 'src/ui/app.py').
_repo_root = Path(__file__).resolve().parent.parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

import streamlit as st

from src.agents.discovery import DiscoveryAgent
from src.core.config import get_settings
from src.storage.db_init import initialize_database
from src.core.exceptions import (
    ApprovalError,
    BootstrapError,
    SecurityViolationError,
    TokenError,
    TokenScopeError,
    WorkflowError,
)
from src.models.approvals import ApprovalDecisionType, ApprovalRecord, ApprovalRequest
from src.models.enums import AuditEventType, PermissionScope, ProjectTemplate, WorkflowStatus
from src.models.requests import BootstrapRequestCreate
from src.security.approvals import ApprovalService
from src.security.audit_chain import AuditChainService
from src.security.tokens import TokenService
from src.storage.connection import get_connection
from src.workflow.discovery import discover_local_repository, discover_mock_dashboard
from src.workflow.orchestrator import WorkflowOrchestrator


# =============================================================================
# Custom CSS & Page Configuration
# =============================================================================


def init_page_config() -> None:
    st.set_page_config(
        page_title="Developer Sandbox Bootstrapper",
        page_icon="terminal",
        layout="wide",
        initial_sidebar_state="expanded",
    )


def inject_custom_css() -> None:
    """Inject restrained Linear/Vercel-inspired CSS design system."""
    css = """
    <style>
    /* Reset & Typography */
    html, body, [class*="css"] {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }
    
    .stApp {
        background-color: #F8FAFC !important;
    }

    /* Main Content Container: centered, bounded to 1240px to eliminate giant empty space */
    .block-container {
        padding-top: 2rem !important;
        padding-bottom: 3.5rem !important;
        padding-left: 2.5rem !important;
        padding-right: 2.5rem !important;
        max-width: 1240px !important;
        margin: 0 auto !important;
    }

    /* Streamlit Chrome Minimization */
    header[data-testid="stHeader"] {
        background: transparent !important;
        height: 1.5rem !important;
    }
    #MainMenu, footer {
        visibility: hidden !important;
    }

    /* Dark Sidebar */
    [data-testid="stSidebar"] {
        background-color: #111827 !important;
        border-right: 1px solid #1F2937 !important;
    }
    [data-testid="stSidebar"] * {
        color: #9CA3AF !important;
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] label {
        color: #D1D5DB !important;
        font-size: 0.875rem !important;
        font-weight: 500 !important;
        padding: 0.45rem 0.65rem !important;
        border-radius: 6px !important;
        margin-bottom: 0.2rem !important;
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] label:hover {
        background-color: #1F2937 !important;
        color: #FFFFFF !important;
    }

    /* Page Header */
    .page-header {
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        padding-bottom: 1.25rem;
        margin-bottom: 1.5rem;
        border-bottom: 1px solid #E2E8F0;
    }
    .page-title {
        font-size: 1.5rem;
        font-weight: 700;
        color: #0F172A;
        margin: 0;
        line-height: 1.2;
    }
    .page-subtitle {
        font-size: 0.875rem;
        color: #64748B;
        margin-top: 0.25rem;
    }

    /* Environment Badge */
    .badge-env {
        display: inline-block;
        background: #F1F5F9;
        color: #475569;
        border: 1px solid #CBD5E1;
        font-size: 0.7rem;
        font-weight: 700;
        letter-spacing: 0.05em;
        padding: 0.25rem 0.55rem;
        border-radius: 4px;
        text-transform: uppercase;
    }

    /* Metric Cards */
    .metric-card {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 6px;
        padding: 1rem 1.25rem;
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.02);
    }
    .metric-label {
        font-size: 0.72rem;
        font-weight: 600;
        color: #64748B;
        text-transform: uppercase;
        letter-spacing: 0.06em;
    }
    .metric-value {
        font-size: 1.75rem;
        font-weight: 700;
        color: #0F172A;
        margin-top: 0.25rem;
        line-height: 1.1;
    }
    .metric-desc {
        font-size: 0.75rem;
        color: #94A3B8;
        margin-top: 0.35rem;
    }

    /* Surface Card */
    .surface-card {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 6px;
        padding: 1.25rem;
        margin-bottom: 1rem;
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.02);
    }
    .surface-title {
        font-size: 0.95rem;
        font-weight: 600;
        color: #0F172A;
        margin-bottom: 0.75rem;
    }

    /* Data Tables Full Width */
    .stDataFrame, .stTable {
        width: 100% !important;
    }
    .stTable table {
        width: 100% !important;
        border-collapse: collapse;
    }

    /* Buttons */
    button[kind="primary"] {
        background-color: #2563EB !important;
        border-color: #2563EB !important;
        color: #FFFFFF !important;
        font-weight: 500 !important;
        border-radius: 6px !important;
    }
    button[kind="primary"]:hover {
        background-color: #1D4ED8 !important;
        border-color: #1D4ED8 !important;
    }
    button[kind="secondary"] {
        background-color: #FFFFFF !important;
        border-color: #E2E8F0 !important;
        color: #0F172A !important;
        font-weight: 500 !important;
        border-radius: 6px !important;
    }
    </style>
    """
    st.markdown(css, unsafe_allow_html=True)


def render_header() -> None:
    """Header rendering compatible with existing unit tests."""
    st.error("LOCAL · MOCK ONLY — All operations are strictly local simulations.")
    st.title("Developer Sandbox Bootstrapper")


def render_page_header(title: str, subtitle: str) -> None:
    """Render a consistent, professional header across all six pages."""
    st.markdown(
        f"""
        <div class="page-header">
            <div>
                <div class="page-title">{title}</div>
                <div class="page-subtitle">{subtitle}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# =============================================================================
# Database Query Helpers (Live Data from SQLite)
# =============================================================================


def get_overview_kpis() -> dict[str, int]:
    """Query live KPIs directly from SQLite database."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM bootstrap_requests")
            row = cursor.fetchone()
            total_requests = row[0] if row else 0

            cursor.execute(
                "SELECT COUNT(*) FROM bootstrap_requests WHERE status IN "
                "('DRAFT', 'DISCOVERED', 'PLANNED', 'PENDING_APPROVAL', 'AWAITING_APPROVAL')"
            )
            row = cursor.fetchone()
            pending_approvals = row[0] if row else 0

            cursor.execute(
                "SELECT COUNT(*) FROM bootstrap_requests WHERE status IN ('SUCCEEDED', 'COMPLETED')"
            )
            row = cursor.fetchone()
            completed_executions = row[0] if row else 0

            cursor.execute(
                "SELECT COUNT(*) FROM bootstrap_requests WHERE status IN ('FAILED', 'REJECTED')"
            )
            row = cursor.fetchone()
            failed_executions = row[0] if row else 0

            return {
                "total_requests": total_requests,
                "pending_approvals": pending_approvals,
                "completed_executions": completed_executions,
                "failed_executions": failed_executions,
            }
    except Exception:
        return {
            "total_requests": 0,
            "pending_approvals": 0,
            "completed_executions": 0,
            "failed_executions": 0,
        }


def get_recent_requests(limit: int = 10) -> list[dict[str, Any]]:
    """Retrieve recent sandbox requests from SQLite."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT request_id, project_name, template, status, developer_id, created_at "
                "FROM bootstrap_requests ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()
            return [
                {
                    "request_id": r[0],
                    "project_name": r[1],
                    "template": r[2],
                    "status": r[3],
                    "developer_id": r[4],
                    "created_at": r[5],
                }
                for r in rows
            ]
    except Exception:
        return []


def get_tracked_sandboxes(limit: int = 10) -> list[dict[str, Any]]:
    """Retrieve provisioned mock sandboxes and cleanup retention deadlines."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT resource_id, request_id, resource_type, filesystem_path, created_at, expires_at "
                "FROM tracked_resources ORDER BY expires_at ASC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()
            return [
                {
                    "sandbox_id": r[0],
                    "request_id": r[1],
                    "resource_type": r[2],
                    "filesystem_path": r[3],
                    "created_at": r[4],
                    "cleanup_deadline": r[5],
                }
                for r in rows
            ]
    except Exception:
        return []


def get_recent_audit_events(limit: int = 8) -> list[dict[str, Any]]:
    """Retrieve recent audit events from append-only SQLite log."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT sequence_number, timestamp, event_type, actor_id, request_id, severity "
                "FROM audit_log ORDER BY sequence_number DESC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()
            return [
                {
                    "sequence_number": r[0],
                    "timestamp": r[1],
                    "event_type": r[2],
                    "actor_id": r[3],
                    "request_id": r[4],
                    "severity": r[5],
                }
                for r in rows
            ]
    except Exception:
        return []


def get_all_approver_tokens() -> list[dict[str, Any]]:
    """Retrieve token metadata without exposing raw secrets (only masked hashes)."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT token_hash, approver_id, role, authorized_scopes, created_at, revoked_at "
                "FROM approver_tokens ORDER BY created_at DESC"
            )
            rows = cursor.fetchall()
            return [
                {
                    "token_hash_preview": f"{r[0][:12]}...{r[0][-8:]}",
                    "approver_id": r[1],
                    "role": r[2],
                    "authorized_scopes": r[3],
                    "created_at": r[4],
                    "status": "Revoked" if r[5] else "Active",
                }
                for r in rows
            ]
    except Exception:
        return []


# =============================================================================
# Service Singletons
# =============================================================================


@st.cache_resource
def get_services() -> tuple[WorkflowOrchestrator, ApprovalService, TokenService, AuditChainService]:
    initialize_database()
    approval_svc = ApprovalService()
    token_svc = TokenService()
    audit_svc = AuditChainService()
    orchestrator = WorkflowOrchestrator(
        approval_service=approval_svc,
        audit_service=audit_svc,
    )
    return orchestrator, approval_svc, token_svc, audit_svc


# =============================================================================
# View 1: Overview Dashboard
# =============================================================================


def render_overview(orchestrator: WorkflowOrchestrator, audit_svc: AuditChainService) -> None:
    render_page_header("Overview", "Monitor sandbox requests, approvals, and executions.")

    kpis = get_overview_kpis()

    # 4 Aligned Metric Cards
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Total Requests</div>
                <div class="metric-value">{kpis['total_requests']}</div>
                <div class="metric-desc">Lifecycle runs initiated</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Pending Approval</div>
                <div class="metric-value">{kpis['pending_approvals']}</div>
                <div class="metric-desc">Awaiting human sign-off</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Completed Sandboxes</div>
                <div class="metric-value">{kpis['completed_executions']}</div>
                <div class="metric-desc">Provisioned & verified</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col4:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Failed / Rejected</div>
                <div class="metric-value">{kpis['failed_executions']}</div>
                <div class="metric-desc">Terminated or denied</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("### Recent Sandbox Requests")
    recent_reqs = get_recent_requests(limit=8)
    if recent_reqs:
        table_data = [
            {
                "Request ID": r["request_id"],
                "Project": r["project_name"],
                "Template": r["template"],
                "Status": r["status"],
                "Created At": r["created_at"][:19].replace("T", " "),
            }
            for r in recent_reqs
        ]
        st.dataframe(table_data, use_container_width=True, hide_index=True)

        col_act1, col_act2 = st.columns([2, 1])
        with col_act1:
            selected_from_table = st.selectbox(
                "Select request to inspect:",
                options=[r["request_id"] for r in recent_reqs],
                key="overview_quick_select",
                label_visibility="collapsed",
            )
        with col_act2:
            if st.button("Inspect in Plan & Approval", use_container_width=True):
                st.session_state["selected_request_id"] = selected_from_table
                st.session_state["nav_selection"] = "3. Plan & Approval"
                st.rerun()
    else:
        st.info("No sandbox requests created yet. Use 'Create Sandbox' to start your first setup workflow.")

    # Two column layout: Cleanups & Audit Activity
    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown("### Sandbox Retention Deadlines")
        tracked = get_tracked_sandboxes(limit=5)
        if tracked:
            cleanup_table = [
                {
                    "Sandbox ID": t["sandbox_id"],
                    "Request ID": t["request_id"],
                    "Created": t["created_at"][:19].replace("T", " "),
                    "Cleanup Deadline": t["cleanup_deadline"][:19].replace("T", " "),
                }
                for t in tracked
            ]
            st.dataframe(cleanup_table, use_container_width=True, hide_index=True)
        else:
            st.info("No active sandboxes provisioned. Retention deadlines are registered upon successful creation.")

    with col_right:
        st.markdown("### Recent Audit Activity")
        events = get_recent_audit_events(limit=5)
        if events:
            audit_table = [
                {
                    "Seq": f"#{e['sequence_number']}",
                    "Event": e["event_type"],
                    "Actor": e["actor_id"],
                    "Request": e["request_id"][:12] if e["request_id"] else "-",
                    "Timestamp": e["timestamp"][:19].replace("T", " "),
                }
                for e in events
            ]
            st.dataframe(audit_table, use_container_width=True, hide_index=True)
        else:
            st.info("No audit events recorded yet. Events are logged automatically as workflows progress.")


# =============================================================================
# View 2: Create Sandbox Request
# =============================================================================


def tab_create_request(orchestrator: WorkflowOrchestrator) -> None:
    st.markdown("### Create Request")
    st.caption("Specify project parameters to discover local prerequisites and generate a least-privilege plan.")

    with st.form("create_request_form"):
        col1, col2 = st.columns(2)
        with col1:
            project_name = st.text_input(
                "Project Name",
                value="my-fastapi-service",
                help="Lowercase alphanumeric with hyphens, e.g. 'my-fastapi-service'",
            )
            template_name = st.selectbox(
                "Project Template",
                options=[t.value for t in ProjectTemplate],
                index=0,
                help="Template defining dependency requirements and mock setup steps",
            )
            repository_path = st.text_input(
                "Repository Path",
                value="./",
                help="Local directory to inspect for framework and config markers",
            )
        with col2:
            developer_id = st.text_input(
                "Developer ID",
                value="dev-alice",
                help="Identifier of the requesting developer",
            )
            target_environment = st.text_input(
                "Target Environment",
                value="local-mock-dev",
                help="Isolated environment identifier",
            )
            scopes_selected = st.multiselect(
                "Requested Permission Scopes",
                options=[s.value for s in PermissionScope if s != PermissionScope.SANDBOX_DELETE],
                default=["sandbox:read", "sandbox:create", "data:seed:synthetic", "test:execute", "audit:read"],
                help="Least-privilege scopes. Deletion permission is intentionally excluded from creation requests.",
            )

        st.info("Synthetic Data Only: Bootstrapper generates local @example.local test fixtures. Zero live cloud access.")

        submit = st.form_submit_button("Create Request", use_container_width=True, type="primary")

    if submit:
        try:
            req_in = BootstrapRequestCreate(
                project_name=project_name,
                template=ProjectTemplate(template_name),
                repository_path=repository_path,
                developer_id=developer_id,
                target_environment=target_environment,
                requested_scopes=[PermissionScope(s) for s in scopes_selected],
            )
            created = orchestrator.create_request(req_in)
            st.session_state["selected_request_id"] = created.request_id
            st.success(f"Request {created.request_id} created successfully in status {created.status.value}.")
        except Exception as exc:
            st.error(f"Failed to create request: {exc}")


# =============================================================================
# View 3: Plan & Approval (Discovery + Planning + Gated Human Approval)
# =============================================================================


def tab_discovery_and_plan(orchestrator: WorkflowOrchestrator) -> None:
    st.markdown("### Setup Plan & Discovery")
    req_id = st.session_state.get("selected_request_id", "")
    req_id_input = st.text_input("Request ID to inspect", value=req_id, key="plan_inspect_req_id")

    if not req_id_input:
        st.warning("Please enter or select a Request ID.")
        return

    try:
        req = orchestrator.get_request(req_id_input)
    except Exception as exc:
        st.error(f"Request not found: {exc}")
        return

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### Request Metadata")
        st.json({
            "request_id": req.request_id,
            "project_name": req.project_name,
            "template": req.template.value,
            "status": req.status.value,
            "target_environment": req.target_environment,
            "developer_id": req.developer_id,
        })

    with col2:
        st.markdown("#### Discovered Local Environment")
        discovery_agent = DiscoveryAgent()
        disc_res = discovery_agent.discover(req.template, req.repository_path)
        st.json({
            "framework": disc_res.detected_framework,
            "config_files": disc_res.config_files_found,
            "mock_dashboard_network": disc_res.mock_network,
            "available_resources": [r.resource_id for r in disc_res.available_resources],
            "unavailable_resources": [r.resource_id for r in disc_res.unavailable_resources],
        })
        if disc_res.warnings:
            for w in disc_res.warnings:
                st.warning(f"Warning: {w}")

    st.markdown("#### Deterministic Setup Plan")
    plan = orchestrator._get_or_create_plan(req)
    st.markdown(f"**Canonical Plan Hash (RFC 8785 SHA-256):** `{plan.canonical_plan_hash}`")
    st.markdown(f"**Plan Version:** `{plan.plan_version}`")

    steps_data = [
        {
            "Step": s.step_id,
            "Action Type": s.action_type.value,
            "Name": s.name,
            "Required Scopes": ", ".join(sc.value for sc in s.required_scopes),
        }
        for s in plan.steps
    ]
    st.table(steps_data)


def tab_approvals(
    orchestrator: WorkflowOrchestrator,
    approval_svc: ApprovalService,
    token_svc: TokenService,
) -> None:
    st.markdown("### Human Approval Gate")
    st.caption("Privileged operations (mock provisioning and data seeding) require server-side approval.")

    req_id = st.session_state.get("selected_request_id", "")
    req_id_input = st.text_input("Target Request ID for Approval", value=req_id, key="approval_req_id")

    # Token Generation Tool
    with st.expander("Generate Approver Token (Displayed Once)", expanded=False):
        col_t1, col_t2 = st.columns(2)
        with col_t1:
            token_approver_id = st.text_input("Approver ID", value="sec-lead-01")
            token_role = st.selectbox("Role", options=["SECURITY_LEAD", "PLATFORM_ADMIN", "AUDITOR"])
        with col_t2:
            token_scopes = st.multiselect(
                "Authorized Permission Scopes",
                options=[s.value for s in PermissionScope],
                default=[s.value for s in PermissionScope],
            )

        if st.button("Generate Approver Token"):
            try:
                res = token_svc.create_token(
                    approver_id=token_approver_id,
                    role=token_role,
                    authorized_scopes=[PermissionScope(s) for s in token_scopes],
                )
                st.warning("Copy this raw token now. It is displayed ONCE and cannot be recovered.")
                st.code(res.raw_token, language="text")
                st.info(f"Token SHA-256 Hash recorded: {res.token_hash}")
            except Exception as exc:
                st.error(f"Failed to issue token: {exc}")

    if not req_id_input:
        st.warning("Please provide a Request ID to manage approval.")
        return

    try:
        req = orchestrator.get_request(req_id_input)
        plan = orchestrator._get_or_create_plan(req)
        existing_approval = orchestrator._check_approval(req, plan)
    except Exception as exc:
        st.error(f"Error loading request or plan: {exc}")
        return

    st.markdown("#### Approval Status")
    if existing_approval:
        st.success(
            f"Approved by {existing_approval.approver_id} "
            f"(Decision: {existing_approval.decision.value}, Expires: {existing_approval.expires_at.isoformat()})"
        )
        if existing_approval.execution_consumed:
            st.info(f"Approval was consumed atomically by execution {existing_approval.execution_id}.")
    else:
        st.warning(f"Awaiting Approval — Plan {plan.canonical_plan_hash[:16]}... requires authorized sign-off.")

    with st.form("submit_approval_form"):
        st.markdown("##### Submit Decision")
        approver_token_input = st.text_input("Enter Plaintext Approver Token", type="password")
        decision_choice = st.radio("Decision", options=["APPROVE", "REJECT"], horizontal=True)
        rejection_reason = st.text_input("Rejection Reason (if rejected)", value="")

        submit_appr = st.form_submit_button("Submit Decision", use_container_width=True, type="primary")

    if submit_appr:
        if not approver_token_input.strip():
            st.error("Approver token is required.")
            return

        try:
            identity = token_svc.resolve_identity(approver_token_input.strip())
            appr_req = ApprovalRequest(
                request_id=req.request_id,
                submitted_plan_hash=plan.canonical_plan_hash,
                plan_version=plan.plan_version,
                decision=ApprovalDecisionType(decision_choice),
                rejection_reason=rejection_reason if decision_choice == "REJECT" else None,
            )
            created_appr = approval_svc.create_approval(
                request=appr_req,
                approver=identity,
                target_environment=plan.target_environment,
                granted_scopes=req.requested_scopes,
            )
            st.success(f"Decision recorded: {created_appr.decision.value} (ID: {created_appr.approval_id}).")
            st.rerun()
        except TokenScopeError as exc:
            st.error(f"Scope Authorization Denied: {exc}")
        except TokenError as exc:
            st.error(f"Authentication Failed: {exc}")
        except ApprovalError as exc:
            st.error(f"Approval Rejected: {exc}")
        except Exception as exc:
            st.error(f"Unexpected error: {exc}")


def render_plan_and_approval(
    orchestrator: WorkflowOrchestrator,
    approval_svc: ApprovalService,
    token_svc: TokenService,
) -> None:
    render_page_header("Plan & Approval", "Inspect discovered environment prerequisites, review setup plan, and authorize execution.")

    recent_reqs = get_recent_requests(limit=20)
    current_selected = st.session_state.get("selected_request_id", "")
    
    if recent_reqs:
        req_ids = [r["request_id"] for r in recent_reqs]
        idx = req_ids.index(current_selected) if current_selected in req_ids else 0
        selected = st.selectbox("Select Sandbox Request to Inspect:", options=req_ids, index=idx)
        st.session_state["selected_request_id"] = selected

    subtabs = st.tabs(["Execution Plan & Discovery", "Approval Gate & Decision"])
    with subtabs[0]:
        tab_discovery_and_plan(orchestrator)
    with subtabs[1]:
        tab_approvals(orchestrator, approval_svc, token_svc)


# =============================================================================
# View 4: Execution Results & Verification
# =============================================================================


def tab_execution(orchestrator: WorkflowOrchestrator) -> None:
    st.markdown("### Workflow Execution")
    req_id = st.session_state.get("selected_request_id", "")
    req_id_input = st.text_input("Request ID to Run", value=req_id, key="run_req_id")

    if not req_id_input:
        st.warning("Please provide a Request ID to run.")
        return

    try:
        req = orchestrator.get_request(req_id_input)
    except Exception as exc:
        st.error(f"Request not found: {exc}")
        return

    st.markdown(f"**Current Status:** `{req.status.value}`")

    run_btn = st.button("Run / Resume Workflow", use_container_width=True, type="primary")

    if run_btn:
        with st.spinner("Executing workflow stages via LangGraph..."):
            result = orchestrator.run_workflow(
                request_id=req_id_input,
                raise_on_failure=False,
            )
            if result.is_completed:
                st.success(f"Workflow successfully completed with status {result.current_status.value}.")
                if result.sandbox_id:
                    st.info(f"Sandbox ID: {result.sandbox_id}")
                if result.cleanup_deadline:
                    st.info(f"Cleanup Deadline (24h retention policy): {result.cleanup_deadline}")
            elif result.approval_required:
                st.warning(
                    f"Workflow paused at stage {result.stage.value}: {result.error_message}. "
                    "Please approve the plan in Plan & Approval."
                )
            else:
                st.error(f"Workflow stopped at stage {result.stage.value}. Error: {result.error_message}")

    # Inspect step tracking
    steps = []
    if hasattr(orchestrator, "execution_tracker") and hasattr(orchestrator.execution_tracker, "get_executions_for_request"):
        steps = orchestrator.execution_tracker.get_executions_for_request(req_id_input)
    elif hasattr(orchestrator, "execution_tracker") and hasattr(orchestrator.execution_tracker, "get_all_executions_for_request"):
        steps = orchestrator.execution_tracker.get_all_executions_for_request(req_id_input)

    if steps:
        st.markdown("#### Step Execution History")
        table_rows = [
            {
                "Step ID": s.step_id,
                "Action": s.action_type.value if hasattr(s.action_type, "value") else str(s.action_type),
                "Status": s.status.value if hasattr(s.status, "value") else str(s.status),
                "Execution ID": s.execution_id,
                "Started At": s.started_at.isoformat() if s.started_at else "-",
                "Completed At": s.completed_at.isoformat() if s.completed_at else "-",
                "Error": s.error_message or "None",
            }
            for s in steps
        ]
        st.table(table_rows)


def tab_manifest_and_verification(orchestrator: WorkflowOrchestrator) -> None:
    st.markdown("### Setup Manifest & Verification")
    req_id = st.session_state.get("selected_request_id", "")
    req_id_input = st.text_input("Request ID for Manifest", value=req_id, key="manifest_req_id")

    if not req_id_input:
        st.warning("Please provide a Request ID.")
        return

    settings = get_settings()
    sandbox_root = Path(settings.sandbox_storage_dir)
    tracked = orchestrator._find_tracked_sandbox(req_id_input, sandbox_root)

    if tracked is None or not tracked.sandbox_dir.exists():
        st.info("No active provisioned sandbox found. Workflow must complete to generate the finalized manifest.")
        return

    manifest_file = tracked.sandbox_dir / "manifest.json"
    if not manifest_file.exists():
        st.info("Manifest file has not yet been generated for this sandbox.")
        return

    try:
        manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
        col_m1, col_m2 = st.columns(2)
        with col_m1:
            st.markdown("#### Manifest Integrity & Environment")
            st.json({
                "manifest_version": manifest_data.get("manifest_version"),
                "environment_label": manifest_data.get("environment_label"),
                "manifest_sha256": manifest_data.get("integrity", {}).get("manifest_sha256"),
                "canonical_plan_hash": manifest_data.get("integrity", {}).get("canonical_plan_hash"),
                "approval_id": manifest_data.get("integrity", {}).get("approval_id"),
                "mock_endpoint": manifest_data.get("environment", {}).get("mock_endpoint_url"),
            })
        with col_m2:
            st.markdown("#### Data Seeding & Verification")
            st.json({
                "fixtures_loaded": manifest_data.get("data_seeding", {}).get("fixtures_loaded"),
                "pii_scan_status": manifest_data.get("data_seeding", {}).get("pii_scan_status"),
                "verification_evidence": manifest_data.get("verification"),
            })

        with st.expander("View Full Manifest JSON"):
            st.json(manifest_data)
    except Exception as exc:
        st.error(f"Failed to read manifest: {exc}")


def render_execution_view(orchestrator: WorkflowOrchestrator, token_svc: TokenService) -> None:
    render_page_header("Execution Results", "Track LangGraph workflow progress, review step results, and inspect verification evidence.")

    recent_reqs = get_recent_requests(limit=20)
    current_selected = st.session_state.get("selected_request_id", "")
    
    if recent_reqs:
        req_ids = [r["request_id"] for r in recent_reqs]
        idx = req_ids.index(current_selected) if current_selected in req_ids else 0
        selected = st.selectbox("Select Target Sandbox Request:", options=req_ids, index=idx, key="exec_view_select")
        st.session_state["selected_request_id"] = selected

    subtabs = st.tabs(["Workflow Execution", "Manifest & Verification", "Authorized Sandbox Cleanup"])
    with subtabs[0]:
        tab_execution(orchestrator)
    with subtabs[1]:
        tab_manifest_and_verification(orchestrator)
    with subtabs[2]:
        st.markdown("#### Authorized Sandbox Cleanup")
        st.caption("Deleting a sandbox requires an approver token holding the 'sandbox:delete' permission scope.")

        with st.form("cleanup_sandbox_form"):
            sbx_id = st.text_input("Sandbox ID to Delete")
            appr_id = st.text_input("Approval ID")
            del_token = st.text_input("Approver Bearer Token (holding 'sandbox:delete')", type="password")
            clean_btn = st.form_submit_button("Delete Mock Sandbox")

        if clean_btn:
            if not sbx_id or not appr_id or not del_token:
                st.error("Sandbox ID, Approval ID, and Token are required.")
                return

            try:
                identity = token_svc.resolve_identity(del_token.strip())
                if PermissionScope.SANDBOX_DELETE not in identity.authorized_scopes:
                    st.error("Denied: Token lacks 'sandbox:delete' scope.")
                    return

                success = orchestrator.cleanup_workflow_sandbox(
                    request_id=st.session_state.get("selected_request_id") or "req-manual",
                    sandbox_id=sbx_id.strip(),
                    approval_id=appr_id.strip(),
                    execution_id=f"clean-{int(datetime.now(timezone.utc).timestamp())}",
                    caller_token=del_token.strip(),
                )
                if success:
                    st.success(f"Sandbox {sbx_id} deleted successfully.")
                else:
                    st.error("Failed to delete sandbox.")
            except Exception as exc:
                st.error(f"Cleanup failed: {exc}")


# =============================================================================
# View 5: Audit Logs & Chain Verification
# =============================================================================


def tab_audit_and_cleanup(
    orchestrator: WorkflowOrchestrator,
    audit_svc: AuditChainService,
    token_svc: TokenService,
) -> None:
    st.markdown("### Audit Log & Sandbox Cleanup")

    # Audit Log Verification
    report = audit_svc.verify_chain()
    if report.is_valid:
        st.success(f"Audit Hash Chain Verified: {report.events_inspected} events inspected. Zero tampering detected.")
    else:
        st.error(f"Audit Chain Integrity Failure! Errors: {report.errors}")

    req_id = st.session_state.get("selected_request_id", "")
    req_id_input = st.text_input("Filter Audit Log by Request ID", value=req_id, key="audit_req_id")

    # Sandbox Cleanup
    st.markdown("#### Authorized Sandbox Cleanup")
    st.caption("Deleting a sandbox requires an approver token holding the 'sandbox:delete' permission scope.")

    with st.form("cleanup_sandbox_form"):
        sbx_id = st.text_input("Sandbox ID to Delete")
        appr_id = st.text_input("Approval ID")
        del_token = st.text_input("Approver Bearer Token (holding 'sandbox:delete')", type="password")
        clean_btn = st.form_submit_button("Delete Mock Sandbox")

    if clean_btn:
        if not sbx_id or not appr_id or not del_token:
            st.error("Sandbox ID, Approval ID, and Token are required.")
            return

        try:
            identity = token_svc.resolve_identity(del_token.strip())
            if PermissionScope.SANDBOX_DELETE not in identity.authorized_scopes:
                st.error("Denied: Token lacks 'sandbox:delete' scope.")
                return

            success = orchestrator.cleanup_workflow_sandbox(
                request_id=req_id_input or "req-manual",
                sandbox_id=sbx_id.strip(),
                approval_id=appr_id.strip(),
                execution_id=f"clean-{int(datetime.now(timezone.utc).timestamp())}",
                caller_token=del_token.strip(),
            )
            if success:
                st.success(f"Sandbox {sbx_id} deleted successfully.")
            else:
                st.error("Failed to delete sandbox.")
        except Exception as exc:
            st.error(f"Cleanup failed: {exc}")


def render_audit_logs(audit_svc: AuditChainService) -> None:
    render_page_header("Audit Logs", "Inspect append-only, tamper-evident cryptographic hash chain of all workflow events.")

    # Integrity verification
    col_v1, col_v2 = st.columns([1, 3])
    with col_v1:
        verify_clicked = st.button("Verify Hash Chain Integrity", use_container_width=True, type="primary")

    if verify_clicked:
        report = audit_svc.verify_chain()
        if report.is_valid:
            st.success(
                f"Chain Verified: {report.events_inspected} events verified against genesis hash 0000... "
                "Zero tampering detected."
            )
        else:
            st.error(f"Chain Compromised: Errors: {report.errors}")

    # Search & Filters
    col_f1, col_f2, col_f3 = st.columns(3)
    with col_f1:
        filter_req = st.text_input("Filter by Request ID", value="")
    with col_f2:
        filter_type = st.selectbox(
            "Filter by Event Type",
            options=["ALL"] + [e.value for e in AuditEventType],
            index=0,
        )
    with col_f3:
        search_kw = st.text_input("Search in details", value="")

    query = "SELECT sequence_number, timestamp, event_type, request_id, actor_id, event_hash, details FROM audit_log WHERE 1=1"
    params: list[Any] = []
    if filter_req.strip():
        query += " AND request_id LIKE ?"
        params.append(f"%{filter_req.strip()}%")
    if filter_type != "ALL":
        query += " AND event_type = ?"
        params.append(filter_type)
    if search_kw.strip():
        query += " AND details LIKE ?"
        params.append(f"%{search_kw.strip()}%")
    query += " ORDER BY sequence_number DESC LIMIT 100"

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            if rows:
                table_rows = [
                    {
                        "Seq": f"#{r[0]}",
                        "Timestamp": r[1][:19].replace("T", " "),
                        "Event Type": r[2],
                        "Request ID": r[3],
                        "Actor": r[4],
                        "Hash Preview": f"{r[5][:8]}...{r[5][-6:]}",
                    }
                    for r in rows
                ]
                st.dataframe(table_rows, use_container_width=True, hide_index=True)

                with st.expander("View Raw Event Details"):
                    selected_seq = st.selectbox("Inspect Event Details by Sequence #:", options=[r[0] for r in rows])
                    selected_row = next((r for r in rows if r[0] == selected_seq), None)
                    if selected_row:
                        try:
                            details_json = json.loads(selected_row[6])
                            st.json(details_json)
                        except Exception:
                            st.code(selected_row[6])
            else:
                st.info("No audit events match the specified filter criteria.")
    except Exception as exc:
        st.error(f"Error querying audit log: {exc}")


# =============================================================================
# View 6: Settings & System Health
# =============================================================================


def render_settings(token_svc: TokenService) -> None:
    render_page_header("Settings", "Local runtime configuration, mock adapter status, and security controls.")

    settings = get_settings()

    col_s1, col_s2 = st.columns(2)
    with col_s1:
        st.markdown("#### Local Configuration")
        st.json({
            "environment": settings.environment,
            "environment_label": "MOCK / LOCAL ONLY",
            "database_path": settings.database_path,
            "sandbox_storage_dir": settings.sandbox_storage_dir,
            "approval_ttl_minutes": settings.approval_ttl_minutes,
            "sandbox_retention_hours": settings.sandbox_retention_hours,
            "ollama_planner_enabled": settings.enable_ollama_planner,
            "cloud_provisioning": False,
        })

    with col_s2:
        st.markdown("#### Security Controls")
        st.markdown(
            """
            - **Policy Engine:** Strict tool allowlist (`PROVISION_MOCK_SANDBOX`, `SEED_SYNTHETIC_DATA`, `EXECUTE_SMOKE_TEST`).
            - **Command Injection Guard:** Blocks arbitrary shell commands, operators, and semicolons.
            - **Path Confinement:** Prevents directory traversal (`..`) and symlink escapes.
            - **Token Entropy:** 256 bits (`secrets.token_urlsafe(32)`). Raw tokens are never stored.
            - **Atomic CAS Consumption:** Single-use execution gates enforced via SQLite `BEGIN IMMEDIATE` locks.
            - **Audit Hash-Chain:** Append-only SHA-256 links with SQLite triggers preventing row modifications.
            """
        )

    st.markdown("#### Approver Token Inventory (Hashed at Rest)")
    tokens = get_all_approver_tokens()
    if tokens:
        st.dataframe(tokens, use_container_width=True, hide_index=True)
    else:
        st.info("No approver tokens found in SQLite database. Use 'Plan & Approval' to bootstrap an initial approver token.")


# =============================================================================
# Main Application Entry Point
# =============================================================================


def main() -> None:
    init_page_config()
    inject_custom_css()

    orchestrator, approval_svc, token_svc, audit_svc = get_services()

    # Dark Sidebar Navigation Shell
    with st.sidebar:
        st.markdown(
            """
            <div style="padding: 1rem 0; border-bottom: 1px solid #1F2937; margin-bottom: 1rem;">
                <div style="font-size: 1.15rem; font-weight: 700; color: #FFFFFF; line-height: 1.2;">Bootstrapper</div>
                <div style="font-size: 0.75rem; color: #64748B; margin-top: 0.2rem;">Developer Sandbox Console</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        nav_options = [
            "1. Overview",
            "2. Create Sandbox",
            "3. Plan & Approval",
            "4. Execution Results",
            "5. Audit Logs",
            "6. Settings",
        ]

        current_nav = st.session_state.get("nav_selection", nav_options[0])
        idx = nav_options.index(current_nav) if current_nav in nav_options else 0

        selected_nav = st.radio(
            "Navigation Menu",
            options=nav_options,
            index=idx,
            label_visibility="collapsed",
            key="sidebar_nav_radio",
        )
        st.session_state["nav_selection"] = selected_nav

        st.markdown(
            """
            <div style="margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #1F2937; font-size: 0.72rem; color: #64748B; line-height: 1.4;">
                <p><strong>System Status:</strong></p>
                <p>Engine: LangGraph</p>
                <p>Storage: SQLite (WAL)</p>
                <p>Planner: Deterministic</p>
                <p>Cloud Cost: $0.00 (Mock)</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Route according to sidebar selection
    active_page = st.session_state.get("nav_selection", "1. Overview")

    if active_page == "1. Overview":
        render_overview(orchestrator, audit_svc)
    elif active_page == "2. Create Sandbox":
        tab_create_request(orchestrator)
    elif active_page == "3. Plan & Approval":
        render_plan_and_approval(orchestrator, approval_svc, token_svc)
    elif active_page == "4. Execution Results":
        render_execution_view(orchestrator, token_svc)
    elif active_page == "5. Audit Logs":
        render_audit_logs(audit_svc)
    elif active_page == "6. Settings":
        render_settings(token_svc)


if __name__ == "__main__":
    main()
