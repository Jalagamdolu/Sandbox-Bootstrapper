"""Workflow Supervisor for Developer Sandbox Bootstrapper.

Provides deterministic, evidence-based conditional routing at graph transition boundaries.
Evaluates typed state evidence (completion flags, approval verification, verification reports,
reflection decisions, and retry limits) to direct workflow state transitions.

NOTE: This supervisor is a rule-based deterministic controller inspecting typed execution evidence.
It is NOT an LLM or AI agent.
"""

from __future__ import annotations

import logging
from typing import Any
from langgraph.graph import END

logger = logging.getLogger(__name__)


class WorkflowSupervisor:
    """Deterministic evidence-based workflow supervisor.

    Evaluates execution evidence across the 10 lifecycle stages to determine state transitions.
    """

    @staticmethod
    def route_after_collect(state: dict[str, Any]) -> str:
        """Route to END if already completed, else continue to DISCOVER."""
        if state.get("is_completed"):
            logger.info("Supervisor: request %s already completed; routing to END.", state.get("request_id"))
            return END
        return "discover"

    @staticmethod
    def route_after_approval(state: dict[str, Any]) -> str:
        """Route to END if approval is required/unapproved, else proceed to PROVISION."""
        if state.get("approval_required") or not state.get("approved"):
            logger.info("Supervisor: request %s awaiting human approval; pausing graph at END.", state.get("request_id"))
            return END
        logger.info("Supervisor: request %s approved; routing to provision_mock_sandbox.", state.get("request_id"))
        return "provision_mock_sandbox"

    @staticmethod
    def route_after_provision(state: dict[str, Any]) -> str:
        """Route to reflect if provisioning had transient failure, else seed."""
        if state.get("error_message"):
            logger.info("Supervisor: provisioning encountered error; routing to reflect.")
            return "reflect"
        return "seed_synthetic_data"

    @staticmethod
    def route_after_seed(state: dict[str, Any]) -> str:
        """Route to reflect if seeding had transient failure, else verify."""
        if state.get("error_message"):
            logger.info("Supervisor: seeding encountered error; routing to reflect.")
            return "reflect"
        return "verify_sandbox"

    @staticmethod
    def route_after_verify(state: dict[str, Any]) -> str:
        """Route to finalize if verification passed, else reflect."""
        if state.get("error_message") or not state.get("verification_passed", True):
            logger.info("Supervisor: verification failure; routing to reflect.")
            return "reflect"
        return "finalize"

    @staticmethod
    def route_after_reflect(state: dict[str, Any]) -> str:
        """Route back to retry target if can_retry, else terminate at END."""
        if state.get("can_retry") and state.get("retry_target"):
            target = state["retry_target"]
            logger.info("Supervisor: bounded retry granted (count=%s); routing to %s.", state.get("retry_count"), target)
            return target
        logger.info("Supervisor: terminal failure or retry exhausted; routing to END.")
        return END
