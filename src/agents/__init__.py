"""Agents package for Developer Sandbox Bootstrapper.

Contains the 4 core agents and 2 deterministic workflow nodes:
- IntakeAgent (Agent 1)
- DiscoveryAgent (Agent 2)
- PlanningAgent (Agent 3)
- ExecutionAgent (Agent 4)
- VerificationNode (Deterministic verification)
- ReflectionNode (Deterministic failure reflection & bounded retry)
"""

from src.agents.discovery import DiscoveredResource, DiscoveryAgent, DiscoveryResult
from src.agents.executor import ExecutionAgent, StepExecutionResult
from src.agents.intake import IntakeAgent, IntakeRequest, ProjectSpecification
from src.agents.planner import PlanningAgent, PlanningInput
from src.agents.reflection import ReflectionDecision, ReflectionNode
from src.agents.verification import VerificationNode, VerificationReport

__all__ = [
    "IntakeAgent",
    "IntakeRequest",
    "ProjectSpecification",
    "DiscoveryAgent",
    "DiscoveryResult",
    "DiscoveredResource",
    "PlanningAgent",
    "PlanningInput",
    "ExecutionAgent",
    "StepExecutionResult",
    "VerificationNode",
    "VerificationReport",
    "ReflectionNode",
    "ReflectionDecision",
]
