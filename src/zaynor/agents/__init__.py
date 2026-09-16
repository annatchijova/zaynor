"""Local, policy-gated agent layer for ZAYNOR."""

from .contracts import AgentRole, AgentSpec, Audience, Capability, CapabilityEffect, UntrustedContext
from .ollama_client import OllamaClient, OllamaError
from .policy import AgentPolicyError, authorize_tool
from .registry import approved_agents, require_approved
from .runtime import AgentRuntime, AgentRuntimeError
from .authority_guard import AuthorityGuardError, check_narrative, check_structured_output
from .consult_tools import ConsultToolError, ConsultTools

__all__ = [
    "AgentRole",
    "AgentSpec",
    "Audience",
    "Capability",
    "CapabilityEffect",
    "UntrustedContext",
    "OllamaClient",
    "OllamaError",
    "AgentPolicyError",
    "authorize_tool",
    "approved_agents",
    "require_approved",
    "AgentRuntime",
    "AgentRuntimeError",
    "AuthorityGuardError",
    "check_structured_output",
    "check_narrative",
    "ConsultToolError",
    "ConsultTools",
]
