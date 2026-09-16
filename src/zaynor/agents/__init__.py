"""Local, policy-gated agent layer for ZAYNOR."""

from .contracts import AgentRole, AgentSpec, Audience, UntrustedContext
from .ollama_client import OllamaClient, OllamaError
from .policy import AgentPolicyError, authorize_tool
from .registry import approved_agents, require_approved
from .runtime import AgentRuntime, AgentRuntimeError

__all__ = [
    "AgentRole",
    "AgentSpec",
    "Audience",
    "UntrustedContext",
    "OllamaClient",
    "OllamaError",
    "AgentPolicyError",
    "authorize_tool",
    "approved_agents",
    "require_approved",
    "AgentRuntime",
    "AgentRuntimeError",
]
