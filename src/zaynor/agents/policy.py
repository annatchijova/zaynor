"""Deterministic tool authorization for local agents."""

from __future__ import annotations

from .contracts import AgentRole, ToolRequest
from .registry import spec_for


class AgentPolicyError(PermissionError):
    """A model-proposed action is outside its approved contract."""


def authorize_tool(role: AgentRole, request: ToolRequest) -> None:
    """Authorize by role and tool name, never by the model's justification."""
    spec = spec_for(role)
    if request.tool not in spec.tools:
        raise AgentPolicyError(
            f"agent {role.value!r} cannot call tool {request.tool!r}"
        )
    if not isinstance(request.arguments, dict):
        raise AgentPolicyError("tool arguments must be an object")
