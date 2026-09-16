"""Deterministic tool authorization for local agents."""

from __future__ import annotations

from .contracts import AgentRole, CapabilityEffect, ToolRequest
from .registry import spec_for


class AgentPolicyError(PermissionError):
    """A model-proposed action is outside its approved contract."""


_TOOL_EFFECTS = {
    "list_hunts": (CapabilityEffect.READ, "hunt_catalog"),
    "collect_endpoint_window": (CapabilityEffect.ACQUIRE, "endpoint_telemetry"),
    "collect_persistence_window": (CapabilityEffect.ACQUIRE, "persistence_artifacts"),
    "enrich_indicators": (CapabilityEffect.DERIVE, "threat_intel"),
    "draft_sigma_rule": (CapabilityEffect.DERIVE, "detection_rule"),
    "collect_window": (CapabilityEffect.ACQUIRE, "evidence_window"),
    "request_adjudication": (CapabilityEffect.READ, "sealed_results"),
    "verify_custody": (CapabilityEffect.READ, "custody"),
    "read_mission": (CapabilityEffect.READ, "case_memory"),
    "task_specialist": (CapabilityEffect.DERIVE, "investigation_plan"),
    "record_hypothesis_proposal": (CapabilityEffect.DERIVE, "investigation_plan"),
    "schedule_review": (CapabilityEffect.DERIVE, "investigation_plan"),
    "escalate_human": (CapabilityEffect.DERIVE, "investigation_plan"),
    "stand_down": (CapabilityEffect.DERIVE, "investigation_plan"),
    "explain_result": (CapabilityEffect.READ, "sealed_results"),
    "explain_framework": (CapabilityEffect.READ, "reference_material"),
}


def authorize_tool(role: AgentRole, request: ToolRequest, *, human_approved: bool = False) -> None:
    """Authorize by role and tool name, never by the model's justification."""
    spec = spec_for(role)
    if request.tool not in spec.tools:
        raise AgentPolicyError(
            f"agent {role.value!r} cannot call tool {request.tool!r}"
        )
    if not isinstance(request.arguments, dict):
        raise AgentPolicyError("tool arguments must be an object")
    effect_resource = _TOOL_EFFECTS.get(request.tool)
    if effect_resource is None:
        raise AgentPolicyError(f"tool {request.tool!r} has no declared capability")
    effect, resource = effect_resource
    spec_capabilities = {(item.effect, item.resource, item.requires_human_approval) for item in spec.capabilities}
    matching = [item for item in spec_capabilities if item[:2] == (effect, resource)]
    if not matching:
        raise AgentPolicyError(f"agent {role.value!r} lacks capability {effect.value}:{resource}")
    if matching[0][2] and not human_approved:
        raise AgentPolicyError(f"capability {effect.value}:{resource} requires human approval")
