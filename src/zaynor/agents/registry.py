"""Approved ZAYNOR agent manifests.

An agent's identity is its exact tool manifest. Adding a tool requires an
explicit registry change and review; prompt text cannot widen authority.
"""

from __future__ import annotations

import hashlib
import json

from .contracts import AgentRole, AgentSpec, Capability, CapabilityEffect


REGISTRY_VERSION = "zaynor-agent-v1"


def _read_capability(resource: str) -> Capability:
    return Capability(CapabilityEffect.READ, resource)


def _derive_capability(resource: str) -> Capability:
    return Capability(CapabilityEffect.DERIVE, resource)


def _acquire_capability(resource: str) -> Capability:
    return Capability(CapabilityEffect.ACQUIRE, resource, True)


_SPECS = (
    AgentSpec(AgentRole.DISPATCHER, REGISTRY_VERSION, ("list_hunts",), ("case_memory",), capabilities=(_read_capability("hunt_catalog"),)),
    AgentSpec(AgentRole.ENDPOINT_HUNTER, REGISTRY_VERSION, ("collect_endpoint_window",), ("endpoint_telemetry",), capabilities=(_acquire_capability("endpoint_telemetry"),)),
    AgentSpec(AgentRole.PERSISTENCE_HUNTER, REGISTRY_VERSION, ("collect_persistence_window",), ("persistence_artifacts",), capabilities=(_acquire_capability("persistence_artifacts"),)),
    AgentSpec(AgentRole.THREAT_INTEL, REGISTRY_VERSION, ("enrich_indicators",), ("external_enrichment",), capabilities=(_derive_capability("threat_intel"),)),
    AgentSpec(AgentRole.DETECTION_ENGINEER, REGISTRY_VERSION, ("draft_sigma_rule",), ("sealed_results", "telemetry"), capabilities=(_derive_capability("detection_rule"),)),
    AgentSpec(AgentRole.INVESTIGATOR, REGISTRY_VERSION, ("list_hunts", "collect_window", "request_adjudication", "verify_custody"), ("frozen_evidence", "sealed_results"), capabilities=(_read_capability("hunt_catalog"), _acquire_capability("evidence_window"), _read_capability("sealed_results"), _read_capability("custody"))),
    AgentSpec(AgentRole.FLEET_COMMANDER, REGISTRY_VERSION, ("read_mission", "task_specialist", "record_hypothesis_proposal", "schedule_review", "escalate_human", "stand_down"), ("case_memory",), capabilities=(_read_capability("case_memory"), _derive_capability("investigation_plan"))),
    AgentSpec(AgentRole.MENTOR, REGISTRY_VERSION, ("explain_result", "explain_framework", "list_hunts"), ("sealed_results", "reference_material"), capabilities=(_read_capability("sealed_results"), _read_capability("reference_material"))),
)


def _manifest(spec: AgentSpec) -> dict:
    return {
        "name": spec.name.value,
        "version": spec.version,
        "tools": sorted(spec.tools),
        "data_classes": sorted(spec.data_classes),
        "can_write": spec.can_write,
        "can_adjudicate": spec.can_adjudicate,
        "capabilities": [
            {"effect": capability.effect.value, "resource": capability.resource,
             "requires_human_approval": capability.requires_human_approval}
            for capability in sorted(spec.capabilities, key=lambda item: (item.effect.value, item.resource))
        ],
    }


def manifest_hash(spec: AgentSpec) -> str:
    raw = json.dumps(_manifest(spec), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


APPROVED = {manifest_hash(spec): spec for spec in _SPECS}


def approved_agents() -> tuple[dict, ...]:
    return tuple(
        {**_manifest(spec), "manifest_sha256": manifest_hash(spec)}
        for spec in _SPECS
    )


def require_approved(role: AgentRole, tools: tuple[str, ...] | list[str]) -> str:
    """Require the exact approved tool contract for an agent role."""
    spec = next((item for item in _SPECS if item.name == role), None)
    if spec is None or tuple(sorted(tools)) != tuple(sorted(spec.tools)):
        raise PermissionError(f"unapproved agent tool manifest: {role.value}")
    return manifest_hash(spec)


def spec_for(role: AgentRole) -> AgentSpec:
    return next(spec for spec in _SPECS if spec.name == role)
