"""Typed contracts shared by ZAYNOR's local agents."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class AgentRole(StrEnum):
    DISPATCHER = "dispatcher"
    ENDPOINT_HUNTER = "endpoint-hunter"
    PERSISTENCE_HUNTER = "persistence-hunter"
    THREAT_INTEL = "threat-intel"
    DETECTION_ENGINEER = "detection-engineer"
    INVESTIGATOR = "investigator"
    FLEET_COMMANDER = "fleet-commander"
    MENTOR = "mentor"


class Audience(StrEnum):
    JUNIOR = "junior"
    SENIOR = "senior"


class CapabilityEffect(StrEnum):
    READ = "read"
    DERIVE = "derive"
    ACQUIRE = "acquire"
    MUTATE = "mutate"
    AUTHORIZE = "authorize"


@dataclass(frozen=True)
class Capability:
    effect: CapabilityEffect
    resource: str
    requires_human_approval: bool = False


@dataclass(frozen=True)
class AgentSpec:
    name: AgentRole
    version: str
    tools: tuple[str, ...]
    data_classes: tuple[str, ...]
    capabilities: tuple[Capability, ...] = ()
    can_write: bool = False
    can_adjudicate: bool = False


@dataclass(frozen=True)
class UntrustedContext:
    """Content read from evidence, MCP, tools, or another agent.

    This envelope is provenance and prompt hygiene, not an authorization
    control. Tool permissions remain enforced by :mod:`policy`.
    """

    source: str
    content: str
    instruction_authority: str = "none"

    def as_prompt_block(self) -> str:
        # Encode the payload as a JSON string and escape markup delimiters.
        # This is prompt hardening, not an authority control: the model still
        # receives untrusted bytes, while policy and structural guards remain
        # the actual controls on what the model can cause.
        encoded = json.dumps(self.content, ensure_ascii=False)[1:-1].replace("<", "\\u003c")
        return (
            f"<untrusted-data source={self.source!r} authority='none'>\n"
            f"{encoded}\n"
            "</untrusted-data>"
        )


@dataclass(frozen=True)
class ToolRequest:
    tool: str
    arguments: dict[str, Any]
