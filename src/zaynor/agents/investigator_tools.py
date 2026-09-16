"""INVESTIGATOR role tool handlers — the connection point between
`agents/`'s policy-gated tool names and VIGÍA's real MCP bridge.

Confirmed by reading `agents/registry.py`/`policy.py` and the rest of the
`agents/` package before writing this: most agent roles' tool names
(FLEET_COMMANDER's mission/hypothesis vocabulary, DISPATCHER/
ENDPOINT_HUNTER/PERSISTENCE_HUNTER/THREAT_INTEL's live-collection/
enrichment vocabulary, DETECTION_ENGINEER's `draft_sigma_rule`) do NOT
correspond to anything VIGÍA's MCP bridge exposes — VIGÍA analyzes frozen
evidence, it does not collect live endpoint telemetry or enrich threat
intel, and Sigma drafting is ZAYNOR's own `sigma_candidate.py`, not a
VIGÍA tool. MENTOR's tools (`consult_tools.py`) are correctly grounded in
ZAYNOR's own already-sealed package, never a live VIGÍA call — an
already-sealed verdict is never re-derived.

INVESTIGATOR is the one role whose declared capabilities
(`ACQUIRE:evidence_window`, `READ:custody`) genuinely name a live VIGÍA
capability: reading a window of frozen evidence, and recomputing a
forensic hash for custody verification. This module is the real
implementation for exactly those two tools — `collect_window` and
`verify_custody` — plus `list_hunts`/`request_adjudication`, which reuse
`ConsultTools` for the same reason MENTOR does (asking "what was
decided" must read the one sealed answer, never re-run VIGÍA).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from zaynor.zaynor_mcp_client import VigiaMCPClient, VigiaMCPConfig, VigiaMCPError

from .consult_tools import ConsultTools


class InvestigatorToolError(ValueError):
    """An INVESTIGATOR tool call could not be completed."""


ToolHandler = Callable[[dict[str, Any]], Any]


def _run_mcp_call(config: VigiaMCPConfig, tool: str, arguments: dict[str, Any]) -> Any:
    """One-shot MCP call: connect, call, disconnect.

    A fresh connection per call (rather than one held open across an
    agent's whole run) trades subprocess-launch overhead for simplicity —
    acceptable given `AgentRuntime`'s bounded step budget (default 8).
    Reusing one connection across a run is a later optimization, not a
    correctness requirement.
    """

    async def _call() -> Any:
        async with VigiaMCPClient(config) as client:
            return await client.call_tool(tool, arguments)

    try:
        content = asyncio.run(_call())
    except VigiaMCPError as exc:
        raise InvestigatorToolError(str(exc)) from exc
    if not content:
        raise InvestigatorToolError(f"VIGÍA tool {tool!r} returned no content")
    text = content[0].text
    try:
        return json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return {"text": text}


def collect_window(config: VigiaMCPConfig, arguments: dict[str, Any]) -> Any:
    """ACQUIRE:evidence_window — reads a bounded window of frozen evidence
    through VIGÍA's own `read_evidence`. Human-approval gating happens in
    `agents.policy.authorize_tool`, before this handler ever runs — this
    function does not re-check it.
    """
    path = arguments.get("path")
    if not isinstance(path, str) or not path.strip():
        raise InvestigatorToolError("collect_window requires a non-empty string 'path'")
    call_args: dict[str, Any] = {"path": path}
    if "max_bytes" in arguments:
        call_args["max_bytes"] = arguments["max_bytes"]
    return _run_mcp_call(config, "read_evidence", call_args)


def verify_custody(config: VigiaMCPConfig, arguments: dict[str, Any]) -> Any:
    """READ:custody — recomputes a forensic hash through VIGÍA's own
    `generate_forensic_hash`. This tool only returns the recomputed hash;
    comparing it against a manifest entry is a deterministic check that
    stays outside the LLM, never something this tool asserts on its own.
    """
    path = arguments.get("path")
    if not isinstance(path, str) or not path.strip():
        raise InvestigatorToolError("verify_custody requires a non-empty string 'path'")
    return _run_mcp_call(config, "generate_forensic_hash", {"file_path": path})


@dataclass(frozen=True)
class InvestigatorToolAdapter:
    """Typed adapter for the minimal real external-tool subset.

    The adapter only exposes handlers. It has no method that can create or
    alter an authoritative result; the bounded investigator remains the sole
    caller of the policy gate and records returned values as observations.
    """

    mcp_config: VigiaMCPConfig
    consult: ConsultTools

    def handlers(self) -> Mapping[str, ToolHandler]:
        return build_investigator_tools(self.mcp_config, self.consult)


def build_investigator_tools(
    mcp_config: VigiaMCPConfig, consult: ConsultTools
) -> dict[str, ToolHandler]:
    """The real INVESTIGATOR tool set for
    `AgentRuntime.run(AgentRole.INVESTIGATOR, tools=build_investigator_tools(...))`.

    `consult` must be bound to the one sealed package this investigation
    is allowed to read from — the same `ConsultTools` instance a MENTOR
    session over the same case would use.
    """
    return {
        "collect_window": lambda arguments: collect_window(mcp_config, arguments),
        "verify_custody": lambda arguments: verify_custody(mcp_config, arguments),
        "list_hunts": lambda arguments: consult.list_hunts(),
        "request_adjudication": lambda arguments: consult.explain_result(arguments.get("case_id", "")),
    }
