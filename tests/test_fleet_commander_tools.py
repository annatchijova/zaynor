"""Tests for FLEET_COMMANDER's real tool implementations, and an
end-to-end check that the tool names match agents/registry.py's declared
contract exactly (so AgentRuntime's authorization + this tool set agree).
"""

from __future__ import annotations

import pytest

from zaynor.agents.contracts import AgentRole
from zaynor.agents.fleet_commander_tools import (
    FleetCommanderToolError,
    build_fleet_commander_tools,
)
from zaynor.agents.registry import spec_for
from zaynor.agents.runtime import AgentRuntime
from zaynor.investigation_log import new_investigation_log


def test_tool_set_matches_the_registry_contract_exactly():
    log = new_investigation_log("CASE-FC")
    tools = build_fleet_commander_tools(log)
    assert set(tools) == set(spec_for(AgentRole.FLEET_COMMANDER).tools)


def test_read_mission_reports_a_clean_empty_journal():
    log = new_investigation_log("CASE-FC")
    tools = build_fleet_commander_tools(log)
    result = tools["read_mission"]({})
    assert result["case_id"] == "CASE-FC"
    assert result["log_ok"] is True
    assert result["journal_entries"] == 0
    assert result["hypotheses"] == []


def test_record_hypothesis_proposal_appends_to_the_real_journal():
    log = new_investigation_log("CASE-FC")
    tools = build_fleet_commander_tools(log)
    hypothesis = tools["record_hypothesis_proposal"]({"text": "Stolen admin credential"})
    assert hypothesis["status"] == "open"
    assert log["hypotheses"][0]["id"] == hypothesis["id"]

    mission = tools["read_mission"]({})
    assert mission["journal_entries"] == 1
    assert mission["hypotheses"][0]["text"] == "Stolen admin credential"


def test_record_hypothesis_proposal_never_produces_an_authoritative_state():
    """Confirms the boundary red-team round 5 (R5-1) required: this tool's
    output has no `state` field shaped like ZAYNOR's `CORROBORATED`/
    `CONTRADICTED`/`INSUFFICIENT` authoritative vocabulary — only
    `open`/`supported`/`refuted`.
    """
    log = new_investigation_log("CASE-FC")
    tools = build_fleet_commander_tools(log)
    hypothesis = tools["record_hypothesis_proposal"]({"text": "Insider threat"})
    assert hypothesis["status"] in ("open", "supported", "refuted")
    assert hypothesis["status"] not in ("CORROBORATED", "CONTRADICTED", "INSUFFICIENT")


def test_task_specialist_and_schedule_review_and_escalate_and_stand_down_are_journal_entries():
    log = new_investigation_log("CASE-FC")
    tools = build_fleet_commander_tools(log)

    tools["task_specialist"]({"specialist": "endpoint-hunter", "reason": "check EDR window"})
    tools["schedule_review"]({"reason": "re-check after new evidence arrives"})
    tools["escalate_human"]({"why": "possible MALICE, needs human sign-off"})
    tools["stand_down"]({"rationale": "no further leads without new evidence"})

    actions = [entry["action"] for entry in log["journal"]]
    assert actions == ["TASK_SPECIALIST", "SCHEDULE_REVIEW", "ESCALATE_HUMAN", "STAND_DOWN"]


@pytest.mark.parametrize(
    "tool,arguments",
    [
        ("record_hypothesis_proposal", {}),
        ("task_specialist", {"specialist": "x"}),
        ("task_specialist", {"reason": "x"}),
        ("schedule_review", {}),
        ("escalate_human", {}),
        ("stand_down", {}),
    ],
)
def test_missing_required_fields_are_rejected(tool, arguments):
    log = new_investigation_log("CASE-FC")
    tools = build_fleet_commander_tools(log)
    with pytest.raises(FleetCommanderToolError):
        tools[tool](arguments)


class _FakeOllama:
    def __init__(self, responses):
        self.responses = iter(responses)

    def generate(self, *, system, prompt):
        return next(self.responses)


def test_agent_runtime_authorizes_and_dispatches_to_the_real_tools():
    """End-to-end: AgentRuntime's own authorization (policy.py, matched
    against registry.py's declared FLEET_COMMANDER contract) accepts and
    correctly dispatches to build_fleet_commander_tools' real handlers,
    not just a test lambda.
    """
    log = new_investigation_log("CASE-FC")
    client = _FakeOllama(
        [
            '{"type":"tool_call","tool":"record_hypothesis_proposal","arguments":{"text":"Stolen admin credential"}}',
            '{"type":"final","text":"Hypothesis recorded."}',
        ]
    )
    result = AgentRuntime(client).run(
        AgentRole.FLEET_COMMANDER,
        system="system",
        prompt="Investigate the login anomaly",
        tools=build_fleet_commander_tools(log),
    )
    assert result == "Hypothesis recorded."
    assert log["hypotheses"][0]["text"] == "Stolen admin credential"
