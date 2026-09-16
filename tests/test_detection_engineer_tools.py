"""Tests for DETECTION_ENGINEER's real tool implementation."""

from __future__ import annotations

import pytest

from zaynor.agents.contracts import AgentRole
from zaynor.agents.detection_engineer_tools import (
    DetectionEngineerToolError,
    build_detection_engineer_tools,
)
from zaynor.agents.registry import spec_for
from zaynor.agents.runtime import AgentRuntime
from zaynor.schemas import AuthoritativeFinding, EvidenceRef, ZaynorAuthoritativeResult

REF = EvidenceRef(artifact="auth:E001", lineage_id="auth")


def _result():
    return ZaynorAuthoritativeResult(
        case_id="CASE-DE",
        engine={"name": "zaynor-test", "version": "1"},
        findings=(AuthoritativeFinding(finding_id="F-1", state="SUSPICION", evidence_refs=(REF,)),),
    )


def test_tool_set_matches_the_registry_contract_exactly():
    tools = build_detection_engineer_tools(_result())
    assert set(tools) == set(spec_for(AgentRole.DETECTION_ENGINEER).tools)


def test_draft_sigma_rule_produces_a_real_grounded_candidate():
    tools = build_detection_engineer_tools(_result())
    candidate = tools["draft_sigma_rule"](
        {
            "finding_id": "F-1",
            "title": "Privileged login from uninventoried device",
            "evidence_refs": [{"artifact": "auth:E001", "lineage_id": "auth"}],
            "logsource": {"category": "authentication"},
            "detection": {"selection": {"event": "vpn_login"}, "condition": "selection"},
            "tags": ["attack.t1078"],
        }
    )
    assert candidate["is_candidate"] is True
    assert candidate["validated"] is False
    assert "CANDIDATE SIGMA RULE" in candidate["banner"]


def test_draft_sigma_rule_rejects_fabricated_evidence():
    tools = build_detection_engineer_tools(_result())
    with pytest.raises(DetectionEngineerToolError, match="not among finding"):
        tools["draft_sigma_rule"](
            {
                "finding_id": "F-1",
                "title": "x",
                "evidence_refs": [{"artifact": "fabricated", "lineage_id": "not-real"}],
                "logsource": {"category": "authentication"},
                "detection": {"condition": "selection"},
            }
        )


def test_draft_sigma_rule_rejects_missing_required_fields():
    tools = build_detection_engineer_tools(_result())
    with pytest.raises(DetectionEngineerToolError, match="title"):
        tools["draft_sigma_rule"]({"finding_id": "F-1"})


class _FakeOllama:
    def __init__(self, responses):
        self.responses = iter(responses)

    def generate(self, *, system, prompt):
        return next(self.responses)


def test_agent_runtime_authorizes_and_dispatches_to_the_real_tool():
    client = _FakeOllama(
        [
            (
                '{"type":"tool_call","tool":"draft_sigma_rule","arguments":'
                '{"finding_id":"F-1","title":"Privileged login",'
                '"evidence_refs":[{"artifact":"auth:E001","lineage_id":"auth"}],'
                '"logsource":{"category":"authentication"},'
                '"detection":{"condition":"selection"}}}'
            ),
            '{"type":"final","text":"Candidate drafted."}',
        ]
    )
    result = AgentRuntime(client).run(
        AgentRole.DETECTION_ENGINEER,
        system="system",
        prompt="Draft a detection for this finding",
        tools=build_detection_engineer_tools(_result()),
    )
    assert result == "Candidate drafted."
