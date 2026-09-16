from __future__ import annotations

from zaynor.agents.contracts import AgentRole
from zaynor.agents.dispatcher_tools import DEFAULT_HUNT_CATALOG, build_dispatcher_tools
from zaynor.agents.registry import spec_for
from zaynor.agents.runtime import AgentRuntime


def test_tool_set_matches_the_registry_contract_exactly():
    tools = build_dispatcher_tools()
    assert set(tools) == set(spec_for(AgentRole.DISPATCHER).tools)


def test_default_catalog_lists_only_hunts_confirmed_reachable_from_mode1():
    tools = build_dispatcher_tools()
    result = tools["list_hunts"]({})
    ids = {hunt["id"] for hunt in result["hunts"]}
    assert ids == set(DEFAULT_HUNT_CATALOG)
    assert all(hunt["description"] for hunt in result["hunts"])


def test_a_narrower_case_specific_catalog_can_be_supplied():
    tools = build_dispatcher_tools({"registry": "registry only, no memory dump for this case"})
    result = tools["list_hunts"]({})
    assert result["hunts"] == [{"id": "registry", "description": "registry only, no memory dump for this case"}]


class _FakeOllama:
    def __init__(self, responses):
        self.responses = iter(responses)

    def generate(self, *, system, prompt):
        return next(self.responses)


def test_agent_runtime_authorizes_and_dispatches_to_the_real_tool():
    client = _FakeOllama(
        [
            '{"type":"tool_call","tool":"list_hunts","arguments":{}}',
            '{"type":"final","text":"Catalog retrieved."}',
        ]
    )
    result = AgentRuntime(client).run(
        AgentRole.DISPATCHER,
        system="system",
        prompt="What can we investigate?",
        tools=build_dispatcher_tools(),
    )
    assert result == "Catalog retrieved."
