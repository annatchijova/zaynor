"""Boundary tests for the typed INVESTIGATOR tool adapter."""

from pathlib import Path

from zaynor.agents.investigator_tools import InvestigatorToolAdapter, build_investigator_tools
from zaynor.zaynor_mcp_client import VigiaMCPConfig


def test_adapter_exposes_only_the_minimal_bound_handlers(monkeypatch):
    config = VigiaMCPConfig(vigia_repo_path=Path("/engine"), evidence_dir=Path("/evidence"))
    consult = object()
    adapter = InvestigatorToolAdapter(config, consult)  # type: ignore[arg-type]
    handlers = adapter.handlers()

    assert set(handlers) == {"collect_window", "verify_custody", "list_hunts", "request_adjudication"}
    assert set(handlers) == set(build_investigator_tools(config, consult))  # type: ignore[arg-type]
    assert "infer_intent" not in handlers
    assert "cross_artifact_analysis" not in handlers


def test_adapter_does_not_execute_until_handler_is_called(monkeypatch):
    config = VigiaMCPConfig(vigia_repo_path=Path("/engine"), evidence_dir=Path("/evidence"))
    calls = []

    class Consult:
        def list_hunts(self):
            calls.append("list_hunts")
            return {"hunts": []}

        def explain_result(self, case_id):
            calls.append(("request_adjudication", case_id))
            return {"found": False}

    handlers = InvestigatorToolAdapter(config, Consult()).handlers()
    assert calls == []
    assert handlers["list_hunts"]({}) == {"hunts": []}
    assert calls == ["list_hunts"]
