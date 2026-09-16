from pathlib import Path

import pytest

from zaynor.adapter import AdapterError, VigiaAdapter, ZaynorMode1Adapter
from zaynor.schemas import CaseManifest, ManifestEntry


def _manifest() -> CaseManifest:
    return CaseManifest(case_id="INC-ADAPTER-001", entries=())


def test_adapter_translates_external_result_without_leaking_executor_objects(tmp_path):
    class ExternalFinding(dict):
        pass

    external_finding = ExternalFinding(
        finding_id="F-001",
        state="CORROBORATED",
        evidence_refs=[{"artifact": "auth.jsonl", "lineage_id": "auth:E001"}],
        rationale="independent deterministic basis",
    )

    def executor(evidence_dir: Path):
        assert evidence_dir == tmp_path
        return {
            "case_id": "INC-ADAPTER-001",
            "engine": {"name": "vigia", "version": "test", "configuration_hash": "cfg"},
            "findings": [external_finding],
            "unknowns": ["credential origin"],
        }

    result = VigiaAdapter(executor).analyze(_manifest(), tmp_path)

    assert result.case_id == "INC-ADAPTER-001"
    assert result.findings[0].finding_id == "F-001"
    assert result.findings[0].evidence_refs[0].lineage_id == "auth:E001"
    assert type(result.findings[0]).__name__ == "AuthoritativeFinding"
    assert "capability absent: timeline" in result.unknowns


def test_adapter_is_deterministic_and_has_no_llm_dependency(tmp_path):
    payload = {
        "case_id": "INC-ADAPTER-001",
        "engine": {"name": "vigia", "version": "test", "configuration_hash": "cfg"},
        "findings": [],
        "observations": [{"id": "O1"}],
        "timeline": [],
        "fractures": [],
        "hypotheses": [],
        "provenance": [],
    }
    adapter = VigiaAdapter(lambda _: payload)

    assert adapter.analyze(_manifest(), tmp_path) == adapter.analyze(_manifest(), tmp_path)


def test_adapter_rejects_case_mismatch_and_malformed_finding(tmp_path):
    with pytest.raises(AdapterError, match="case_id"):
        VigiaAdapter(lambda _: {"case_id": "OTHER", "findings": []}).analyze(_manifest(), tmp_path)

    with pytest.raises(AdapterError, match="finding_id"):
        VigiaAdapter(lambda _: {"findings": [{}]}).analyze(_manifest(), tmp_path)


def test_mode1_adapter_wires_manifest_to_real_executor(monkeypatch, tmp_path):
    case_root = tmp_path / "INC-ADAPTER-001"
    evidence_dir = case_root / "evidence"
    evidence_dir.mkdir(parents=True)
    captured = {}

    def fake_run(**kwargs):
        captured.update(kwargs)
        return {"case_id": "INC-ADAPTER-001", "agent_verdict": "ABSTAIN", "pipeline_results": {"signals": []}}

    monkeypatch.setattr("zaynor.zaynor_mode1_executor.run_vigia_mode1", fake_run)
    result = ZaynorMode1Adapter(tmp_path / "engine", tmp_path / "outputs").analyze(
        _manifest(), evidence_dir
    )

    assert result.case_id == "INC-ADAPTER-001"
    assert result.findings == ()
    assert captured["allowed_evidence_root"].parent == case_root
    assert captured["evidence_path"].parent == captured["allowed_evidence_root"]
    assert captured["case_id"] == "INC-ADAPTER-001"
