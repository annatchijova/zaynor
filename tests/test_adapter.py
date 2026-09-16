from pathlib import Path

import pytest

from zaynor.adapter import AdapterError, VigiaAdapter
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
