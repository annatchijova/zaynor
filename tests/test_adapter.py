import json
from pathlib import Path

import pytest

from zaynor.adapter import AdapterError, VigiaAdapter, ZaynorMode1Adapter, _evidence_path_for_mode1
from zaynor.case_freezer import _content_sha256, _sealed_at_sha256
from zaynor.schemas import CaseManifest, ManifestEntry
from zaynor.vendored_engine import VENDORED_ENGINE_PATH

VIGIA_REPO_PATH = VENDORED_ENGINE_PATH
SCENARIO_ROOT = Path(__file__).parent.parent / "scenarios" / "inc-2026-demo-001"


def _manifest() -> CaseManifest:
    content = _content_sha256([])
    sealed_at = "2026-09-16T00:00:00+00:00"
    return CaseManifest(
        case_id="INC-ADAPTER-001", entries=(), content_sha256=content,
        sealed_at=sealed_at, sealed_at_sha256=_sealed_at_sha256(content, sealed_at),
    )


def test_evidence_path_for_mode1_routes_a_lone_json_file_to_itself(tmp_path):
    """Confirmed by induction against the real VIGÍA engine: a directory
    containing exactly one .json file (e.g. one of VIGÍA's own case
    corpus files, artifacts[] with type/source/content/metadata) produces
    0 signals when Mode 1 is pointed at the DIRECTORY (its directory-scan
    auto-detection has no *.json pattern), but real signals (20, for
    OWL-NEXUS5-CASE.json) when pointed at the file itself, which routes
    to VIGÍA's own EBS-JSON/rich-case-schema ingestion.
    """
    lone_json = tmp_path / "case.json"
    lone_json.write_text("{}")
    assert _evidence_path_for_mode1(tmp_path) == lone_json


def test_evidence_path_for_mode1_keeps_directory_mode_for_real_artifacts(tmp_path):
    (tmp_path / "SAM").write_bytes(b"fake hive")
    (tmp_path / "SYSTEM").write_bytes(b"fake hive")
    assert _evidence_path_for_mode1(tmp_path) == tmp_path


def test_evidence_path_for_mode1_keeps_directory_mode_for_multiple_json_files(tmp_path):
    (tmp_path / "a.json").write_text("{}")
    (tmp_path / "b.json").write_text("{}")
    assert _evidence_path_for_mode1(tmp_path) == tmp_path


def test_evidence_path_for_mode1_keeps_directory_mode_when_empty(tmp_path):
    assert _evidence_path_for_mode1(tmp_path) == tmp_path


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


def test_mode1_adapter_routes_a_lone_json_case_file_to_mode1_by_itself(monkeypatch, tmp_path):
    """A frozen case whose only evidence is one VIGÍA case-corpus JSON file
    (artifacts[] with type/source/content/metadata) must reach Mode 1 as
    that file, not the directory containing it — the directory-scan path
    has no *.json pattern and would silently see nothing.
    """
    import hashlib

    case_root = tmp_path / "INC-ADAPTER-002"
    evidence_dir = case_root / "evidence"
    evidence_dir.mkdir(parents=True)
    content = b'{"case_id": "INC-ADAPTER-002", "artifacts": []}'
    (evidence_dir / "vigia-case.json").write_bytes(content)
    captured = {}

    def fake_run(**kwargs):
        captured.update(kwargs)
        return {"case_id": "INC-ADAPTER-002", "agent_verdict": "ABSTAIN", "pipeline_results": {"signals": []}}

    monkeypatch.setattr("zaynor.zaynor_mode1_executor.run_vigia_mode1", fake_run)
    entry = ManifestEntry(
        relative_path="vigia-case.json", sha256=hashlib.sha256(content).hexdigest(), size_bytes=len(content)
    )
    content_sha = _content_sha256([entry])
    manifest = CaseManifest(
        case_id="INC-ADAPTER-002", entries=(entry,), content_sha256=content_sha,
        sealed_at="2026-09-16T00:00:00+00:00",
        sealed_at_sha256=_sealed_at_sha256(content_sha, "2026-09-16T00:00:00+00:00"),
    )
    ZaynorMode1Adapter(tmp_path / "engine", tmp_path / "outputs").analyze(manifest, evidence_dir)

    # The captured path lived under materialize_frozen_snapshot's temporary
    # directory, already cleaned up by the time analyze() returns — the
    # name is what proves the routing decision, not liveness.
    assert captured["evidence_path"].name == "vigia-case.json"
    assert captured["case_id"] == "INC-ADAPTER-002"


@pytest.mark.skipif(
    not (VIGIA_REPO_PATH / "vigia_agent.py").is_file(),
    reason="vendored VIGÍA engine (vendor/vigia_engine/) is missing",
)
def test_repeated_analyze_of_the_same_frozen_case_produces_the_same_seal(tmp_path):
    """Confirmed by an external audit, then reproduced here: before this
    fix, materialize_frozen_snapshot used a random tempfile suffix for its
    private snapshot directory. ZAYNOR points VIGIA_EVIDENCE_DIR/
    VIGIA_ALLOWED_REGISTRY_PATHS/VIGIA_ALLOWED_DUMP_PATHS at that
    directory, and VIGIA's own runtime_execution_fingerprint (vigia-repo,
    vigia/core/runtime_fingerprint.py) hashes every VIGIA_* environment
    variable into engine.configuration_hash — by design, since values like
    VIGIA_EBS_RESOLVE genuinely affect the deterministic computation. A
    randomized path carries no decision-relevant information but still
    changed configuration_hash, and therefore the seal, on every run of
    the IDENTICAL frozen case — violating CLAUDE.md 5.2's bit-for-bit
    reproducibility requirement with nothing about the evidence, decision,
    or configuration actually differing. Fixed by making the snapshot
    directory name content-addressed (manifest.content_sha256) instead of
    randomized, entirely on ZAYNOR's side of the environment variables it
    constructs (AGENTS.md 2.1: never modify vigia-repo).
    """
    from zaynor.case_freezer import freeze_case

    profile_map = json.loads((SCENARIO_ROOT / "evidence_profile.json").read_text())
    manifest, evidence_dir = freeze_case(
        case_id="INC-ADAPTER-REPRO",
        evidence_profile="admin-session-investigation",
        profile_map=profile_map,
        source_root=SCENARIO_ROOT,
        cases_root=tmp_path,
    )
    adapter = ZaynorMode1Adapter(VIGIA_REPO_PATH, tmp_path / "outputs", timeout_seconds=120)

    result_a = adapter.analyze(manifest, evidence_dir)
    result_b = adapter.analyze(manifest, evidence_dir)

    assert result_a.engine["configuration_hash"] == result_b.engine["configuration_hash"]
    from zaynor.authority_seal import seal_authoritative_result

    assert seal_authoritative_result(result_a).sha256 == seal_authoritative_result(result_b).sha256
