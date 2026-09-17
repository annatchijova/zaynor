"""Integration test against the real vigia_agent.py (no mocks).

Skips cleanly if vigia-repo isn't present, same policy as
test_zaynor_mcp_client.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from zaynor.case_freezer import freeze_case
from zaynor.zaynor_mode1_executor import Mode1ExecutionError, run_vigia_mode1, translate_mode1_bundle
from zaynor.vendored_engine import VENDORED_ENGINE_PATH

VIGIA_REPO_PATH = VENDORED_ENGINE_PATH
SCENARIO_ROOT = Path(__file__).parent.parent / "scenarios" / "inc-2026-demo-001"
PROFILE_MAP = json.loads((SCENARIO_ROOT / "evidence_profile.json").read_text())

pytestmark = pytest.mark.skipif(
    not (VIGIA_REPO_PATH / "vigia_agent.py").is_file(),
    reason="vendored VIGÍA engine (vendor/vigia_engine/) is missing",
)


def test_mode1_runs_against_a_real_frozen_case(tmp_path):
    manifest, evidence_dir = freeze_case(
        case_id="INC-MODE1-TEST",
        evidence_profile="admin-session-investigation",
        profile_map=PROFILE_MAP,
        source_root=SCENARIO_ROOT,
        cases_root=tmp_path,
    )

    bundle = run_vigia_mode1(
        vigia_repo_path=VIGIA_REPO_PATH,
        evidence_path=evidence_dir,
        case_id=manifest.case_id,
        output_path=tmp_path / "bundle.json",
        allowed_evidence_root=tmp_path,
    )

    assert bundle["case_id"] == manifest.case_id
    assert bundle["agent_verdict"] in {"NOISE", "MALICE", "INTENT", "ABSTAIN", "SUSPICION"}
    assert len(bundle["evidence_sha256"]) == 64

    result = translate_mode1_bundle(manifest.case_id, bundle)
    assert result.case_id == manifest.case_id
    assert result.engine["name"] == "vigia_agent"
    assert result.verdict in {"MALICE", "ABSTAIN", "UNKNOWN", "BENIGN", "SUSPICION"}
    # This fixture's raw JSONL evidence matches none of VIGÍA's recognized
    # artifact patterns (see docs/implementation-plan.en.md Phase 0) — 0
    # signals, so no finding is fabricated from an uninformative verdict.
    assert result.findings == ()
    assert any("no usable signals" in u for u in result.unknowns)


def test_mode1_is_reproducible_on_the_same_frozen_case(tmp_path):
    manifest, evidence_dir = freeze_case(
        case_id="INC-MODE1-REPRO",
        evidence_profile="admin-session-investigation",
        profile_map=PROFILE_MAP,
        source_root=SCENARIO_ROOT,
        cases_root=tmp_path,
    )

    bundle_a = run_vigia_mode1(VIGIA_REPO_PATH, evidence_dir, manifest.case_id, tmp_path / "a.json", allowed_evidence_root=tmp_path)
    bundle_b = run_vigia_mode1(VIGIA_REPO_PATH, evidence_dir, manifest.case_id, tmp_path / "b.json", allowed_evidence_root=tmp_path)

    assert bundle_a["evidence_sha256"] == bundle_b["evidence_sha256"]
    assert bundle_a["agent_verdict"] == bundle_b["agent_verdict"]


def test_mode1_rejects_nonexistent_evidence_dir(tmp_path):
    with pytest.raises(Mode1ExecutionError):
        run_vigia_mode1(VIGIA_REPO_PATH, tmp_path / "does-not-exist", "X", tmp_path / "out.json", allowed_evidence_root=tmp_path)
