import json
from fractions import Fraction
from pathlib import Path

import pytest

from zaynor.case_freezer import freeze_case
from zaynor.ebs_artifact_scorer import score_inc_2026_demo_001, write_ebs_evidence
from zaynor.zaynor_mode1_executor import run_vigia_mode1, translate_mode1_bundle

SCENARIO_ROOT = Path(__file__).parent.parent / "scenarios" / "inc-2026-demo-001"
PROFILE_MAP = json.loads((SCENARIO_ROOT / "evidence_profile.json").read_text())
VIGIA_REPO_PATH = Path("/home/labestiadevigia/vigia-repo")

pytestmark = pytest.mark.skipif(
    not (VIGIA_REPO_PATH / "vigia_agent.py").is_file(),
    reason="vigia-repo checkout not present on this machine",
)


@pytest.fixture
def frozen_evidence_dir(tmp_path):
    _, evidence_dir = freeze_case(
        case_id="INC-EBS-FIXTURE",
        evidence_profile="admin-session-investigation",
        profile_map=PROFILE_MAP,
        source_root=SCENARIO_ROOT,
        cases_root=tmp_path,
    )
    return evidence_dir


def test_scorer_fires_all_three_rules_on_the_real_fixture(frozen_evidence_dir):
    rules = score_inc_2026_demo_001(frozen_evidence_dir)
    artifact_ids = {r.artifact_id for r in rules}
    assert artifact_ids == {"auth:E001", "fs:E006", "net:E005"}
    for rule in rules:
        assert Fraction(0) <= rule.raw_score <= Fraction(1)
        assert Fraction(0) <= rule.prior_trust <= Fraction(1)


def test_scorer_does_not_fire_when_device_is_known(frozen_evidence_dir):
    auth_path = frozen_evidence_dir / "collected" / "auth.jsonl"
    lines = auth_path.read_text().splitlines()
    lines[0] = lines[0].replace("DEV-UNKNOWN-17", "DEV-CORP-01")
    auth_path.chmod(0o600)
    auth_path.write_text("\n".join(lines) + "\n")

    rules = score_inc_2026_demo_001(frozen_evidence_dir)
    assert "auth:E001" not in {r.artifact_id for r in rules}


def test_write_ebs_evidence_produces_the_shape_vigia_expects(frozen_evidence_dir, tmp_path):
    rules = score_inc_2026_demo_001(frozen_evidence_dir)
    ebs_path = write_ebs_evidence("INC-EBS-FIXTURE", rules, tmp_path / "vigia_input" / "evidence.json")
    payload = json.loads(ebs_path.read_text())
    assert payload["case_id"] == "INC-EBS-FIXTURE"
    assert len(payload["artifacts"]) == 3
    for artifact in payload["artifacts"]:
        assert set(artifact) == {"artifact_id", "evidence_type", "raw_score", "prior_trust", "description", "source_tool"}


def test_end_to_end_scored_evidence_produces_traceable_findings(frozen_evidence_dir, tmp_path):
    """The full chain: fixture -> scorer -> EBS JSON -> real vigia_agent.py
    -> translate_mode1_bundle -> findings citing the real artifact_ids.
    """
    rules = score_inc_2026_demo_001(frozen_evidence_dir)
    ebs_path = write_ebs_evidence("INC-EBS-E2E", rules, tmp_path / "vigia_input" / "evidence.json")

    bundle = run_vigia_mode1(
        vigia_repo_path=VIGIA_REPO_PATH,
        evidence_path=ebs_path,
        case_id="INC-EBS-E2E",
        output_path=tmp_path / "bundle.json",
        allowed_evidence_root=tmp_path,
    )
    assert len(bundle["pipeline_results"]["signals"]) == 3

    result = translate_mode1_bundle("INC-EBS-E2E", bundle)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert {ref.artifact for ref in finding.evidence_refs} == {"auth:E001", "fs:E006", "net:E005"}
    assert finding.lineage_ids == tuple(ref.lineage_id for ref in finding.evidence_refs)
    assert finding.rationale  # VIGÍA's real Peircean narrative text, not empty
    assert result.unknowns == ()
