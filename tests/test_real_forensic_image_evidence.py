"""Integration test against a REAL, public Digital Corpora forensic image
(2019-OWL, https://digitalcorpora.org/corpora/scenarios/2019-owl/),
already extracted locally for a prior VIGÍA investigation.

This is the "real forensic image" path, distinct from
`test_ebs_artifact_scorer.py`'s synthetic EBS-JSON path: it exercises
VIGÍA's actual registry/prefetch/browser/event-log analyzers on genuine
Windows artifacts, not a hand-scored JSON shortcut. Skips cleanly if this
specific evidence directory isn't present on the machine — the image is
gigabytes of public research data, not something to ship in this repo or
assume present in every environment.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from zaynor.zaynor_mode1_executor import run_vigia_mode1, translate_mode1_bundle

VIGIA_REPO_PATH = Path("/home/labestiadevigia/vigia-repo")
OWL_EVIDENCE_DIR = VIGIA_REPO_PATH / "evidence" / "owl-2019-hd1-windows"

pytestmark = pytest.mark.skipif(
    not OWL_EVIDENCE_DIR.is_dir(),
    reason="real Digital Corpora evidence (2019-OWL) not present on this machine",
)


def test_registry_hives_are_readable_once_allowlisted(tmp_path):
    """Regression for a real bug found by induction: registry_timeline_
    reconstructor.py and memory_forensics.py each keep their own path
    allowlist (VIGIA_ALLOWED_REGISTRY_PATHS / VIGIA_ALLOWED_DUMP_PATHS),
    separate from VIGIA_EVIDENCE_DIR. Before run_vigia_mode1 set these,
    every registry hive in this real image was rejected with "Hive outside
    configured allowlist" even though it sat inside VIGIA_EVIDENCE_DIR.
    """
    bundle = run_vigia_mode1(
        vigia_repo_path=VIGIA_REPO_PATH,
        evidence_path=OWL_EVIDENCE_DIR,
        case_id="INC-OWL-2019-REGRESSION",
        output_path=tmp_path / "bundle.json",
        timeout_seconds=180,
        allowed_evidence_root=VIGIA_REPO_PATH / "evidence",
    )
    registry_signals = [
        s for s in bundle["pipeline_results"]["signals"]
        if isinstance(s, dict) and s.get("metadata", {}).get("artifact_type") == "registry"
    ]
    assert len(registry_signals) == 5  # SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT
    for signal in registry_signals:
        assert not signal["metadata"].get("error")
        assert "hive_sha256" in signal["metadata"]


def test_real_image_produces_traceable_findings_across_artifact_types(tmp_path):
    """The generalized signal->EvidenceRef mapping, confirmed against real
    forensic-image signals that have no artifact_id (unlike the EBS-JSON
    path) — identified instead by metadata.hive_sha256/source_path/
    source_profile/artifact_type.
    """
    bundle = run_vigia_mode1(
        vigia_repo_path=VIGIA_REPO_PATH,
        evidence_path=OWL_EVIDENCE_DIR,
        case_id="INC-OWL-2019-FINDINGS",
        output_path=tmp_path / "bundle.json",
        timeout_seconds=180,
        allowed_evidence_root=VIGIA_REPO_PATH / "evidence",
    )
    result = translate_mode1_bundle("INC-OWL-2019-FINDINGS", bundle)

    assert len(result.findings) == 1
    finding = result.findings[0]
    lineages = {ref.lineage_id for ref in finding.evidence_refs}
    # At minimum, registry and prefetch signals should both be present and
    # traceable, each under its own artifact-type lineage.
    assert "registry" in lineages
    assert "prefetch" in lineages

    # Five distinct registry hives must not collapse into one evidence_ref
    # (they're separate files)...
    registry_artifacts = {ref.artifact for ref in finding.evidence_refs if ref.lineage_id == "registry"}
    assert len(registry_artifacts) == 5
    # ...but they also must not be counted as five independent lineages —
    # they're all the same analysis pipeline over the same acquisition.
    registry_lineages = {ref.lineage_id for ref in finding.evidence_refs if ref.artifact in registry_artifacts}
    assert registry_lineages == {"registry"}
