import json
from pathlib import Path

import pytest

from zaynor.case_freezer import freeze_case

SCENARIO_ROOT = Path(__file__).parent.parent / "scenarios" / "inc-2026-demo-001"
PROFILE_MAP = json.loads((SCENARIO_ROOT / "evidence_profile.json").read_text())


def test_freeze_case_produces_manifest_and_readonly_copies(tmp_path):
    manifest, evidence_dir = freeze_case(
        case_id="INC-TEST-001",
        evidence_profile="admin-session-investigation",
        profile_map=PROFILE_MAP,
        source_root=SCENARIO_ROOT,
        cases_root=tmp_path,
    )

    assert len(manifest.entries) == 5
    for entry in manifest.entries:
        frozen_file = evidence_dir / entry.relative_path
        assert frozen_file.exists()
        assert not (frozen_file.stat().st_mode & 0o200)  # not owner-writable


def test_freeze_case_is_reproducible():
    import tempfile

    with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
        manifest_a, _ = freeze_case(
            "INC-TEST-002", "admin-session-investigation", PROFILE_MAP, SCENARIO_ROOT, Path(a)
        )
        manifest_b, _ = freeze_case(
            "INC-TEST-002", "admin-session-investigation", PROFILE_MAP, SCENARIO_ROOT, Path(b)
        )
        hashes_a = sorted((e.relative_path, e.sha256) for e in manifest_a.entries)
        hashes_b = sorted((e.relative_path, e.sha256) for e in manifest_b.entries)
        assert hashes_a == hashes_b


def test_content_sha256_is_deterministic_across_freezes():
    """content_sha256 depends only on (relative_path, sha256) pairs — same
    evidence set, any time, same value.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
        manifest_a, _ = freeze_case(
            "INC-CONTENT-HASH", "admin-session-investigation", PROFILE_MAP, SCENARIO_ROOT, Path(a)
        )
        manifest_b, _ = freeze_case(
            "INC-CONTENT-HASH", "admin-session-investigation", PROFILE_MAP, SCENARIO_ROOT, Path(b)
        )
        assert manifest_a.content_sha256 == manifest_b.content_sha256


def test_sealed_at_sha256_differs_across_freezes_of_identical_content():
    """sealed_at_sha256 folds in the freeze timestamp — two freezes of the
    exact same evidence must NOT produce the same sealed_at_sha256, even
    though content_sha256 does match.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
        manifest_a, _ = freeze_case(
            "INC-SEAL-HASH", "admin-session-investigation", PROFILE_MAP, SCENARIO_ROOT, Path(a)
        )
        manifest_b, _ = freeze_case(
            "INC-SEAL-HASH", "admin-session-investigation", PROFILE_MAP, SCENARIO_ROOT, Path(b)
        )
        assert manifest_a.content_sha256 == manifest_b.content_sha256
        assert manifest_a.sealed_at != manifest_b.sealed_at
        assert manifest_a.sealed_at_sha256 != manifest_b.sealed_at_sha256


def test_freeze_case_rejects_unknown_evidence_profile():
    with pytest.raises(KeyError):
        freeze_case("INC-TEST-003", "nonexistent-profile", PROFILE_MAP, SCENARIO_ROOT, Path("/tmp"))


def test_freeze_case_rejects_path_traversal_inputs(tmp_path):
    with pytest.raises(ValueError, match="path-safe"):
        freeze_case("../escape", "admin-session-investigation", PROFILE_MAP, SCENARIO_ROOT, tmp_path)
    with pytest.raises(ValueError, match="relative"):
        freeze_case("INC-SAFE", "malicious", {"malicious": ["../secret"]}, SCENARIO_ROOT, tmp_path)


def test_frozen_evidence_is_only_readable_through_the_case_boundary(tmp_path):
    """Ground truth lives at docs/ground-truth-*.md, outside `scenarios/`'s
    evidence_profile.json entries — confirm freezing the case never pulls
    it in, regardless of what future evidence profiles might list.
    """
    _, evidence_dir = freeze_case(
        "INC-TEST-004", "admin-session-investigation", PROFILE_MAP, SCENARIO_ROOT, tmp_path
    )
    names = {p.name for p in evidence_dir.rglob("*") if p.is_file()}
    assert "GROUND_TRUTH.md" not in names
    assert not any("ground-truth" in name.lower() for name in names)
