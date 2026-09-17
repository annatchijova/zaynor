import hashlib
import textwrap
from pathlib import Path

import pytest

from zaynor.adapter import AdapterError, ZaynorMode1Adapter
from zaynor.case_freezer import _content_sha256, _sealed_at_sha256, freeze_case
from zaynor.frozen_snapshot import FrozenSnapshotError, _inventory, materialize_frozen_snapshot
from zaynor.hash_utils import sha256_file
from zaynor.schemas import CaseManifest, ManifestEntry


def _manifest(case_id: str, path: Path) -> CaseManifest:
    entry = ManifestEntry(path.name, sha256_file(path), path.stat().st_size)
    content = _content_sha256([entry])
    sealed_at = "2026-09-16T00:00:00+00:00"
    return CaseManifest(
        case_id=case_id,
        entries=(entry,),
        content_sha256=content,
        sealed_at=sealed_at,
        sealed_at_sha256=_sealed_at_sha256(content, sealed_at),
    )


def _mutating_agent(engine: Path) -> None:
    (engine / "vigia_agent.py").write_text(
        textwrap.dedent(
            """
            import hashlib, json, pathlib, sys
            evidence = pathlib.Path(sys.argv[sys.argv.index('--evidence') + 1])
            output = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])
            target = evidence / 'event.log'
            target.chmod(0o600)
            target.write_text('tampered snapshot')
            digest = hashlib.sha256()
            for path in sorted(evidence.rglob('*')):
                if path.is_file():
                    digest.update(str(path.relative_to(evidence)).encode())
                    digest.update(hashlib.sha256(path.read_bytes()).digest())
            bundle = {'case_id': 'CASE-SNAPSHOT',
                      'evidence_sha256': digest.hexdigest(),
                      'agent_verdict': 'NOISE', 'audit_trail': []}
            raw = json.dumps(bundle).encode()
            output.write_bytes(raw)
            output.with_suffix(output.suffix + '.sha256').write_text(
                hashlib.sha256(raw).hexdigest() + '  ' + str(output) + '\\n')
            """
        )
    )


def test_mutation_after_initial_hash_fails_closed_on_private_snapshot(tmp_path):
    case_root = tmp_path / "CASE-SNAPSHOT"
    evidence = case_root / "evidence"
    evidence.mkdir(parents=True)
    original = evidence / "event.log"
    original.write_text("original frozen bytes")
    engine = tmp_path / "engine"
    engine.mkdir()
    _mutating_agent(engine)

    with pytest.raises(AdapterError, match="changed while"):
        ZaynorMode1Adapter(engine, tmp_path / "output").analyze(
            _manifest("CASE-SNAPSHOT", original), evidence
        )

    # The live frozen case was never handed to the subprocess.
    assert original.read_text() == "original frozen bytes"


def test_inventory_symlink_error_does_not_leak_the_absolute_server_path(tmp_path):
    """Red team round 22 (R22-03, CONFIRMED BY INDUCTION): the error used
    to interpolate the absolute `Path`, so it always contained the
    server's real `cases_root` prefix (str(tmp_path) here stands in for
    that). `api.py`'s get_case_evidence forwards this string verbatim to
    an HTTP client, so this must stay a case-relative path.
    """
    evidence = tmp_path / "cases" / "CASE-LEAK" / "evidence"
    evidence.mkdir(parents=True)
    (evidence / "collected").mkdir()
    (evidence / "collected" / "real.log").write_text("x")
    (evidence / "collected" / "evil_link").symlink_to(evidence / "collected" / "real.log")

    with pytest.raises(FrozenSnapshotError) as excinfo:
        _inventory(evidence)
    assert "evil_link" in str(excinfo.value)
    assert str(tmp_path) not in str(excinfo.value)


def test_manifest_binds_the_complete_authorized_evidence_set(tmp_path):
    case_root = tmp_path / "CASE-EXACT"
    evidence = case_root / "evidence"
    evidence.mkdir(parents=True)
    event = evidence / "event.log"
    event.write_text("authorized")
    (evidence / "unlisted.log").write_text("not authorized")
    engine = tmp_path / "engine"
    engine.mkdir()
    _mutating_agent(engine)

    with pytest.raises(AdapterError, match="evidence set does not match manifest"):
        ZaynorMode1Adapter(engine, tmp_path / "output").analyze(
            _manifest("CASE-EXACT", event),
            evidence,
        )


def test_snapshot_directory_name_is_content_addressed_not_randomized(tmp_path):
    """Confirmed by an external audit, then reproduced against the real
    engine: a randomized snapshot directory name leaked into VIGIA's
    runtime_execution_fingerprint (every VIGIA_* env var, including the
    allowlist paths ZAYNOR points at this directory), making
    engine.configuration_hash — and therefore the seal — different on
    every run of the identical frozen case. The directory name must
    depend only on the manifest's content identity, so it repeats exactly
    for repeated analyses of the same case.
    """
    case_root = tmp_path / "CASE-DETERMINISTIC"
    evidence = case_root / "evidence"
    evidence.mkdir(parents=True)
    (evidence / "event.log").write_text("evidence bytes")
    manifest = _manifest("CASE-DETERMINISTIC", evidence / "event.log")

    with materialize_frozen_snapshot(manifest, evidence) as snapshot_a:
        snapshot_dir_a = snapshot_a.path.parent.name
    with materialize_frozen_snapshot(manifest, evidence) as snapshot_b:
        snapshot_dir_b = snapshot_b.path.parent.name

    assert snapshot_dir_a == snapshot_dir_b
    assert manifest.content_sha256 in snapshot_dir_a


def test_concurrent_snapshot_for_the_same_case_fails_closed(tmp_path):
    """A leftover directory from a crashed prior run, or a genuinely
    concurrent analyze of the same case, must be visible as a failure —
    never silently reused or overwritten.
    """
    case_root = tmp_path / "CASE-COLLISION"
    evidence = case_root / "evidence"
    evidence.mkdir(parents=True)
    (evidence / "event.log").write_text("evidence bytes")
    manifest = _manifest("CASE-COLLISION", evidence / "event.log")

    with materialize_frozen_snapshot(manifest, evidence):
        with pytest.raises(FrozenSnapshotError, match="already exists"):
            with materialize_frozen_snapshot(manifest, evidence):
                pass


def test_snapshot_directory_is_cleaned_up_after_use(tmp_path):
    case_root = tmp_path / "CASE-CLEANUP"
    evidence = case_root / "evidence"
    evidence.mkdir(parents=True)
    (evidence / "event.log").write_text("evidence bytes")
    manifest = _manifest("CASE-CLEANUP", evidence / "event.log")

    with materialize_frozen_snapshot(manifest, evidence) as snapshot:
        snapshot_dir = snapshot.path.parent
        assert snapshot_dir.is_dir()
    assert not snapshot_dir.exists()


def test_snapshot_materialization_does_not_make_case_evidence_writable(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    event = source / "event.log"
    event.write_text("evidence bytes")
    _, evidence = freeze_case(
        "CASE-PERMISSIONS", "profile", {"profile": ["event.log"]}, source, tmp_path / "cases"
    )
    assert evidence.stat().st_mode & 0o222 == 0
