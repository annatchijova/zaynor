import hashlib
import textwrap
from pathlib import Path

import pytest

from zaynor.adapter import AdapterError, ZaynorMode1Adapter
from zaynor.case_freezer import _content_sha256, _sealed_at_sha256
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
