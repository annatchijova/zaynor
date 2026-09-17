from __future__ import annotations

import hashlib
import json
import sys
import textwrap
from pathlib import Path

import pytest

from zaynor.adapter import AdapterError
from zaynor.zaynor_mode1_executor import (
    Mode1ExecutionError,
    run_vigia_mode1,
    translate_mode1_bundle,
)


def _agent(repo: Path, verdict: str = "NOISE", *, sidecar: str = "valid", stdout: int = 0) -> None:
    body = textwrap.dedent(
        f"""
        import hashlib, json, pathlib, sys
        evidence = pathlib.Path(sys.argv[sys.argv.index('--evidence') + 1])
        output = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])
        h = hashlib.sha256()
        for path in sorted(evidence.rglob('*')):
            if path.is_file():
                fh = hashlib.sha256(path.read_bytes()).digest()
                h.update(str(path.relative_to(evidence)).encode())
                h.update(fh)
        bundle = {{'case_id': 'CASE', 'evidence_sha256': h.hexdigest(),
                   'agent_verdict': {verdict!r}, 'analysis_timestamp': 'volatile',
                   'audit_trail': []}}
        raw = json.dumps(bundle).encode()
        output.write_bytes(raw)
        (output.parent / (output.name + '.sha256')).write_text(
            ({'hashlib.sha256(raw).hexdigest()' if sidecar == 'valid' else repr('0' * 64)} + '  ' + str(output) + '\\n'))
        print('X' * {stdout})
        sys.exit({{'NOISE': 0, 'MALICE': 1, 'INTENT': 3, 'ABSTAIN': 4, 'SUSPICION': 5}}.get({verdict!r}, 0))
        """
    )
    (repo / "vigia_agent.py").write_text(body)


def _case(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    evidence.mkdir()
    (evidence / "event.log").write_text("event")
    return repo, evidence


def test_rejects_bad_sidecar_and_evidence_hash(tmp_path):
    repo, evidence = _case(tmp_path)
    _agent(repo, sidecar="bad")
    with pytest.raises(Mode1ExecutionError, match="sidecar"):
        run_vigia_mode1(repo, evidence, "CASE", tmp_path / "out.json", sys.executable, allowed_evidence_root=tmp_path)


def test_rejects_output_symlink(tmp_path):
    repo, evidence = _case(tmp_path)
    _agent(repo)
    target = tmp_path / "target"
    target.write_text("untouched")
    output = tmp_path / "out.json"
    output.symlink_to(target)
    with pytest.raises(Mode1ExecutionError, match="symlink"):
        run_vigia_mode1(repo, evidence, "CASE", output, sys.executable, allowed_evidence_root=tmp_path)
    assert target.read_text() == "untouched"


def test_rejects_evidence_outside_explicit_root(tmp_path):
    repo, evidence = _case(tmp_path)
    _agent(repo)
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    with pytest.raises(Mode1ExecutionError, match="escapes allowed root"):
        run_vigia_mode1(repo, evidence, "CASE", tmp_path / "out.json", sys.executable, allowed_evidence_root=allowed)


def test_rejects_evidence_changed_during_execution(tmp_path):
    repo, evidence = _case(tmp_path)
    (repo / "vigia_agent.py").write_text(textwrap.dedent("""
        import hashlib, json, pathlib, sys
        evidence = pathlib.Path(sys.argv[sys.argv.index('--evidence') + 1])
        output = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])
        old = hashlib.sha256(evidence.joinpath('event.log').read_bytes()).hexdigest()
        evidence.joinpath('event.log').write_text('changed while running')
        bundle = {'case_id': 'CASE', 'evidence_sha256': old, 'agent_verdict': 'NOISE', 'audit_trail': []}
        raw = json.dumps(bundle).encode()
        output.write_bytes(raw)
        (output.parent / (output.name + '.sha256')).write_text(hashlib.sha256(raw).hexdigest() + '  ' + str(output) + '\\n')
        """))
    with pytest.raises(Mode1ExecutionError, match="changed while"):
        run_vigia_mode1(repo, evidence, "CASE", tmp_path / "out.json", sys.executable, allowed_evidence_root=tmp_path)


def test_rejects_exit_verdict_mismatch(tmp_path):
    repo, evidence = _case(tmp_path)
    _agent(repo, verdict="MALICE")
    # The generated agent exits 1 for MALICE; alter it to exit 0.
    path = repo / "vigia_agent.py"
    path.write_text(path.read_text().replace("sys.exit({'NOISE': 0, 'MALICE': 1", "sys.exit({'NOISE': 0, 'MALICE': 0"))
    with pytest.raises(Mode1ExecutionError, match="inconsistent"):
        run_vigia_mode1(repo, evidence, "CASE", tmp_path / "out.json", sys.executable, allowed_evidence_root=tmp_path)


def test_normalizes_verdict_and_excludes_volatile_timestamp(tmp_path):
    repo, evidence = _case(tmp_path)
    _agent(repo, verdict="NOISE")
    bundle = run_vigia_mode1(repo, evidence, "CASE", tmp_path / "out.json", sys.executable, allowed_evidence_root=tmp_path)
    first = translate_mode1_bundle("CASE", bundle)
    bundle["analysis_timestamp"] = "different"
    second = translate_mode1_bundle("CASE", bundle)
    assert first == second
    assert first.verdict == "UNKNOWN"


def test_rejects_unbounded_subprocess_output_and_timeout(tmp_path):
    repo, evidence = _case(tmp_path)
    _agent(repo, stdout=2_000_000)
    with pytest.raises(Mode1ExecutionError, match="output limit"):
        run_vigia_mode1(repo, evidence, "CASE", tmp_path / "out.json", sys.executable, allowed_evidence_root=tmp_path)
    (repo / "vigia_agent.py").write_text("import time; time.sleep(2)")
    with pytest.raises(Mode1ExecutionError, match="timed out"):
        run_vigia_mode1(repo, evidence, "CASE", tmp_path / "out.json", sys.executable, timeout_seconds=1, allowed_evidence_root=tmp_path)


def test_rejects_unknown_verdict_at_translation_boundary():
    with pytest.raises(AdapterError, match="unsupported"):
        translate_mode1_bundle("CASE", {"case_id": "CASE", "agent_verdict": "BOGUS"})


def _manifest_with_hashes(*hashes: str) -> "CaseManifest":
    from zaynor.schemas import CaseManifest, ManifestEntry

    return CaseManifest(
        case_id="CASE",
        entries=tuple(
            ManifestEntry(relative_path=f"artifact-{i}", sha256=h, size_bytes=1)
            for i, h in enumerate(hashes)
        ),
        content_sha256="irrelevant-for-this-test",
        sealed_at="1970-01-01T00:00:00+00:00",
        sealed_at_sha256="irrelevant-for-this-test",
    )


def test_signal_hive_sha256_outside_the_manifest_is_rejected():
    """Red-team round 7 (RT-03): confirmed by induction that, before this
    fix, nothing checked a signal's `metadata.hive_sha256` against the
    frozen case's manifest — a bundle citing a hive hash that was never
    part of this case's evidence produced an authoritative finding anyway.
    `hive_sha256` is a real content hash (confirmed against the 2019-OWL
    Digital Corpora image: matches `sha256sum` of the actual hive file),
    so a mismatch is a genuine integrity violation, not a benign gap.
    """
    bundle = {
        "case_id": "CASE",
        "agent_verdict": "NOISE",
        "pipeline_results": {
            "signals": [
                {"metadata": {"artifact_type": "registry", "hive_sha256": "f" * 64}},
            ]
        },
    }
    manifest = _manifest_with_hashes("a" * 64, "b" * 64)  # does not include "f" * 64
    with pytest.raises(AdapterError, match="not present in the frozen case manifest"):
        translate_mode1_bundle("CASE", bundle, manifest=manifest)


def test_signal_hive_sha256_inside_the_manifest_is_accepted():
    bundle = {
        "case_id": "CASE",
        "agent_verdict": "NOISE",
        "pipeline_results": {
            "signals": [
                {"metadata": {"artifact_type": "registry", "hive_sha256": "a" * 64}},
            ]
        },
    }
    manifest = _manifest_with_hashes("a" * 64, "b" * 64)
    result = translate_mode1_bundle("CASE", bundle, manifest=manifest)
    assert len(result.findings) == 1
    assert result.findings[0].evidence_refs[0].artifact == f"registry:{'a' * 64}"


def test_signal_hive_sha256_is_unchecked_when_no_manifest_is_given():
    """Documents the deliberate scope limit: omitting `manifest` narrows
    this check rather than failing — existing callers with only a
    synthetic bundle and no manifest fixture keep working.
    """
    bundle = {
        "case_id": "CASE",
        "agent_verdict": "NOISE",
        "pipeline_results": {
            "signals": [
                {"metadata": {"artifact_type": "registry", "hive_sha256": "f" * 64}},
            ]
        },
    }
    result = translate_mode1_bundle("CASE", bundle)
    assert len(result.findings) == 1
