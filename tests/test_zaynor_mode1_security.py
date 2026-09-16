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
        run_vigia_mode1(repo, evidence, "CASE", tmp_path / "out.json", sys.executable)


def test_rejects_output_symlink(tmp_path):
    repo, evidence = _case(tmp_path)
    _agent(repo)
    target = tmp_path / "target"
    target.write_text("untouched")
    output = tmp_path / "out.json"
    output.symlink_to(target)
    with pytest.raises(Mode1ExecutionError, match="symlink"):
        run_vigia_mode1(repo, evidence, "CASE", output, sys.executable)
    assert target.read_text() == "untouched"


def test_rejects_exit_verdict_mismatch(tmp_path):
    repo, evidence = _case(tmp_path)
    _agent(repo, verdict="MALICE")
    # The generated agent exits 1 for MALICE; alter it to exit 0.
    path = repo / "vigia_agent.py"
    path.write_text(path.read_text().replace("sys.exit({'NOISE': 0, 'MALICE': 1", "sys.exit({'NOISE': 0, 'MALICE': 0"))
    with pytest.raises(Mode1ExecutionError, match="inconsistent"):
        run_vigia_mode1(repo, evidence, "CASE", tmp_path / "out.json", sys.executable)


def test_normalizes_verdict_and_excludes_volatile_timestamp(tmp_path):
    repo, evidence = _case(tmp_path)
    _agent(repo, verdict="NOISE")
    bundle = run_vigia_mode1(repo, evidence, "CASE", tmp_path / "out.json", sys.executable)
    first = translate_mode1_bundle("CASE", bundle)
    bundle["analysis_timestamp"] = "different"
    second = translate_mode1_bundle("CASE", bundle)
    assert first == second
    assert first.integrity["agent_verdict"] == "BENIGN"


def test_rejects_unbounded_subprocess_output_and_timeout(tmp_path):
    repo, evidence = _case(tmp_path)
    _agent(repo, stdout=2_000_000)
    with pytest.raises(Mode1ExecutionError, match="output limit"):
        run_vigia_mode1(repo, evidence, "CASE", tmp_path / "out.json", sys.executable)
    (repo / "vigia_agent.py").write_text("import time; time.sleep(2)")
    with pytest.raises(Mode1ExecutionError, match="timed out"):
        run_vigia_mode1(repo, evidence, "CASE", tmp_path / "out.json", sys.executable, timeout_seconds=1)


def test_rejects_unknown_verdict_at_translation_boundary():
    with pytest.raises(AdapterError, match="unsupported"):
        translate_mode1_bundle("CASE", {"case_id": "CASE", "agent_verdict": "BOGUS"})
