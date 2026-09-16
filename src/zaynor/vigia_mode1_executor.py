"""Real Mode-1 executor: runs `vigia_agent.py` as a subprocess and returns
its sealed bundle, for `adapter.VigiaAdapter`.

Confirmed by reading `vigia_agent.py` directly (Phase 0 inventory) before
writing this:

- CLI: `python3 vigia_agent.py --evidence <dir> --case-id <id> --output
  <path>`. Writes the bundle atomically to `<path>` plus a `<path>.sha256`
  sidecar; exits 0 (NOISE) / 1 (MALICE) / 2 (ERROR) / 3 (INTENT) /
  4 (ABSTAIN) / 5 (SUSPICION) — `_VERDICT_EXIT` in `vigia_agent.py`.
- `--output` is validated by `_validate_agent_output_path` to resolve
  *under the process's CWD* — confirmed by induction: pointing it at an
  arbitrary `/tmp` path while `cwd=vigia_repo_path` failed with exit 2,
  "output path escapes working directory". So this executor writes the
  bundle to a private subdirectory under `vigia_repo_path` first, then
  copies it to the caller's requested `output_path` (which may be
  anywhere), rather than assuming the caller's path is usable directly.
- The bundle's real top-level shape (confirmed, not assumed) is:
  `vigia_agent_version`, `case_id`, `evidence_path`, `evidence_sha256`,
  `runtime_fingerprint`, `analysis_timestamp`, `iterations_executed`,
  `self_corrections_applied`, `agent_verdict`, `signal_stats`,
  `pipeline_results` (contains `abduction`: `best_hypothesis`,
  `best_posterior`, `devil_advocate`, plus `signals`), `narrative`,
  `audit_trail`, `sans_compliance`. This does NOT match the
  `findings`/`observations`/`timeline`/`fractures` shape
  `adapter.translate_result` was originally written against — that shape
  was provisional, written before this inventory existed.

The executor verifies the evidence digest, bundle sidecar, exit/verdict
agreement, and output destination before returning anything. What this module
deliberately does NOT do: invent a `findings[]` list
with fabricated `evidence_refs`/`lineage_id` out of `pipeline_results`.
`pipeline_results.signals` is not yet inspected deeply enough to know
which fields would make honest per-finding evidence references (real
per-signal artifact identity, not something derived after the fact) — see
`translate_mode1_bundle`'s docstring for what is mapped and what is left
as an explicit `unknowns` entry instead of a guess.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

_SAFE_RUN_ID = re.compile(r"[^A-Za-z0-9._-]")

from zaynor.adapter import AdapterError
from zaynor.schemas import ZaynorAuthoritativeResult

_VERDICT_EXIT_OK = {0, 1, 3, 4, 5}  # NOISE, MALICE, INTENT, ABSTAIN, SUSPICION
_EXIT_ERROR = 2
_EXIT_TO_VERDICT = {0: "NOISE", 1: "MALICE", 3: "INTENT", 4: "ABSTAIN", 5: "SUSPICION"}
_KNOWN_VERDICTS = frozenset(_EXIT_TO_VERDICT.values())
_MAX_SUBPROCESS_OUTPUT = 1_048_576
_CANONICAL_VERDICT = {
    "MALICE": "MALICE",
    "INTENT": "SUSPICION",
    "ABSTAIN": "ABSTAIN",
    "NOISE": "BENIGN",
    "SUSPICION": "SUSPICION",
}


class Mode1ExecutionError(RuntimeError):
    """`vigia_agent.py` could not be run or did not produce a readable bundle."""


def _hash_evidence_dir(evidence_dir: Path) -> str:
    """Match VIGÍA's deterministic directory digest and reject unsafe entries."""
    if evidence_dir.is_symlink():
        raise Mode1ExecutionError(f"evidence directory is a symlink: {evidence_dir}")
    digest = hashlib.sha256()
    for path in sorted(evidence_dir.rglob("*")):
        if path.is_symlink():
            raise Mode1ExecutionError(f"evidence contains symlink: {path}")
        if path.is_file():
            file_digest = hashlib.sha256(path.read_bytes()).digest()
            digest.update(str(path.relative_to(evidence_dir)).encode())
            digest.update(file_digest)
    return digest.hexdigest()


def _reject_symlink_path(path: Path) -> None:
    """Reject an output path whose existing components are symlinks."""
    current = path
    while current != current.parent:
        if current.exists() and current.is_symlink():
            raise Mode1ExecutionError(f"output path contains symlink: {current}")
        current = current.parent


def _tail(path: Path, limit: int = 2000) -> str:
    if not path.is_file():
        return ""
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        handle.seek(max(0, handle.tell() - limit))
        return handle.read().decode("utf-8", errors="replace")


def _read_sidecar(sidecar: Path, bundle_digest: str) -> None:
    if not sidecar.is_file() or sidecar.is_symlink():
        raise Mode1ExecutionError("VIGÍA did not produce a safe bundle digest sidecar")
    fields = sidecar.read_text(encoding="utf-8").strip().split()
    if not fields or fields[0] != bundle_digest:
        raise Mode1ExecutionError("VIGÍA bundle digest sidecar does not match bundle bytes")


def run_vigia_mode1(
    vigia_repo_path: Path,
    evidence_dir: Path,
    case_id: str,
    output_path: Path,
    python_executable: str = "python3",
    timeout_seconds: int = 300,
    max_output_bytes: int = _MAX_SUBPROCESS_OUTPUT,
) -> dict[str, Any]:
    """Run `vigia_agent.py` against `evidence_dir` and return its parsed
    bundle. Raises on exit code 2 (ERROR) or a missing/unparseable output
    file — a verdict exit code (0/1/3/4/5) is success, including ABSTAIN.
    """
    agent_path = vigia_repo_path / "vigia_agent.py"
    if not agent_path.is_file():
        raise Mode1ExecutionError(f"vigia_agent.py not found at {agent_path}")
    if not evidence_dir.is_dir():
        raise Mode1ExecutionError(f"evidence_dir does not exist: {evidence_dir}")

    # vigia_agent.py's --output must resolve under its own CWD (see module
    # docstring); write there first, in a private run-scoped subdirectory,
    # then copy the result to wherever the caller actually wants it.
    safe_run_id = _SAFE_RUN_ID.sub("_", case_id) or "run"
    if timeout_seconds <= 0 or max_output_bytes <= 0:
        raise Mode1ExecutionError("timeout_seconds and max_output_bytes must be positive")
    evidence_digest = _hash_evidence_dir(evidence_dir)
    with tempfile.TemporaryDirectory(dir=str(vigia_repo_path), prefix=f".zaynor_mode1_{safe_run_id}_") as run_dir:
        internal_output = Path(run_dir) / "bundle.json"
        stdout_path = Path(run_dir) / "stdout.log"
        stderr_path = Path(run_dir) / "stderr.log"

        try:
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                result = subprocess.run(
                    [python_executable, str(agent_path), "--evidence", str(evidence_dir),
                     "--case-id", case_id, "--output", str(internal_output)],
                    cwd=str(vigia_repo_path), stdout=stdout, stderr=stderr,
                    timeout=timeout_seconds,
                )
        except subprocess.TimeoutExpired as exc:
            raise Mode1ExecutionError(f"vigia_agent.py timed out after {timeout_seconds}s") from exc

        if result.returncode == _EXIT_ERROR:
            raise Mode1ExecutionError(
                f"vigia_agent.py reported an agent-level error (exit 2): {_tail(stderr_path)}"
            )
        if result.returncode not in _VERDICT_EXIT_OK:
            raise Mode1ExecutionError(
                f"vigia_agent.py exited with unexpected code {result.returncode}: {_tail(stderr_path)}"
            )
        if stdout_path.stat().st_size > max_output_bytes or stderr_path.stat().st_size > max_output_bytes:
            raise Mode1ExecutionError("vigia_agent.py exceeded the subprocess output limit")
        if not internal_output.is_file():
            raise Mode1ExecutionError(
                f"vigia_agent.py exited {result.returncode} but wrote no bundle: {_tail(stderr_path)}"
            )

        sha_sidecar = internal_output.with_suffix(internal_output.suffix + ".sha256")
        try:
            bundle_bytes = internal_output.read_bytes()
            bundle = json.loads(bundle_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise Mode1ExecutionError(f"bundle at {internal_output} is not valid JSON: {exc}") from exc
        if not isinstance(bundle, dict):
            raise Mode1ExecutionError("VIGÍA bundle must be a JSON object")
        bundle_digest = hashlib.sha256(bundle_bytes).hexdigest()
        _read_sidecar(sha_sidecar, bundle_digest)
        if bundle.get("evidence_sha256") != evidence_digest:
            raise Mode1ExecutionError("VIGÍA evidence hash does not match the frozen evidence directory")
        raw_verdict = bundle.get("agent_verdict")
        expected_verdict = _EXIT_TO_VERDICT[result.returncode]
        if raw_verdict not in _KNOWN_VERDICTS or raw_verdict != expected_verdict:
            raise Mode1ExecutionError("VIGÍA exit code and bundle verdict are inconsistent")

        _reject_symlink_path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        _reject_symlink_path(output_path)
        with tempfile.NamedTemporaryFile(dir=output_path.parent, prefix=f".{output_path.name}.", delete=False) as temp:
            temp.write(bundle_bytes)
            temp.flush()
            os.fsync(temp.fileno())
            temp_path = Path(temp.name)
        os.replace(temp_path, output_path)
        sidecar_output = output_path.with_suffix(output_path.suffix + ".sha256")
        _reject_symlink_path(sidecar_output)
        with tempfile.NamedTemporaryFile(dir=sidecar_output.parent, prefix=f".{sidecar_output.name}.", mode="w", encoding="utf-8", delete=False) as temp:
            temp.write(f"{bundle_digest}  {output_path.resolve()}\n")
            temp.flush()
            os.fsync(temp.fileno())
            sidecar_temp = Path(temp.name)
        os.replace(sidecar_temp, sidecar_output)
        return bundle


def translate_mode1_bundle(case_id: str, bundle: dict[str, Any]) -> ZaynorAuthoritativeResult:
    """Map VIGÍA's real Mode-1 bundle into `ZaynorAuthoritativeResult`,
    conservatively.

    Mapped (confirmed real fields, descriptive metadata only — none of
    this is a truth claim about the evidence):
    - `engine`: name="vigia_agent", version=`vigia_agent_version`,
      configuration_hash=`runtime_fingerprint`.
    - `integrity`: verified `evidence_sha256`, `iterations_executed`,
      `self_corrections_applied`, and the canonical ZAYNOR verdict.
    - `audit_refs`: one reference per `audit_trail` entry's action name —
      the entries themselves stay in VIGÍA's bundle, not duplicated here.

    Deliberately NOT mapped to `findings[]`: `agent_verdict` and
    `pipeline_results.abduction` (`best_hypothesis`, `best_posterior`,
    `devil_advocate`) are real, but turning them into an
    `AuthoritativeFinding` requires deciding what `evidence_refs`/
    `lineage_id` values are honest to attach — `pipeline_results.signals`'
    actual per-signal shape hasn't been inspected deeply enough yet to
    answer that without guessing. Recorded as an explicit `unknowns` entry
    instead of inventing a finding with fabricated evidence references.
    """
    raw_case_id = bundle.get("case_id")
    if raw_case_id != case_id:
        raise AdapterError(f"bundle case_id {raw_case_id!r} does not match frozen case {case_id!r}")
    raw_verdict = bundle.get("agent_verdict")
    if raw_verdict not in _CANONICAL_VERDICT:
        raise AdapterError(f"unsupported VIGÍA agent_verdict: {raw_verdict!r}")

    engine = {
        "name": "vigia_agent",
        "version": str(bundle.get("vigia_agent_version", "UNKNOWN")),
        "configuration_hash": str(bundle.get("runtime_fingerprint", "UNKNOWN")),
    }

    integrity = {
        "evidence_sha256": bundle.get("evidence_sha256", "UNKNOWN"),
        "iterations_executed": bundle.get("iterations_executed", "UNKNOWN"),
        "self_corrections_applied": bundle.get("self_corrections_applied", "UNKNOWN"),
        "agent_verdict": _CANONICAL_VERDICT[raw_verdict],
        "vigia_agent_verdict": raw_verdict,
    }

    audit_trail = bundle.get("audit_trail", [])
    audit_refs = tuple(
        f"{entry.get('action', 'UNKNOWN')}@{entry.get('timestamp', entry.get('iteration', '?'))}"
        for entry in audit_trail
        if isinstance(entry, dict)
    )

    unknowns = (
        "finding-level evidence_refs/lineage_id mapping not yet designed — "
        "pipeline_results.signals structure not yet inspected deeply enough "
        "to derive honest per-finding references",
    )

    return ZaynorAuthoritativeResult(
        case_id=case_id,
        engine=engine,
        findings=(),
        unknowns=unknowns,
        integrity=integrity,
        audit_refs=audit_refs,
    )
