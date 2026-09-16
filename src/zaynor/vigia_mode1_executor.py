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

What this module deliberately does NOT do: invent a `findings[]` list
with fabricated `evidence_refs`/`lineage_id` out of `pipeline_results`.
`pipeline_results.signals` is not yet inspected deeply enough to know
which fields would make honest per-finding evidence references (real
per-signal artifact identity, not something derived after the fact) — see
`translate_mode1_bundle`'s docstring for what is mapped and what is left
as an explicit `unknowns` entry instead of a guess.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

_SAFE_RUN_ID = re.compile(r"[^A-Za-z0-9._-]")

from zaynor.adapter import AdapterError
from zaynor.schemas import ZaynorAuthoritativeResult

_VERDICT_EXIT_OK = {0, 1, 3, 4, 5}  # NOISE, MALICE, INTENT, ABSTAIN, SUSPICION
_EXIT_ERROR = 2


class Mode1ExecutionError(RuntimeError):
    """`vigia_agent.py` could not be run or did not produce a readable bundle."""


def run_vigia_mode1(
    vigia_repo_path: Path,
    evidence_dir: Path,
    case_id: str,
    output_path: Path,
    python_executable: str = "python3",
    timeout_seconds: int = 300,
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
    with tempfile.TemporaryDirectory(dir=str(vigia_repo_path), prefix=f".zaynor_mode1_{safe_run_id}_") as run_dir:
        internal_output = Path(run_dir) / "bundle.json"

        result = subprocess.run(
            [
                python_executable,
                str(agent_path),
                "--evidence", str(evidence_dir),
                "--case-id", case_id,
                "--output", str(internal_output),
            ],
            cwd=str(vigia_repo_path),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )

        if result.returncode == _EXIT_ERROR:
            raise Mode1ExecutionError(
                f"vigia_agent.py reported an agent-level error (exit 2): {result.stderr[-2000:]}"
            )
        if result.returncode not in _VERDICT_EXIT_OK:
            raise Mode1ExecutionError(
                f"vigia_agent.py exited with unexpected code {result.returncode}: {result.stderr[-2000:]}"
            )
        if not internal_output.is_file():
            raise Mode1ExecutionError(
                f"vigia_agent.py exited {result.returncode} but wrote no bundle: {result.stderr[-2000:]}"
            )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(internal_output, output_path)
        sha_sidecar = internal_output.with_suffix(internal_output.suffix + ".sha256")
        if sha_sidecar.is_file():
            shutil.copy2(sha_sidecar, output_path.with_suffix(output_path.suffix + ".sha256"))

        try:
            return json.loads(output_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise Mode1ExecutionError(f"bundle at {output_path} is not valid JSON: {exc}") from exc


def translate_mode1_bundle(case_id: str, bundle: dict[str, Any]) -> ZaynorAuthoritativeResult:
    """Map VIGÍA's real Mode-1 bundle into `ZaynorAuthoritativeResult`,
    conservatively.

    Mapped (confirmed real fields, descriptive metadata only — none of
    this is a truth claim about the evidence):
    - `engine`: name="vigia_agent", version=`vigia_agent_version`,
      configuration_hash=`runtime_fingerprint`.
    - `integrity`: `evidence_sha256`, `analysis_timestamp`,
      `iterations_executed`, `self_corrections_applied`.
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

    engine = {
        "name": "vigia_agent",
        "version": str(bundle.get("vigia_agent_version", "UNKNOWN")),
        "configuration_hash": str(bundle.get("runtime_fingerprint", "UNKNOWN")),
    }

    integrity = {
        "evidence_sha256": bundle.get("evidence_sha256", "UNKNOWN"),
        "analysis_timestamp": bundle.get("analysis_timestamp", "UNKNOWN"),
        "iterations_executed": bundle.get("iterations_executed", "UNKNOWN"),
        "self_corrections_applied": bundle.get("self_corrections_applied", "UNKNOWN"),
        "agent_verdict": bundle.get("agent_verdict", "UNKNOWN"),
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
