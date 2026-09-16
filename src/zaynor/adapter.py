"""Explicit ZAYNOR ↔ VIGÍA adapter boundary.

The executor is injected because VIGÍA is an external engine. This module
owns only the stable ZAYNOR contract and translation; it never imports or
returns VIGÍA types.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from zaynor.schemas import (
    AuthoritativeFinding,
    CaseManifest,
    EvidenceRef,
    ZaynorAuthoritativeResult,
)
from zaynor.frozen_snapshot import FrozenSnapshotError, materialize_frozen_snapshot


class AdapterError(ValueError):
    """Raised when the external deterministic result cannot be translated."""


VigiaExecutor = Callable[[Path], Mapping[str, Any]]


def _as_records(value: Any) -> tuple[dict[str, Any], ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise AdapterError("expected a list of object records")
    return tuple(dict(item) for item in value)


def _as_strings(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise AdapterError("expected a list of strings")
    return tuple(value)


def _translate_finding(raw: Any) -> AuthoritativeFinding:
    if not isinstance(raw, dict) or not isinstance(raw.get("finding_id"), str):
        raise AdapterError("finding requires a string finding_id")
    state = raw.get("state", "UNKNOWN")
    if not isinstance(state, str):
        raise AdapterError("finding state must be a string")

    raw_refs = raw.get("evidence_refs", [])
    if not isinstance(raw_refs, list):
        raise AdapterError("finding evidence_refs must be a list")
    refs: list[EvidenceRef] = []
    for ref in raw_refs:
        if not isinstance(ref, dict):
            raise AdapterError("evidence_refs must contain objects")
        artifact = ref.get("artifact")
        lineage_id = ref.get("lineage_id")
        if not isinstance(artifact, str) or not isinstance(lineage_id, str):
            raise AdapterError("evidence refs require artifact and lineage_id")
        refs.append(EvidenceRef(artifact=artifact, lineage_id=lineage_id))

    lineage_ids = _as_strings(raw.get("lineage_ids", [ref.lineage_id for ref in refs]))
    return AuthoritativeFinding(
        finding_id=raw["finding_id"],
        state=state,
        evidence_refs=tuple(refs),
        lineage_ids=lineage_ids,
        rationale=str(raw.get("rationale", "")),
        mitre=dict(raw["mitre"]) if isinstance(raw.get("mitre"), dict) else None,
        nist=dict(raw["nist"]) if isinstance(raw.get("nist"), dict) else None,
    )


def translate_result(case_id: str, raw: Mapping[str, Any]) -> ZaynorAuthoritativeResult:
    """Translate one executor result and fail closed on malformed fields.

    Missing optional capabilities are represented explicitly as UNKNOWN rather
    than filled with a ZAYNOR-generated forensic value.
    """
    raw_case_id = raw.get("case_id", case_id)
    if raw_case_id != case_id:
        raise AdapterError("executor result case_id does not match frozen case")

    engine_raw = raw.get("engine")
    if not isinstance(engine_raw, dict):
        engine = {"name": "UNKNOWN", "version": "UNKNOWN", "configuration_hash": "UNKNOWN"}
        missing_engine = ("capability absent: engine metadata",)
    else:
        engine = {key: str(engine_raw.get(key, "UNKNOWN")) for key in ("name", "version", "configuration_hash")}
        missing_engine = ()

    expected_records = ("observations", "timeline", "fractures", "hypotheses", "provenance")
    unknowns = list(_as_strings(raw.get("unknowns", [])))
    for field_name in expected_records:
        if field_name not in raw:
            unknowns.append(f"capability absent: {field_name}")

    findings_raw = raw.get("findings", [])
    if not isinstance(findings_raw, list):
        raise AdapterError("findings must be a list")

    return ZaynorAuthoritativeResult(
        case_id=case_id,
        engine=engine,
        observations=_as_records(raw.get("observations")),
        timeline=_as_records(raw.get("timeline")),
        fractures=_as_records(raw.get("fractures")),
        hypotheses=_as_records(raw.get("hypotheses")),
        findings=tuple(_translate_finding(item) for item in findings_raw),
        unknowns=tuple(dict.fromkeys((*missing_engine, *unknowns))),
        provenance=_as_records(raw.get("provenance")),
        integrity=dict(raw.get("integrity", {})) if isinstance(raw.get("integrity", {}), dict) else {},
        audit_refs=_as_strings(raw.get("audit_refs", [])),
    )


class VigiaAdapter:
    """Run the injected deterministic executor against a frozen case."""

    def __init__(self, executor: VigiaExecutor):
        self._executor = executor

    def analyze(self, manifest: CaseManifest, evidence_dir: Path) -> ZaynorAuthoritativeResult:
        if manifest.case_id == "":
            raise AdapterError("frozen case_id must not be empty")
        if not evidence_dir.is_dir():
            raise AdapterError("frozen evidence directory is missing")
        raw = self._executor(evidence_dir)
        if not isinstance(raw, Mapping):
            raise AdapterError("executor must return a mapping")
        return translate_result(manifest.case_id, raw)


class ZaynorMode1Adapter:
    """Production wiring for ZAYNOR's real Mode-1 integration.

    This keeps the generic injected adapter above useful for contract tests,
    while providing the missing concrete path from a frozen case to the real
    subprocess executor. The executor module is imported lazily to avoid a
    circular dependency: it imports ``AdapterError`` for its translation
    boundary.
    """

    def __init__(
        self,
        engine_repo_path: Path,
        output_root: Path,
        *,
        python_executable: str = "python3",
        timeout_seconds: int = 300,
        max_output_bytes: int = 1_048_576,
    ) -> None:
        self._engine_repo_path = engine_repo_path
        self._output_root = output_root
        self._python_executable = python_executable
        self._timeout_seconds = timeout_seconds
        self._max_output_bytes = max_output_bytes

    def analyze(self, manifest: CaseManifest, evidence_dir: Path) -> ZaynorAuthoritativeResult:
        if not manifest.case_id:
            raise AdapterError("frozen case_id must not be empty")
        if not evidence_dir.is_dir() or evidence_dir.is_symlink():
            raise AdapterError("frozen evidence directory is missing or unsafe")
        case_root = evidence_dir.parent
        if case_root.name != manifest.case_id:
            raise AdapterError("evidence directory is not under the manifest case root")

        from zaynor.zaynor_mode1_executor import run_vigia_mode1, translate_mode1_bundle

        output_path = self._output_root / manifest.case_id / "bundle.json"
        try:
            with materialize_frozen_snapshot(manifest, evidence_dir) as snapshot:
                bundle = run_vigia_mode1(
                    vigia_repo_path=self._engine_repo_path,
                    evidence_path=snapshot.path,
                    case_id=manifest.case_id,
                    output_path=output_path,
                    python_executable=self._python_executable,
                    timeout_seconds=self._timeout_seconds,
                    max_output_bytes=self._max_output_bytes,
                    allowed_evidence_root=snapshot.path.parent,
                )
                result = translate_mode1_bundle(manifest.case_id, bundle)
                integrity = dict(result.integrity)
                integrity.update(
                    {
                        "authorized_case_id": manifest.case_id,
                        "authorized_manifest_sha256": snapshot.manifest_sha256,
                        "analyzed_snapshot_sha256": snapshot.snapshot_sha256,
                    }
                )
                return ZaynorAuthoritativeResult(
                    case_id=result.case_id,
                    engine=result.engine,
                    observations=result.observations,
                    timeline=result.timeline,
                    fractures=result.fractures,
                    hypotheses=result.hypotheses,
                    findings=result.findings,
                    unknowns=result.unknowns,
                    provenance=result.provenance,
                    integrity=integrity,
                    audit_refs=result.audit_refs,
                )
        except (OSError, RuntimeError, AdapterError, FrozenSnapshotError) as exc:
            if isinstance(exc, AdapterError):
                raise
            raise AdapterError(f"Mode-1 execution failed for {manifest.case_id}: {exc}") from exc
