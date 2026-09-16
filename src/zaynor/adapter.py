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
