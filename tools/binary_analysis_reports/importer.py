"""Validate and stage reports produced by an upstream binary-analysis pipeline.

Deep analysis — disassembly, control-flow recovery, binary instrumentation,
taint tracking, symbolic execution (PBA ch. 6-13) — never runs inside
ZAYNOR (ADR-0003). It runs in a separate, isolated pipeline, and this module
imports that pipeline's *output* as frozen evidence, the integration shape
ADR-0003 names as its revisit trigger. The pattern mirrors
``rootkit_scanner_reports``: raw reports are preserved byte for byte, only
one exact report format is normalized, every result is recorded as
``tool_reported``, and nothing here becomes a ZAYNOR finding (ADR-0005).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from tools.offline_evidence import (
    MAX_FILES,
    MAX_OBSERVATIONS,
    MAX_TOTAL_BYTES,
    SUPPORTED_TARGET_OS,
    OfflineEvidenceError,
    StagedEvidence,
    _reject_binary_floats,
    _reject_json_constant,
    _unique_json_object,
    finish_staging,
    make_observation,
    prepare_staging,
    read_original,
    validate_package_context,
    validate_relative_path,
    validate_sha256,
    write_staged_bytes,
)

MODULE = "binary_analysis_reports"
REPORT_FORMAT = "zaynor-binary-analysis-report/1"

MAX_REPORTS = 64
MAX_RESULTS_PER_REPORT = 4096
MAX_ATTRIBUTE_DEPTH = 4
MAX_ATTRIBUTE_ITEMS = 64
MAX_ATTRIBUTE_TEXT = 1024
MAX_LABEL_CHARS = 256

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_RECORD_TYPE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ATTRIBUTE_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
_EXECUTION_MODES = {"static", "dynamic"}
_ISOLATION = {"disposable_vm", "container", "none"}
_NETWORK = {"disabled", "enabled", "unknown"}
_LOCATION_SPACES = {"vaddr", "rva", "file_offset"}
_ANALYZER_KEYS = {
    "name", "version", "executable_sha256", "configuration_sha256", "command",
    "execution_mode", "environment",
}
_REPORT_ENTRY_KEYS = {"source_path", "sha256", "subject_sha256", "subject_logical_path"}
_RESULT_KEYS = {"record_type", "label", "location", "attributes"}


class _ReportRejected(ValueError):
    """Report content is unusable; the raw bytes stay frozen as evidence."""


def _string(value: Any, field: str, *, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise OfflineEvidenceError(f"{field} must be a non-empty bounded string")
    return value


def _validate_analyzer(raw: Any) -> tuple[dict[str, Any], list[str]]:
    if not isinstance(raw, dict) or set(raw) != _ANALYZER_KEYS:
        raise OfflineEvidenceError(
            "package.analyzer requires name, version, executable_sha256, "
            "configuration_sha256, command, execution_mode and environment"
        )
    name = _string(raw["name"], "package.analyzer.name", maximum=64)
    if not _IDENTIFIER.fullmatch(name):
        raise OfflineEvidenceError("package.analyzer.name must be a bounded identifier")
    command = raw["command"]
    if not isinstance(command, list) or not command or len(command) > 64:
        raise OfflineEvidenceError("package.analyzer.command must contain 1 to 64 arguments")
    execution_mode = raw["execution_mode"]
    if execution_mode not in _EXECUTION_MODES:
        raise OfflineEvidenceError("package.analyzer.execution_mode must be static or dynamic")
    environment = raw["environment"]
    if not isinstance(environment, dict) or set(environment) != {
        "isolation", "network", "environment_id"
    }:
        raise OfflineEvidenceError(
            "package.analyzer.environment requires isolation, network and environment_id"
        )
    if environment["isolation"] not in _ISOLATION:
        raise OfflineEvidenceError("package.analyzer.environment.isolation is unsupported")
    if environment["network"] not in _NETWORK:
        raise OfflineEvidenceError("package.analyzer.environment.network is unsupported")
    analyzer = {
        "name": name,
        "version": _string(raw["version"], "package.analyzer.version", maximum=64),
        "executable_sha256": validate_sha256(
            raw["executable_sha256"], "package.analyzer.executable_sha256"
        ),
        "configuration_sha256": (
            validate_sha256(raw["configuration_sha256"], "package.analyzer.configuration_sha256")
            if raw["configuration_sha256"] is not None
            else None
        ),
        "command": [
            _string(argument, f"package.analyzer.command[{index}]")
            for index, argument in enumerate(command)
        ],
        "execution_mode": execution_mode,
        "environment": {
            "isolation": environment["isolation"],
            "network": environment["network"],
            "environment_id": _string(
                environment["environment_id"],
                "package.analyzer.environment.environment_id",
                maximum=256,
            ),
        },
    }
    limitations: list[str] = []
    if analyzer["configuration_sha256"] is None:
        limitations.append("analyzer_provenance_missing:configuration_sha256")
    if execution_mode == "dynamic":
        limitations.append("subject_executed_upstream")
        if analyzer["environment"]["isolation"] == "none":
            limitations.append("subject_executed_without_declared_isolation")
    return analyzer, limitations


def _parse_report(data: bytes) -> dict[str, Any]:
    """Strict JSON with the same rules as package loading, but non-fatal."""
    try:
        decoded = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (OfflineEvidenceError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise _ReportRejected("invalid_json") from exc
    if not isinstance(decoded, dict):
        raise _ReportRejected("report_root_not_object")
    try:
        _reject_binary_floats(decoded, "report")
    except OfflineEvidenceError as exc:
        raise _ReportRejected("floating_point_or_excessive_depth") from exc
    return decoded


def _check_attributes(value: Any, depth: int) -> None:
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, str):
        if len(value) > MAX_ATTRIBUTE_TEXT:
            raise _ReportRejected("attribute_text_too_long")
        return
    if depth >= MAX_ATTRIBUTE_DEPTH:
        raise _ReportRejected("attribute_nesting_too_deep")
    if isinstance(value, list):
        if len(value) > MAX_ATTRIBUTE_ITEMS:
            raise _ReportRejected("attribute_list_too_long")
        for item in value:
            _check_attributes(item, depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > MAX_ATTRIBUTE_ITEMS:
            raise _ReportRejected("attribute_object_too_large")
        for key, item in value.items():
            if not _ATTRIBUTE_KEY.fullmatch(key):
                raise _ReportRejected("attribute_key_invalid")
            _check_attributes(item, depth + 1)
        return
    raise _ReportRejected("attribute_type_unsupported")


def _validate_results(results: Any) -> list[dict[str, Any]]:
    if not isinstance(results, list):
        raise _ReportRejected("results_not_list")
    if len(results) > MAX_RESULTS_PER_REPORT:
        raise _ReportRejected("results_exceed_limit")
    validated: list[dict[str, Any]] = []
    for result in results:
        if not isinstance(result, dict) or set(result) != _RESULT_KEYS:
            raise _ReportRejected("result_shape_invalid")
        record_type = result["record_type"]
        if not isinstance(record_type, str) or not _RECORD_TYPE.fullmatch(record_type):
            raise _ReportRejected("result_record_type_invalid")
        label = result["label"]
        if label is not None and (
            not isinstance(label, str) or not label or len(label) > MAX_LABEL_CHARS
        ):
            raise _ReportRejected("result_label_invalid")
        location = result["location"]
        if location is not None:
            if (
                not isinstance(location, dict)
                or set(location) != {"space", "value"}
                or location["space"] not in _LOCATION_SPACES
                or not isinstance(location["value"], int)
                or isinstance(location["value"], bool)
                or location["value"] < 0
            ):
                raise _ReportRejected("result_location_invalid")
        attributes = result["attributes"]
        if not isinstance(attributes, dict):
            raise _ReportRejected("result_attributes_not_object")
        _check_attributes(attributes, 0)
        validated.append(result)
    return validated


def import_analysis_reports(
    package: dict[str, Any], source_root: Path, staging_root: Path
) -> StagedEvidence:
    """Stage one bounded upstream-analysis package for the existing freezer."""
    context = validate_package_context(package, MODULE, allowed_os=SUPPORTED_TARGET_OS)
    allowed_keys = {
        "schema_version", "module", "case_id", "target", "acquisition", "analyzer", "reports"
    }
    unknown = sorted(package.keys() - allowed_keys)
    if unknown:
        raise OfflineEvidenceError(f"package contains unknown fields: {', '.join(unknown)}")
    analyzer, limitations = _validate_analyzer(package.get("analyzer"))
    reports = package.get("reports")
    if not isinstance(reports, list) or not reports or len(reports) > min(MAX_FILES, MAX_REPORTS):
        raise OfflineEvidenceError(f"package.reports must contain 1 to {MAX_REPORTS} entries")

    root = prepare_staging(staging_root)
    paths: list[str] = []
    observations: list[dict[str, Any]] = []
    limitations.extend(
        [
            "vigia_input_contract_not_validated",
            "upstream_analysis_not_reproduced_by_zaynor",
            "upstream_environment_declared_not_verified",
            "analysis_does_not_establish_independent_acquisition",
        ]
    )
    seen_sources: set[str] = set()
    total_bytes = 0

    for index, raw in enumerate(reports):
        if not isinstance(raw, dict) or set(raw) != _REPORT_ENTRY_KEYS:
            raise OfflineEvidenceError(
                f"package.reports[{index}] requires source_path, sha256, subject_sha256 "
                "and subject_logical_path"
            )
        source_path = validate_relative_path(
            raw["source_path"], f"package.reports[{index}].source_path"
        )
        if source_path in seen_sources:
            raise OfflineEvidenceError(f"duplicate source_path: {source_path}")
        seen_sources.add(source_path)
        digest = validate_sha256(raw["sha256"], f"package.reports[{index}].sha256")
        subject_sha256 = validate_sha256(
            raw["subject_sha256"], f"package.reports[{index}].subject_sha256"
        )
        subject_logical_path = _string(
            raw["subject_logical_path"], f"package.reports[{index}].subject_logical_path"
        )
        data = read_original(source_root, source_path, digest)
        total_bytes += len(data)
        if total_bytes > MAX_TOTAL_BYTES:
            raise OfflineEvidenceError(
                f"package exceeds the {MAX_TOTAL_BYTES}-byte aggregate limit"
            )
        manifest_path = write_staged_bytes(root, f"originals/{MODULE}/{source_path}", data)
        paths.append(manifest_path)

        status = "observed"
        rejection: str | None = None
        report_format: str | None = None
        results: list[dict[str, Any]] = []
        try:
            report = _parse_report(data)
            report_format = report.get("format") if isinstance(report.get("format"), str) else None
            if report_format != REPORT_FORMAT:
                status, rejection = "unknown", "unsupported_report_format"
            elif set(report) != {"format", "analyzer", "subject_sha256", "results"}:
                raise _ReportRejected("report_shape_invalid")
            elif report["analyzer"] != {"name": analyzer["name"], "version": analyzer["version"]}:
                status, rejection = "unknown", "report_analyzer_mismatch"
            elif report["subject_sha256"] != subject_sha256:
                status, rejection = "unknown", "report_subject_mismatch"
            else:
                results = _validate_results(report["results"])
        except _ReportRejected as exc:
            status, rejection, results = "parse_failed", str(exc), []
        if rejection is not None:
            prefix = "report_parse_failed" if status == "parse_failed" else rejection
            limitations.append(f"{prefix}:{source_path}")

        observations.append(
            make_observation(
                context,
                observation_id=f"analysis:{index:06d}:report",
                kind="analysis_report",
                status=status,
                transform_name="binary-analysis-report-inventory",
                manifest_path=manifest_path,
                sha256=digest,
                fields={
                    "record_type": "analysis_report",
                    "source_path": source_path,
                    "report_format": report_format,
                    "subject_sha256": subject_sha256,
                    "subject_logical_path": subject_logical_path,
                    "analyzer": analyzer,
                    "size_bytes": len(data),
                    "result_count": len(results),
                    "rejection_reason": rejection,
                },
            )
        )
        for result_index, result in enumerate(results):
            observations.append(
                make_observation(
                    context,
                    observation_id=f"analysis:{index:06d}:result:{result_index:06d}",
                    kind="analysis_result",
                    status="tool_reported",
                    transform_name="binary-analysis-report-v1",
                    manifest_path=manifest_path,
                    sha256=digest,
                    fields={
                        "record_type": "analysis_result",
                        "result_index": result_index,
                        "result_type": result["record_type"],
                        "tool_reported_label": result["label"],
                        "location": result["location"],
                        "attributes": result["attributes"],
                        "analyzer_name": analyzer["name"],
                        "analyzer_version": analyzer["version"],
                        "execution_mode": analyzer["execution_mode"],
                        "subject_sha256": subject_sha256,
                    },
                )
            )
        if len(observations) > MAX_OBSERVATIONS:
            raise OfflineEvidenceError(
                f"package exceeds the {MAX_OBSERVATIONS}-observation limit"
            )

    return finish_staging(context, root, paths, observations, limitations, package)
