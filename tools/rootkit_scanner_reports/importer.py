"""Validate and stage reports produced by upstream rootkit scanners.

Only exact, documented report dialects are parsed.  Unknown versions,
locales, and lines remain frozen and render as ``unknown``; scanner labels
never become ZAYNOR findings in this module.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from tools.offline_evidence import (
    MAX_FILES,
    MAX_OBSERVATIONS,
    MAX_TEXT_LINE_CHARS,
    MAX_TOTAL_BYTES,
    OfflineEvidenceError,
    StagedEvidence,
    finish_staging,
    make_observation,
    prepare_staging,
    read_original,
    validate_package_context,
    validate_relative_path,
    validate_sha256,
    validate_timestamp,
    write_staged_bytes,
)

MODULE = "rootkit_scanner_reports"

_SUPPORTED_DIALECTS = {("chkrootkit", "0.59", "C"), ("rkhunter", "1.4.6", "C")}
_STREAMS = {"stdout", "stderr", "combined"}
_CHKROOTKIT_LINE = re.compile(
    r"^Checking [`'](?P<test>[^`']+)[`']\.\.\. "
    r"(?P<label>INFECTED|not infected|not tested|not found)(?:\s+(?P<detail>.*))?$"
)
_RKHUNTER_LINE = re.compile(
    r"^\s*(?P<test>Checking .+?)\s+\[\s*"
    r"(?P<label>OK|Warning|Not found|None found|Found|Skipped)\s*\]\s*$"
)


def _string(value: Any, field: str, *, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise OfflineEvidenceError(f"{field} must be a non-empty bounded string")
    return value


def _optional_string(value: Any, field: str, *, maximum: int = 1024) -> str | None:
    if value is None:
        return None
    return _string(value, field, maximum=maximum)


def _status(tool: str, label: str) -> str:
    if tool == "chkrootkit":
        return {
            "INFECTED": "reported_alert",
            "not infected": "reported_clear",
            "not tested": "skipped",
            "not found": "skipped",
        }[label]
    return {
        "OK": "reported_clear",
        "Not found": "reported_clear",
        "None found": "reported_clear",
        "Warning": "reported_alert",
        "Found": "reported_alert",
        "Skipped": "skipped",
    }[label]


def _parse_lines(
    context,
    scanner: dict[str, Any],
    report_index: int,
    report: dict[str, Any],
    data: bytes,
    manifest_path: str,
    digest: str,
    pattern: re.Pattern[str],
) -> tuple[list[dict[str, Any]], int, int]:
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return [], 0, 0
    observations: list[dict[str, Any]] = []
    byte_offset = 0
    matched = 0
    oversized = 0
    for line_number, raw_bytes in enumerate(data.splitlines(keepends=True), start=1):
        raw_line = raw_bytes.rstrip(b"\r\n").decode("utf-8")
        if len(raw_line) > MAX_TEXT_LINE_CHARS:
            oversized += 1
            byte_offset += len(raw_bytes)
            continue
        match = pattern.fullmatch(raw_line)
        if match is not None:
            matched += 1
            label = match.group("label")
            fields: dict[str, Any] = {
                "record_type": "scanner_test",
                "tool": scanner["name"],
                "tool_version": scanner["version"],
                "locale": scanner["locale"],
                "stream": report["stream"],
                "test": match.group("test"),
                "tool_reported_label": label,
                "normalized_status": _status(scanner["name"], label),
                "raw_line": raw_line,
                "line_number": line_number,
                "byte_offset": byte_offset,
            }
            if scanner["name"] == "chkrootkit" and match.group("detail"):
                fields["detail"] = match.group("detail")
            observations.append(
                make_observation(
                    context,
                    observation_id=(
                        f"scanner:{report_index:06d}:test:{line_number:06d}"
                    ),
                    kind="scanner_test_result",
                    status=fields["normalized_status"],
                    transform_name=f"{scanner['name']}-report",
                    manifest_path=manifest_path,
                    sha256=digest,
                    fields=fields,
                )
            )
            if len(observations) > MAX_OBSERVATIONS:
                raise OfflineEvidenceError(
                    f"package exceeds the {MAX_OBSERVATIONS}-observation limit"
                )
        byte_offset += len(raw_bytes)
    return observations, matched, oversized


def _validate_scanner(raw: Any) -> tuple[dict[str, Any], list[str]]:
    scanner = raw if isinstance(raw, dict) else None
    if scanner is None:
        raise OfflineEvidenceError("package.scanner must be an object")
    allowed = {
        "name", "version", "locale", "command", "executable_sha256", "exit_status",
        "configuration_sha256", "data_version", "enabled_tests", "properties_database"
    }
    unknown = sorted(scanner.keys() - allowed)
    if unknown:
        raise OfflineEvidenceError(f"package.scanner contains unknown fields: {', '.join(unknown)}")
    name = scanner.get("name")
    if name not in {"chkrootkit", "rkhunter"}:
        raise OfflineEvidenceError("package.scanner.name must be 'chkrootkit' or 'rkhunter'")
    version = _string(scanner.get("version"), "package.scanner.version", maximum=64)
    locale = _string(scanner.get("locale"), "package.scanner.locale", maximum=64)
    command = scanner.get("command")
    if not isinstance(command, list) or not command or len(command) > 64:
        raise OfflineEvidenceError("package.scanner.command must contain 1 to 64 arguments")
    normalized_command = [
        _string(argument, f"package.scanner.command[{index}]", maximum=1024)
        for index, argument in enumerate(command)
    ]
    exit_status = scanner.get("exit_status")
    if exit_status is not None and (
        not isinstance(exit_status, int) or isinstance(exit_status, bool)
    ):
        raise OfflineEvidenceError("package.scanner.exit_status must be an integer or null")
    if exit_status is not None and not -255 <= exit_status <= 255:
        raise OfflineEvidenceError("package.scanner.exit_status must be between -255 and 255")
    enabled_tests = scanner.get("enabled_tests")
    if enabled_tests is not None:
        if not isinstance(enabled_tests, list) or len(enabled_tests) > 1024:
            raise OfflineEvidenceError(
                "package.scanner.enabled_tests must be a bounded list or null"
            )
        enabled_tests = [
            _string(value, f"package.scanner.enabled_tests[{index}]", maximum=256)
            for index, value in enumerate(enabled_tests)
        ]
    properties = scanner.get("properties_database")
    normalized_properties = None
    if properties is not None:
        if not isinstance(properties, dict) or set(properties) != {"sha256", "created_at"}:
            raise OfflineEvidenceError(
                "package.scanner.properties_database requires sha256 and created_at"
            )
        normalized_properties = {
            "sha256": validate_sha256(
                properties["sha256"], "package.scanner.properties_database.sha256"
            ),
            "created_at": validate_timestamp(
                properties["created_at"],
                "package.scanner.properties_database.created_at",
            ),
        }
    normalized = {
        "name": name,
        "version": version,
        "locale": locale,
        "command": normalized_command,
        "executable_sha256": validate_sha256(
            scanner.get("executable_sha256"), "package.scanner.executable_sha256"
        ),
        "exit_status": exit_status,
        "configuration_sha256": (
            validate_sha256(scanner["configuration_sha256"], "package.scanner.configuration_sha256")
            if scanner.get("configuration_sha256") is not None else None
        ),
        "data_version": _optional_string(
            scanner.get("data_version"), "package.scanner.data_version", maximum=256
        ),
        "enabled_tests": enabled_tests,
        "properties_database": normalized_properties,
    }
    limitations: list[str] = []
    for key in ("exit_status", "configuration_sha256", "data_version", "enabled_tests"):
        if normalized[key] is None:
            limitations.append(f"scanner_provenance_missing:{key}")
    if name == "rkhunter" and normalized_properties is None:
        limitations.append("scanner_provenance_missing:properties_database")
    if "--propupd" in normalized_command:
        limitations.append("rkhunter_properties_database_may_have_been_updated_upstream")
    return normalized, limitations


def import_scanner_reports(
    package: dict[str, Any], source_root: Path, staging_root: Path
) -> StagedEvidence:
    """Stage one bounded scanner-run package for the existing freezer."""
    context = validate_package_context(package, MODULE)
    allowed_keys = {
        "schema_version", "module", "case_id", "target", "acquisition", "scanner", "reports"
    }
    unknown = sorted(package.keys() - allowed_keys)
    if unknown:
        raise OfflineEvidenceError(f"package contains unknown fields: {', '.join(unknown)}")
    scanner, limitations = _validate_scanner(package.get("scanner"))
    reports = package.get("reports")
    if not isinstance(reports, list) or not reports or len(reports) > min(MAX_FILES, 8):
        raise OfflineEvidenceError("package.reports must contain 1 to 8 entries")

    root = prepare_staging(staging_root)
    paths: list[str] = []
    observations: list[dict[str, Any]] = []
    limitations.append("vigia_input_contract_not_validated")
    dialect = (scanner["name"], scanner["version"], scanner["locale"])
    supported = dialect in _SUPPORTED_DIALECTS
    if not supported:
        limitations.append(
            f"unsupported_scanner_dialect:{scanner['name']}:"
            f"{scanner['version']}:{scanner['locale']}"
        )
    pattern: re.Pattern[str] | None = None
    if supported:
        pattern = _CHKROOTKIT_LINE if scanner["name"] == "chkrootkit" else _RKHUNTER_LINE

    seen_sources: set[str] = set()
    total_bytes = 0
    for index, raw in enumerate(reports):
        if not isinstance(raw, dict) or set(raw) != {"source_path", "sha256", "stream"}:
            raise OfflineEvidenceError(
                f"package.reports[{index}] requires source_path, sha256, and stream"
            )
        source_path = validate_relative_path(
            raw["source_path"], f"package.reports[{index}].source_path"
        )
        if source_path in seen_sources:
            raise OfflineEvidenceError(f"duplicate source_path: {source_path}")
        seen_sources.add(source_path)
        digest = validate_sha256(raw["sha256"], f"package.reports[{index}].sha256")
        stream = raw["stream"]
        if stream not in _STREAMS:
            raise OfflineEvidenceError(f"package.reports[{index}].stream is unsupported")
        report = {"source_path": source_path, "sha256": digest, "stream": stream}
        data = read_original(source_root, source_path, digest)
        total_bytes += len(data)
        if total_bytes > MAX_TOTAL_BYTES:
            raise OfflineEvidenceError(
                f"package exceeds the {MAX_TOTAL_BYTES}-byte aggregate limit"
            )
        manifest_path = write_staged_bytes(root, f"originals/{MODULE}/{source_path}", data)
        paths.append(manifest_path)

        matched_observations: list[dict[str, Any]] = []
        matched = 0
        oversized = 0
        if pattern is not None:
            matched_observations, matched, oversized = _parse_lines(
                context, scanner, index, report, data, manifest_path, digest, pattern
            )
        observations.extend(matched_observations)
        total_lines = len(data.splitlines())
        if matched == 0:
            limitations.append(f"report_unparsed:{source_path}")
        if oversized:
            limitations.append(f"oversized_text_lines:{source_path}")
        observations.append(
            make_observation(
                context,
                observation_id=f"scanner:{index:06d}:report",
                kind="scanner_report",
                status="observed" if supported and matched else "unknown",
                transform_name="scanner-report-inventory",
                manifest_path=manifest_path,
                sha256=digest,
                fields={
                    "record_type": "report",
                    "tool": scanner["name"],
                    "tool_version": scanner["version"],
                    "locale": scanner["locale"],
                    "stream": stream,
                    "source_path": source_path,
                    "size_bytes": len(data),
                    "line_count": total_lines,
                    "parsed_test_count": matched,
                    "unparsed_line_count": total_lines - matched,
                    "command": scanner["command"],
                    "executable_sha256": scanner["executable_sha256"],
                    "exit_status": scanner["exit_status"],
                    "configuration_sha256": scanner["configuration_sha256"],
                    "data_version": scanner["data_version"],
                    "enabled_tests": scanner["enabled_tests"],
                    "properties_database": scanner["properties_database"],
                },
            )
        )
        if len(observations) > MAX_OBSERVATIONS:
            raise OfflineEvidenceError(
                f"package exceeds the {MAX_OBSERVATIONS}-observation limit"
            )

    return finish_staging(context, root, paths, observations, limitations, package)
