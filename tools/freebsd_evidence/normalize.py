"""Deterministic, non-diagnostic observations from acquired FreeBSD files."""

from __future__ import annotations

import re
from dataclasses import asdict
from typing import Any

from tools.freebsd_evidence.schema import (
    Acquisition,
    AcquisitionCase,
    AcquiredFile,
    UnavailableFile,
)

_TRANSFORM_VERSION = "1"
_MAX_CONFIG_TEXT_BYTES = 1_048_576
_MAX_CONFIG_LINES = 4096
_MAX_CONFIG_LINE_LENGTH = 16_384
_ASSIGNMENT = re.compile(r"^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.*)$")


def _base(
    case: AcquisitionCase,
    acquisition: Acquisition,
    *,
    index: int,
    kind: str,
    status: str,
    manifest_path: str,
    sha256: str,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "case_id": case.case_id,
        "observation_id": f"freebsd:{index:06d}",
        "module": "freebsd_evidence",
        "kind": kind,
        "status": status,
        "target": asdict(case.target),
        "acquisition": {
            "id": acquisition.acquisition_id,
            "role": acquisition.role,
            "collector": acquisition.collector,
        },
        "source": {
            "manifest_path": manifest_path,
            "sha256": sha256,
            "acquisition_id": acquisition.acquisition_id,
            "vantage": acquisition.vantage,
            "lineage_id": acquisition.lineage_id,
        },
        "transform": {"name": "freebsd-evidence-normalizer", "version": _TRANSFORM_VERSION},
        "captured_at": acquisition.captured_at,
        "capture_time_source": acquisition.capture_time_source,
    }


def _configuration_fields(data: bytes) -> tuple[str, dict[str, Any]]:
    fields: dict[str, Any] = {"size_bytes": len(data), "interpretation": "literal_assignments_only"}
    if len(data) > _MAX_CONFIG_TEXT_BYTES:
        fields["parse_error"] = "configuration exceeds parser limit"
        return "parse_failed", fields
    try:
        content = data.decode("utf-8")
    except UnicodeDecodeError:
        fields["parse_error"] = "configuration is not UTF-8"
        return "parse_failed", fields
    lines = content.splitlines()
    if len(lines) > _MAX_CONFIG_LINES or any(len(line) > _MAX_CONFIG_LINE_LENGTH for line in lines):
        fields["parse_error"] = "configuration exceeds line limit"
        return "parse_failed", fields
    assignments: list[dict[str, Any]] = []
    unparsed_lines: list[int] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _ASSIGNMENT.fullmatch(line)
        if match is None:
            unparsed_lines.append(number)
            continue
        assignments.append({"line": number, "key": match.group(1), "raw_value": match.group(2)})
    fields["line_count"] = len(lines)
    fields["assignments"] = assignments
    fields["unparsed_line_numbers"] = unparsed_lines
    return "observed", fields


def normalize_file(
    case: AcquisitionCase,
    acquisition: Acquisition,
    item: AcquiredFile,
    data: bytes,
    *,
    index: int,
) -> dict[str, Any]:
    """Describe preserved bytes without interpreting them as rootkit evidence."""
    source_path = f"originals/{acquisition.acquisition_id}/{item.path}"
    status = "observed"
    fields: dict[str, Any] = {"relative_path": item.path, "size_bytes": len(data)}
    if item.kind == "startup_configuration":
        status, parsed = _configuration_fields(data)
        fields.update(parsed)
    elif item.kind in {"system_log", "guest_command_output"}:
        fields["line_count"] = data.count(b"\n") + int(bool(data) and not data.endswith(b"\n"))
        fields["interpretation"] = "metadata_only"
    else:
        fields["interpretation"] = "metadata_only"
    observation = _base(
        case,
        acquisition,
        index=index,
        kind=item.kind,
        status=status,
        manifest_path=source_path,
        sha256=item.sha256,
    )
    observation["fields"] = fields
    return observation


def normalize_unavailable(
    case: AcquisitionCase,
    acquisition: Acquisition,
    item: UnavailableFile,
    *,
    index: int,
    acquisition_manifest_sha256: str,
) -> dict[str, Any]:
    """Preserve a collector's declared gap without turning it into absence proof."""
    observation = _base(
        case,
        acquisition,
        index=index,
        kind=item.kind,
        status=item.status,
        manifest_path="metadata/acquisition-manifest.json",
        sha256=acquisition_manifest_sha256,
    )
    fields: dict[str, Any] = {"relative_path": item.path, "reason": item.reason}
    if item.search_scope is not None:
        fields["search_scope"] = item.search_scope
        fields["search_complete_reported"] = True
    observation["fields"] = fields
    return observation
