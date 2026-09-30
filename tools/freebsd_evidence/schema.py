"""Strict, versioned input contract for offline FreeBSD evidence."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any

MAX_MANIFEST_BYTES = 1_048_576
MAX_ACQUISITIONS = 8
MAX_ITEMS = 256
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024

KINDS = frozenset(
    {
        "boot_file",
        "kernel_module_file",
        "startup_configuration",
        "system_log",
        "bsm_audit_trail",
        "guest_command_output",
    }
)
UNAVAILABLE_STATES = frozenset({"not_collected", "unreadable", "observed_absent"})
ROLES = frozenset({"baseline", "subject", "auxiliary"})
VANTAGES = frozenset({"external_disk", "guest_report"})
_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ACQUISITION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_LINEAGE_ID = re.compile(r"^lineage:[a-z0-9-]{1,80}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class FreeBSDImportError(ValueError):
    """Acquisition input cannot be safely imported or verified."""


@dataclass(frozen=True)
class Target:
    os: str
    release: str
    arch: str
    kernel_build: str


@dataclass(frozen=True)
class AcquiredFile:
    path: str
    kind: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class UnavailableFile:
    path: str
    kind: str
    status: str
    reason: str
    search_scope: str | None


@dataclass(frozen=True)
class Acquisition:
    acquisition_id: str
    role: str
    vantage: str
    lineage_id: str
    captured_at: str
    capture_time_source: str
    collector: str
    files: tuple[AcquiredFile, ...]
    unavailable: tuple[UnavailableFile, ...]


@dataclass(frozen=True)
class AcquisitionCase:
    case_id: str
    target: Target
    acquisitions: tuple[Acquisition, ...]


def _no_float(value: str) -> Any:
    raise FreeBSDImportError("binary floats and non-finite values are forbidden")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FreeBSDImportError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _object(value: Any, label: str, required: set[str], optional: set[str] | None = None) -> dict:
    if not isinstance(value, dict):
        raise FreeBSDImportError(f"{label} must be an object")
    optional = optional or set()
    missing = required - value.keys()
    extra = value.keys() - required - optional
    if missing or extra:
        raise FreeBSDImportError(
            f"{label} has missing {sorted(missing)} or unknown {sorted(extra)} keys"
        )
    return value


def _text(value: Any, label: str, max_length: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > max_length
        or any(ord(char) < 32 for char in value)
    ):
        raise FreeBSDImportError(f"{label} must be bounded, nonempty text without controls")
    return value


def _relative_path(value: Any, label: str) -> str:
    path = _text(value, label, 240)
    if "\\" in path or path.startswith("/"):
        raise FreeBSDImportError(f"{label} must be a relative POSIX path")
    candidate = PurePosixPath(path)
    if (
        path != candidate.as_posix()
        or not candidate.parts
        or any(part in {".", ".."} for part in candidate.parts)
    ):
        raise FreeBSDImportError(f"{label} must be a canonical relative path")
    return path


def _kind(value: Any) -> str:
    if not isinstance(value, str) or value not in KINDS:
        raise FreeBSDImportError(f"unsupported FreeBSD evidence kind: {value!r}")
    return value


def _timestamp(value: Any) -> str:
    text = _text(value, "captured_at", 64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FreeBSDImportError("captured_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise FreeBSDImportError("captured_at requires an explicit timezone")
    return text


def _file(value: Any) -> AcquiredFile:
    row = _object(value, "file", {"path", "kind", "sha256", "size_bytes"})
    digest = _text(row["sha256"], "file.sha256", 64)
    if not _SHA256.fullmatch(digest):
        raise FreeBSDImportError("file.sha256 must be lowercase SHA-256 hex")
    size = row["size_bytes"]
    if type(size) is not int or not 0 <= size <= MAX_FILE_BYTES:
        raise FreeBSDImportError("file.size_bytes is outside the supported range")
    return AcquiredFile(
        path=_relative_path(row["path"], "file.path"),
        kind=_kind(row["kind"]),
        sha256=digest,
        size_bytes=size,
    )


def _unavailable(value: Any) -> UnavailableFile:
    row = _object(
        value,
        "unavailable entry",
        {"path", "kind", "status", "reason"},
        {"search_scope", "search_complete"},
    )
    status = row["status"]
    if not isinstance(status, str) or status not in UNAVAILABLE_STATES:
        raise FreeBSDImportError(f"invalid unavailable status: {status!r}")
    scope = row.get("search_scope")
    if status == "observed_absent":
        scope = _text(scope, "search_scope", 512)
        if row.get("search_complete") is not True:
            raise FreeBSDImportError("observed_absent requires search_complete=true")
    elif "search_scope" in row or "search_complete" in row:
        raise FreeBSDImportError("search fields are only valid for observed_absent")
    return UnavailableFile(
        path=_relative_path(row["path"], "unavailable.path"),
        kind=_kind(row["kind"]),
        status=status,
        reason=_text(row["reason"], "unavailable.reason", 512),
        search_scope=scope,
    )


def _acquisition(value: Any) -> Acquisition:
    row = _object(
        value,
        "acquisition",
        {
            "acquisition_id",
            "role",
            "vantage",
            "lineage_id",
            "captured_at",
            "capture_time_source",
            "collector",
            "files",
        },
        {"unavailable"},
    )
    acquisition_id = _text(row["acquisition_id"], "acquisition_id", 64)
    if not _ACQUISITION_ID.fullmatch(acquisition_id):
        raise FreeBSDImportError("acquisition_id must be path-safe")
    if (
        not isinstance(row["role"], str)
        or row["role"] not in ROLES
        or not isinstance(row["vantage"], str)
        or row["vantage"] not in VANTAGES
    ):
        raise FreeBSDImportError("acquisition role or vantage is unsupported")
    lineage_id = _text(row["lineage_id"], "lineage_id", 88)
    if not _LINEAGE_ID.fullmatch(lineage_id):
        raise FreeBSDImportError("lineage_id has invalid syntax")
    files = row["files"]
    unavailable = row.get("unavailable", [])
    if not isinstance(files, list) or not isinstance(unavailable, list):
        raise FreeBSDImportError("files and unavailable must be lists")
    if len(files) + len(unavailable) > MAX_ITEMS:
        raise FreeBSDImportError("acquisition has too many entries")
    parsed_files = tuple(_file(item) for item in files)
    parsed_unavailable = tuple(_unavailable(item) for item in unavailable)
    all_paths = [item.path for item in (*parsed_files, *parsed_unavailable)]
    if len(all_paths) != len(set(all_paths)):
        raise FreeBSDImportError("duplicate evidence path in acquisition")
    return Acquisition(
        acquisition_id=acquisition_id,
        role=row["role"],
        vantage=row["vantage"],
        lineage_id=lineage_id,
        captured_at=_timestamp(row["captured_at"]),
        capture_time_source=_text(row["capture_time_source"], "capture_time_source"),
        collector=_text(row["collector"], "collector"),
        files=parsed_files,
        unavailable=parsed_unavailable,
    )


def parse_manifest(raw: bytes) -> AcquisitionCase:
    """Parse one acquisition manifest without lossy or ambiguous JSON values."""
    if len(raw) > MAX_MANIFEST_BYTES:
        raise FreeBSDImportError("acquisition manifest exceeds size limit")
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_float=_no_float,
            parse_constant=_no_float,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise FreeBSDImportError("acquisition manifest is not valid UTF-8 JSON") from exc
    root = _object(document, "manifest", {"schema_version", "case_id", "target", "acquisitions"})
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise FreeBSDImportError("unsupported acquisition schema_version")
    case_id = _text(root["case_id"], "case_id", 128)
    if not _CASE_ID.fullmatch(case_id):
        raise FreeBSDImportError("case_id must be path-safe")
    target = _object(root["target"], "target", {"os", "release", "arch", "kernel_build"})
    if target["os"] != "FreeBSD":
        raise FreeBSDImportError("target.os must be FreeBSD")
    parsed_target = Target(
        os="FreeBSD",
        release=_text(target["release"], "target.release", 80),
        arch=_text(target["arch"], "target.arch", 80),
        kernel_build=_text(target["kernel_build"], "target.kernel_build", 160),
    )
    acquisitions = root["acquisitions"]
    if not isinstance(acquisitions, list) or not 1 <= len(acquisitions) <= MAX_ACQUISITIONS:
        raise FreeBSDImportError("manifest needs one to eight acquisitions")
    parsed_acquisitions = tuple(_acquisition(item) for item in acquisitions)
    ids = [item.acquisition_id for item in parsed_acquisitions]
    if len(ids) != len(set(ids)):
        raise FreeBSDImportError("duplicate acquisition_id")
    item_count = sum(len(item.files) + len(item.unavailable) for item in parsed_acquisitions)
    total_bytes = sum(row.size_bytes for item in parsed_acquisitions for row in item.files)
    if not 1 <= item_count <= MAX_ITEMS or total_bytes > MAX_TOTAL_BYTES:
        raise FreeBSDImportError("case exceeds supported item or byte limits")
    return AcquisitionCase(case_id=case_id, target=parsed_target, acquisitions=parsed_acquisitions)
