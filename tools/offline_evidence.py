"""Shared boundary for bounded, offline evidence importers.

This module stages already-acquired bytes and deterministic observations for
the existing ZAYNOR case freezer.  It does not execute evidence, call a live
target, score observations, or translate them into an authoritative finding.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_FILES = 256
MAX_OBSERVATIONS = 10_000
MAX_PACKAGE_BYTES = 1024 * 1024
MAX_TEXT_LINE_CHARS = 16_384
MAX_VALUE_DEPTH = 32
PROFILE_NAME = "offline-evidence-import"

_SAFE_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SAFE_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class OfflineEvidenceError(ValueError):
    """Raised when an offline evidence package fails closed."""


@dataclass(frozen=True)
class PackageContext:
    """Validated provenance shared by every observation in one package."""

    case_id: str
    module: str
    target: dict[str, str]
    acquisition: dict[str, str]


@dataclass(frozen=True)
class StagedEvidence:
    """A complete staging tree ready for ``freeze_case``."""

    case_id: str
    module: str
    staging_root: Path
    relative_paths: tuple[str, ...]
    observation_count: int
    limitations: tuple[str, ...]
    analysis_status: str = "analysis_unsupported"


def _bounded_string(value: Any, field: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise OfflineEvidenceError(
            f"{field} must be a non-empty string of at most {maximum} characters"
        )
    return value


def _reject_binary_floats(value: Any, field: str = "package") -> None:
    pending = [(value, field, 0)]
    while pending:
        item, item_field, depth = pending.pop()
        if depth > MAX_VALUE_DEPTH:
            raise OfflineEvidenceError(
                f"{item_field} exceeds the maximum nesting depth of {MAX_VALUE_DEPTH}"
            )
        if isinstance(item, float):
            raise OfflineEvidenceError(
                f"{item_field} cannot contain binary floating-point values"
            )
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise OfflineEvidenceError(f"{item_field} object keys must be strings")
                pending.append((child, f"{item_field}.{key}", depth + 1))
        elif isinstance(item, (list, tuple)):
            for index, child in enumerate(item):
                pending.append((child, f"{item_field}[{index}]", depth + 1))


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise OfflineEvidenceError(f"package JSON contains duplicate key: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise OfflineEvidenceError(f"package JSON contains invalid numeric constant: {value}")


def load_package_json(path: Path) -> dict[str, Any]:
    """Load one bounded JSON package without accepting symlinks or duplicate keys."""
    package_path = Path(path)
    if package_path.is_symlink() or not package_path.is_file():
        raise OfflineEvidenceError("package path must be a regular file and cannot be a symlink")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(package_path, flags)
    except OSError as exc:
        raise OfflineEvidenceError("cannot open package JSON") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise OfflineEvidenceError("package path is not a regular file")
        if before.st_size > MAX_PACKAGE_BYTES:
            raise OfflineEvidenceError(
                f"package JSON exceeds the {MAX_PACKAGE_BYTES}-byte limit"
            )
        chunks: list[bytes] = []
        remaining = MAX_PACKAGE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or len(raw) != before.st_size:
        raise OfflineEvidenceError("package JSON changed while being read")
    try:
        decoded = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except OfflineEvidenceError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise OfflineEvidenceError("package must be bounded valid UTF-8 JSON") from exc
    if not isinstance(decoded, dict):
        raise OfflineEvidenceError("package JSON root must be an object")
    _reject_binary_floats(decoded)
    return decoded


def _require_object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OfflineEvidenceError(f"{field} must be an object")
    return value


def _require_exact_keys(value: dict[str, Any], field: str, keys: set[str]) -> None:
    missing = sorted(keys - value.keys())
    unknown = sorted(value.keys() - keys)
    if missing:
        raise OfflineEvidenceError(f"{field} is missing required fields: {', '.join(missing)}")
    if unknown:
        raise OfflineEvidenceError(f"{field} contains unknown fields: {', '.join(unknown)}")


def validate_timestamp(value: Any, field: str) -> str:
    text = _bounded_string(value, field, maximum=64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OfflineEvidenceError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise OfflineEvidenceError(f"{field} must include a timezone")
    return text


def validate_package_context(package: Any, expected_module: str) -> PackageContext:
    """Validate the authority-neutral header shared by both importers."""
    _reject_binary_floats(package)
    root = _require_object(package, "package")
    schema_version = root.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != 1
    ):
        raise OfflineEvidenceError("package.schema_version must be integer 1")
    if root.get("module") != expected_module:
        raise OfflineEvidenceError(f"package.module must be {expected_module!r}")
    case_id = _bounded_string(root.get("case_id"), "package.case_id", maximum=128)
    if not _SAFE_CASE_ID.fullmatch(case_id):
        raise OfflineEvidenceError("package.case_id must be a bounded path-safe identifier")

    target = _require_object(root.get("target"), "package.target")
    _require_exact_keys(target, "package.target", {"os", "release", "arch", "kernel_build"})
    normalized_target = {
        key: _bounded_string(target[key], f"package.target.{key}", maximum=256)
        for key in ("os", "release", "arch", "kernel_build")
    }
    if normalized_target["os"] != "FreeBSD":
        raise OfflineEvidenceError("package.target.os must be 'FreeBSD'")

    acquisition = _require_object(package.get("acquisition"), "package.acquisition")
    _require_exact_keys(
        acquisition,
        "package.acquisition",
        {"acquisition_id", "vantage", "lineage_id", "captured_at", "capture_time_source"},
    )
    normalized_acquisition = {
        "acquisition_id": _bounded_string(
            acquisition["acquisition_id"], "package.acquisition.acquisition_id", maximum=256
        ),
        "vantage": _bounded_string(
            acquisition["vantage"], "package.acquisition.vantage", maximum=128
        ),
        "lineage_id": _bounded_string(
            acquisition["lineage_id"], "package.acquisition.lineage_id", maximum=256
        ),
        "captured_at": validate_timestamp(
            acquisition["captured_at"], "package.acquisition.captured_at"
        ),
        "capture_time_source": _bounded_string(
            acquisition["capture_time_source"],
            "package.acquisition.capture_time_source",
            maximum=256,
        ),
    }
    return PackageContext(case_id, expected_module, normalized_target, normalized_acquisition)


def validate_sha256(value: Any, field: str) -> str:
    digest = _bounded_string(value, field, maximum=64)
    if not _SAFE_SHA256.fullmatch(digest):
        raise OfflineEvidenceError(f"{field} must be a lowercase SHA-256 hex digest")
    return digest


def validate_relative_path(value: Any, field: str) -> str:
    text = _bounded_string(value, field, maximum=1024)
    relative = Path(text)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise OfflineEvidenceError(f"{field} must be a confined relative path")
    if any(part in ("", ".") for part in relative.parts):
        raise OfflineEvidenceError(f"{field} must not contain empty or current-directory segments")
    return relative.as_posix()


def _reject_symlink_components(root: Path, relative: Path) -> None:
    current = root
    if current.is_symlink():
        raise OfflineEvidenceError("source_root cannot be a symlink")
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise OfflineEvidenceError(f"source path contains a symlink: {relative.as_posix()}")


# ``os.open(..., dir_fd=...)`` lets each path component be opened relative to
# the already-open parent directory descriptor, so a component check and its
# open are the same syscall: there is no window between "is this a symlink?"
# and "open it" where a concurrent rename/symlink swap could win a race.
# Falls back to a resolve-then-check (with that race window) only on a
# platform where this is unavailable.
_SUPPORTS_ATOMIC_WALK = (
    os.open in os.supports_dir_fd
    and hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
)


def _raise_for_open_failure(exc: OSError, relative: Path) -> None:
    if exc.errno == errno.ELOOP:
        raise OfflineEvidenceError(
            f"source path contains a symlink: {relative.as_posix()}"
        ) from exc
    raise OfflineEvidenceError(f"cannot open source file: {relative.as_posix()}") from exc


def _open_regular_no_symlinks(root: Path, relative: Path) -> int:
    """Open ``root / relative`` and return a file descriptor to it.

    Every component is opened with ``O_NOFOLLOW`` relative to its already-open
    parent directory, so no symlink anywhere on the path - including a
    component swapped in after validation - can be followed.
    """
    if not _SUPPORTS_ATOMIC_WALK:
        if root.is_symlink():
            raise OfflineEvidenceError("source_root cannot be a symlink")
        resolved_root = root.resolve(strict=True)
        _reject_symlink_components(resolved_root, relative)
        candidate = resolved_root / relative
        resolved = candidate.resolve(strict=True)
        if resolved_root not in resolved.parents:
            raise OfflineEvidenceError("source path escapes source_root")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            return os.open(candidate, flags)
        except OSError as exc:
            _raise_for_open_failure(exc, relative)

    dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        current_fd = os.open(root, dir_flags)
    except OSError as exc:
        raise OfflineEvidenceError("source_root must be a real, non-symlink directory") from exc
    try:
        for part in relative.parts[:-1]:
            try:
                next_fd = os.open(part, dir_flags, dir_fd=current_fd)
            except OSError as exc:
                _raise_for_open_failure(exc, relative)
            os.close(current_fd)
            current_fd = next_fd
        file_flags = os.O_RDONLY | os.O_NOFOLLOW
        try:
            return os.open(relative.parts[-1], file_flags, dir_fd=current_fd)
        except OSError as exc:
            _raise_for_open_failure(exc, relative)
    finally:
        os.close(current_fd)


def read_original(source_root: Path, relative_path: str, expected_sha256: str) -> bytes:
    """Read one regular file once, with bounds and mutation checks."""
    root = Path(source_root)
    relative = Path(validate_relative_path(relative_path, "source_path"))
    descriptor = _open_regular_no_symlinks(root, relative)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise OfflineEvidenceError(f"source is not a regular file: {relative.as_posix()}")
        if before.st_size > MAX_FILE_BYTES:
            raise OfflineEvidenceError(
                f"source exceeds the {MAX_FILE_BYTES}-byte per-file limit: {relative.as_posix()}"
            )
        chunks: list[bytes] = []
        remaining = MAX_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or len(data) != before.st_size:
        raise OfflineEvidenceError(f"source changed while being read: {relative.as_posix()}")
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha256:
        raise OfflineEvidenceError(f"source SHA-256 does not match manifest: {relative.as_posix()}")
    return data


def prepare_staging(staging_root: Path) -> Path:
    root = Path(staging_root)
    if root.exists():
        if root.is_symlink() or not root.is_dir():
            raise OfflineEvidenceError("staging_root must be a directory and cannot be a symlink")
        if any(root.iterdir()):
            raise OfflineEvidenceError("staging_root must be empty")
    else:
        root.mkdir(parents=True)
    return root.resolve(strict=True)


def _safe_staging_path(root: Path, relative_path: str) -> Path:
    relative = Path(validate_relative_path(relative_path, "staged path"))
    candidate = root / relative
    resolved = candidate.resolve(strict=False)
    if root not in resolved.parents:
        raise OfflineEvidenceError("staged path escapes staging_root")
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        if current.exists() and current.is_symlink():
            raise OfflineEvidenceError("staged path contains a symlink")
    return candidate


def write_staged_bytes(root: Path, relative_path: str, data: bytes) -> str:
    if not isinstance(data, bytes):
        raise OfflineEvidenceError("staged evidence must be bytes")
    path = _safe_staging_path(root, relative_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise OfflineEvidenceError(f"duplicate staged path: {relative_path}") from exc
    return Path(relative_path).as_posix()


def canonical_json_bytes(value: Any) -> bytes:
    _reject_binary_floats(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8") + b"\n"


def write_staged_json(root: Path, relative_path: str, value: Any) -> str:
    return write_staged_bytes(root, relative_path, canonical_json_bytes(value))


def observation_source(
    context: PackageContext,
    *,
    manifest_path: str | None,
    sha256: str | None,
) -> dict[str, str | None]:
    return {
        "manifest_path": manifest_path,
        "sha256": sha256,
        "package_manifest_path": f"metadata/{context.module}-input-package.json",
        "acquisition_id": context.acquisition["acquisition_id"],
        "vantage": context.acquisition["vantage"],
        "lineage_id": context.acquisition["lineage_id"],
    }


def make_observation(
    context: PackageContext,
    *,
    observation_id: str,
    kind: str,
    status: str,
    transform_name: str,
    manifest_path: str | None,
    sha256: str | None,
    fields: dict[str, Any],
) -> dict[str, Any]:
    _bounded_string(observation_id, "observation_id", maximum=512)
    _bounded_string(kind, "kind", maximum=128)
    _bounded_string(status, "status", maximum=64)
    _reject_binary_floats(fields, "observation.fields")
    return {
        "schema_version": 1,
        "case_id": context.case_id,
        "observation_id": observation_id,
        "module": context.module,
        "kind": kind,
        "status": status,
        "target": context.target,
        "source": observation_source(
            context, manifest_path=manifest_path, sha256=sha256
        ),
        "transform": {"name": transform_name, "version": "1"},
        "captured_at": context.acquisition["captured_at"],
        "capture_time_source": context.acquisition["capture_time_source"],
        "fields": fields,
    }


def finish_staging(
    context: PackageContext,
    staging_root: Path,
    relative_paths: list[str],
    observations: list[dict[str, Any]],
    limitations: list[str],
    package: dict[str, Any],
) -> StagedEvidence:
    if len(observations) > MAX_OBSERVATIONS:
        raise OfflineEvidenceError(
            f"package exceeds the {MAX_OBSERVATIONS}-observation limit"
        )
    seen_ids: set[str] = set()
    for index, observation in enumerate(observations):
        observation_id = observation["observation_id"]
        if observation_id in seen_ids:
            raise OfflineEvidenceError(f"duplicate observation_id: {observation_id}")
        seen_ids.add(observation_id)
        relative_paths.append(
            write_staged_json(
                staging_root,
                f"observations/{context.module}/{index:06d}.json",
                observation,
            )
        )

    unique_limitations = sorted(set(limitations))
    relative_paths.append(
        write_staged_json(
            staging_root,
            f"metadata/{context.module}-input-package.json",
            package,
        )
    )
    metadata = {
        "schema_version": 1,
        "case_id": context.case_id,
        "module": context.module,
        "analysis_status": "analysis_unsupported",
        "observation_count": len(observations),
        "limitations": unique_limitations,
    }
    relative_paths.append(
        write_staged_json(staging_root, f"metadata/{context.module}.json", metadata)
    )
    return StagedEvidence(
        case_id=context.case_id,
        module=context.module,
        staging_root=staging_root,
        relative_paths=tuple(relative_paths),
        observation_count=len(observations),
        limitations=tuple(unique_limitations),
    )


def combine_staged_evidence(
    staged_items: list[StagedEvidence] | tuple[StagedEvidence, ...], staging_root: Path
) -> StagedEvidence:
    """Combine independently staged modules into one freezeable case.

    Every input must belong to the same case and to a distinct module.  The
    files are copied into a new, empty staging tree and re-read with the same
    symlink, size, and mutation checks used for acquired originals.
    """
    if not staged_items:
        raise OfflineEvidenceError("at least one staged evidence module is required")
    case_ids = {item.case_id for item in staged_items}
    if len(case_ids) != 1:
        raise OfflineEvidenceError("staged evidence modules must belong to the same case_id")
    modules = [item.module for item in staged_items]
    if len(modules) != len(set(modules)):
        raise OfflineEvidenceError("staged evidence modules must be unique")
    observation_count = sum(item.observation_count for item in staged_items)
    if observation_count > MAX_OBSERVATIONS:
        raise OfflineEvidenceError(
            f"combined package exceeds the {MAX_OBSERVATIONS}-observation limit"
        )

    requested_root = Path(staging_root).resolve(strict=False)
    for item in staged_items:
        source_root = item.staging_root.resolve(strict=True)
        if source_root == requested_root or source_root in requested_root.parents:
            raise OfflineEvidenceError(
                "combined staging_root cannot be inside an input staging tree"
            )

    root = prepare_staging(staging_root)
    relative_paths: list[str] = []
    seen_paths: set[str] = set()
    total_bytes = 0
    from zaynor.hash_utils import sha256_file

    for item in staged_items:
        for relative_path in item.relative_paths:
            if relative_path in seen_paths:
                raise OfflineEvidenceError(
                    f"staged modules contain duplicate path: {relative_path}"
                )
            seen_paths.add(relative_path)
            source = item.staging_root / relative_path
            if source.is_symlink() or not source.is_file():
                raise OfflineEvidenceError(f"staged evidence is missing or unsafe: {relative_path}")
            digest = sha256_file(source)
            data = read_original(item.staging_root, relative_path, digest)
            total_bytes += len(data)
            if total_bytes > MAX_TOTAL_BYTES:
                raise OfflineEvidenceError(
                    f"combined package exceeds the {MAX_TOTAL_BYTES}-byte aggregate limit"
                )
            relative_paths.append(write_staged_bytes(root, relative_path, data))

    limitations = tuple(
        sorted({limitation for item in staged_items for limitation in item.limitations})
    )
    return StagedEvidence(
        case_id=next(iter(case_ids)),
        module="offline_evidence_bundle",
        staging_root=root,
        relative_paths=tuple(relative_paths),
        observation_count=observation_count,
        limitations=limitations,
    )


def freeze_staged_evidence(staged: StagedEvidence, cases_root: Path):
    """Freeze originals and derived records through the existing boundary."""
    from zaynor.case_freezer import freeze_case

    return freeze_case(
        staged.case_id,
        PROFILE_NAME,
        {PROFILE_NAME: list(staged.relative_paths)},
        staged.staging_root,
        Path(cases_root),
    )


def run_import_cli(
    importer: Callable[..., StagedEvidence],
    *,
    description: str,
    module_name: str,
    argv: list[str] | None = None,
) -> int:
    """Run one importer through a small, JSON-output command-line boundary."""
    parser = argparse.ArgumentParser(
        prog=f"python3 -m tools.{module_name}", description=description
    )
    parser.add_argument("--package", required=True, type=Path, help="Input package JSON")
    parser.add_argument(
        "--source-root", required=True, type=Path, help="Root containing acquired files"
    )
    parser.add_argument(
        "--staging-root", required=True, type=Path, help="New or empty staging directory"
    )
    parser.add_argument(
        "--cases-root",
        type=Path,
        help="When supplied, freeze the staged package into this cases directory",
    )
    args = parser.parse_args(argv)
    try:
        package = load_package_json(args.package)
        staged = importer(package, args.source_root, args.staging_root)
        frozen = None
        if args.cases_root is not None:
            manifest, evidence_dir = freeze_staged_evidence(staged, args.cases_root)
            frozen = {
                "content_sha256": manifest.content_sha256,
                "entry_count": len(manifest.entries),
                "evidence_dir": str(evidence_dir),
            }
        result = {
            "analysis_status": staged.analysis_status,
            "case_id": staged.case_id,
            "frozen": frozen,
            "limitations": list(staged.limitations),
            "module": staged.module,
            "observation_count": staged.observation_count,
            "staged_file_count": len(staged.relative_paths),
            "staging_root": str(staged.staging_root),
        }
    except (OfflineEvidenceError, OSError) as exc:
        parser.exit(2, f"{module_name}: error: {exc}\n")
    sys.stdout.write(json.dumps(result, sort_keys=True, indent=2) + "\n")
    return 0
