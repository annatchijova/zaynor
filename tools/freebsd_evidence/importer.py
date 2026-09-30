"""Stage acquired FreeBSD bytes and freeze them through ZAYNOR's case freezer."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from zaynor.case_freezer import freeze_case
from zaynor.hash_utils import sha256_file
from zaynor.schemas import CaseManifest

from tools.freebsd_evidence.normalize import normalize_file, normalize_unavailable
from tools.freebsd_evidence.schema import (
    MAX_FILE_BYTES,
    MAX_MANIFEST_BYTES,
    AcquisitionCase,
    FreeBSDImportError,
    parse_manifest,
)

_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_PROFILE = "freebsd-evidence"


@dataclass(frozen=True)
class FreeBSDImportResult:
    """A frozen case, with no implied FreeBSD rootkit verdict."""

    manifest: CaseManifest
    evidence_dir: Path
    original_count: int
    observation_count: int
    analysis_status: str = "analysis_unsupported"


def _read_bounded(fd: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining:
        chunk = os.read(fd, min(remaining, 1024 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) > limit:
        raise FreeBSDImportError("source file exceeds the supported size limit")
    return data


def _read_manifest_file(path: Path) -> bytes:
    try:
        fd = os.open(path, _READ_FLAGS)
    except OSError as exc:
        raise FreeBSDImportError(f"cannot open acquisition manifest: {exc.strerror}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise FreeBSDImportError("acquisition manifest must be a regular file")
        data = _read_bounded(fd, MAX_MANIFEST_BYTES)
        after = os.fstat(fd)
        if (
            before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise FreeBSDImportError("acquisition manifest changed during import")
        return data
    finally:
        os.close(fd)


def _read_acquired_file(root_fd: int, relative_path: str) -> bytes:
    """Open every path component relative to the pinned source directory fd."""
    parts = PurePosixPath(relative_path).parts
    opened_dirs: list[int] = []
    directory_fd = root_fd
    try:
        for part in parts[:-1]:
            directory_fd = os.open(part, _DIRECTORY_FLAGS, dir_fd=directory_fd)
            opened_dirs.append(directory_fd)
        file_fd = os.open(parts[-1], _READ_FLAGS, dir_fd=directory_fd)
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode):
                raise FreeBSDImportError("acquired source must be a regular file")
            data = _read_bounded(file_fd, MAX_FILE_BYTES)
            after = os.fstat(file_fd)
            if (
                before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ctime_ns != after.st_ctime_ns
            ):
                raise FreeBSDImportError("acquired source changed during import")
            return data
        finally:
            os.close(file_fd)
    except OSError as exc:
        raise FreeBSDImportError(
            f"cannot read acquired source {relative_path}: {exc.strerror}"
        ) from exc
    finally:
        for fd in reversed(opened_dirs):
            os.close(fd)


def _stage_bytes(root: Path, relative_path: str, data: bytes) -> None:
    destination = root / relative_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as output:
        output.write(data)


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
    )


def _stage_case(
    case: AcquisitionCase, raw_manifest: bytes, root_fd: int, stage: Path
) -> tuple[list[str], int, int]:
    manifest_sha256 = hashlib.sha256(raw_manifest).hexdigest()
    _stage_bytes(stage, "metadata/acquisition-manifest.json", raw_manifest)
    profile = ["metadata/acquisition-manifest.json"]
    observations: list[dict] = []
    original_count = 0
    for acquisition in sorted(case.acquisitions, key=lambda item: item.acquisition_id):
        for item in sorted(acquisition.files, key=lambda row: row.path):
            source_path = f"{acquisition.acquisition_id}/{item.path}"
            data = _read_acquired_file(root_fd, source_path)
            if len(data) != item.size_bytes or hashlib.sha256(data).hexdigest() != item.sha256:
                raise FreeBSDImportError(f"size or SHA-256 mismatch for {source_path}")
            staged_path = f"originals/{source_path}"
            _stage_bytes(stage, staged_path, data)
            if hashlib.sha256((stage / staged_path).read_bytes()).hexdigest() != item.sha256:
                raise FreeBSDImportError(f"staged copy changed for {source_path}")
            profile.append(staged_path)
            original_count += 1
            observations.append(
                normalize_file(case, acquisition, item, data, index=len(observations) + 1)
            )
        for item in sorted(acquisition.unavailable, key=lambda row: row.path):
            observations.append(
                normalize_unavailable(
                    case,
                    acquisition,
                    item,
                    index=len(observations) + 1,
                    acquisition_manifest_sha256=manifest_sha256,
                )
            )
    _stage_bytes(stage, "observations/freebsd.json", _json_bytes(observations))
    profile.append("observations/freebsd.json")
    _stage_bytes(
        stage,
        "metadata/freebsd-import-status.json",
        _json_bytes(
            {
                "schema_version": 1,
                "case_id": case.case_id,
                "module": "freebsd_evidence",
                "analysis_status": "analysis_unsupported",
                "reason": "No validated FreeBSD-to-VIGIA rootkit analysis contract is available",
            }
        ),
    )
    profile.append("metadata/freebsd-import-status.json")
    return profile, original_count, len(observations)


def _discard_generated_case(case_dir: Path) -> None:
    """Remove only a case directory reserved by this import after failure."""
    if not case_dir.exists():
        return
    for path in sorted(case_dir.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if path.is_dir():
            path.chmod(0o700)
    case_dir.chmod(0o700)
    shutil.rmtree(case_dir)


def import_freebsd_case(
    acquisition_manifest: Path,
    source_root: Path,
    cases_root: Path,
) -> FreeBSDImportResult:
    """Import bounded original files and freeze them with derived observations.

    The input manifest names files under ``source_root/<acquisition_id>/``.
    Imported content is data only; this function does not invoke VIGÍA or
    execute any guest content.
    """
    raw_manifest = _read_manifest_file(Path(acquisition_manifest))
    case = parse_manifest(raw_manifest)
    source_root = Path(source_root)
    if source_root.is_symlink() or not source_root.is_dir():
        raise FreeBSDImportError("source_root must be a real directory")
    cases_root = Path(cases_root)
    if cases_root.is_symlink():
        raise FreeBSDImportError("cases_root cannot be a symlink")
    cases_root.mkdir(parents=True, exist_ok=True)
    if not cases_root.is_dir():
        raise FreeBSDImportError("cases_root must be a directory")
    case_dir = cases_root / case.case_id
    if case_dir.exists() or case_dir.is_symlink():
        raise FreeBSDImportError("case_id already exists; refusing to overwrite a case")

    try:
        root_fd = os.open(source_root, _DIRECTORY_FLAGS)
    except OSError as exc:
        raise FreeBSDImportError(f"cannot open source_root: {exc.strerror}") from exc
    try:
        with tempfile.TemporaryDirectory(prefix=".freebsd-stage-", dir=cases_root) as temp:
            profile, original_count, observation_count = _stage_case(
                case, raw_manifest, root_fd, Path(temp)
            )
            try:
                case_dir.mkdir(mode=0o700)
            except FileExistsError as exc:
                raise FreeBSDImportError("case_id was created concurrently") from exc
            try:
                manifest, evidence_dir = freeze_case(
                    case.case_id,
                    _PROFILE,
                    {_PROFILE: profile},
                    Path(temp),
                    cases_root,
                )
                entries = {entry.relative_path: entry for entry in manifest.entries}
                if len(entries) != len(profile) or set(entries) != set(profile):
                    raise FreeBSDImportError("frozen manifest does not match staged evidence")
                if any(
                    sha256_file(evidence_dir / path) != entry.sha256
                    for path, entry in entries.items()
                ):
                    raise FreeBSDImportError("frozen evidence failed integrity verification")
            except Exception:
                _discard_generated_case(case_dir)
                raise
    finally:
        os.close(root_fd)
    return FreeBSDImportResult(
        manifest=manifest,
        evidence_dir=evidence_dir,
        original_count=original_count,
        observation_count=observation_count,
    )
