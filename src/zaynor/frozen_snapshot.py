"""Validate a frozen case manifest and materialize a private Mode-1 snapshot."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from zaynor.hash_utils import sha256_file
from zaynor.schemas import CaseManifest

_SAFE_CONTENT_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class FrozenSnapshotError(ValueError):
    """Raised when the case no longer matches its frozen manifest."""


@dataclass(frozen=True)
class FrozenSnapshot:
    path: Path
    manifest_sha256: str
    snapshot_sha256: str


def _manifest_digest(manifest: CaseManifest) -> str:
    digest = hashlib.sha256()
    for relative_path, sha256 in sorted(
        (entry.relative_path, entry.sha256) for entry in manifest.entries
    ):
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(sha256.encode("utf-8"))
        digest.update(b"\x00")
    content_digest = digest.hexdigest()
    if content_digest != manifest.content_sha256:
        raise FrozenSnapshotError("manifest content hash is inconsistent with its entries")
    event_digest = hashlib.sha256(
        f"{manifest.content_sha256}\x00{manifest.sealed_at}".encode("utf-8")
    ).hexdigest()
    if event_digest != manifest.sealed_at_sha256:
        raise FrozenSnapshotError("manifest sealing-event hash is invalid")
    return content_digest


def _inventory(root: Path) -> set[str]:
    files: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise FrozenSnapshotError(f"frozen evidence contains symlink: {path}")
        if path.is_file():
            files.add(path.relative_to(root).as_posix())
        elif not path.is_dir():
            raise FrozenSnapshotError(f"frozen evidence contains non-regular entry: {path}")
    return files


def _validated_entries(manifest: CaseManifest, evidence_dir: Path) -> list[tuple[str, str, int]]:
    if not evidence_dir.is_dir() or evidence_dir.is_symlink():
        raise FrozenSnapshotError("frozen evidence directory is missing or unsafe")
    if len({entry.relative_path for entry in manifest.entries}) != len(manifest.entries):
        raise FrozenSnapshotError("manifest contains duplicate evidence paths")

    expected: list[tuple[str, str, int]] = []
    for entry in manifest.entries:
        relative = Path(entry.relative_path)
        if relative.is_absolute() or ".." in relative.parts or not entry.relative_path:
            raise FrozenSnapshotError("manifest contains an unsafe evidence path")
        path = evidence_dir / relative
        if path.is_symlink() or not path.is_file():
            raise FrozenSnapshotError(f"manifest evidence is missing or unsafe: {entry.relative_path}")
        if path.stat().st_size != entry.size_bytes or sha256_file(path) != entry.sha256:
            raise FrozenSnapshotError(f"frozen evidence does not match manifest: {entry.relative_path}")
        expected.append((entry.relative_path, entry.sha256, entry.size_bytes))

    if _inventory(evidence_dir) != {relative for relative, _, _ in expected}:
        raise FrozenSnapshotError("frozen evidence set does not match manifest")
    return expected


def _snapshot_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise FrozenSnapshotError(f"snapshot contains symlink: {path}")
        if path.is_file():
            digest.update(path.relative_to(root).as_posix().encode("utf-8"))
            digest.update(bytes.fromhex(sha256_file(path)))
    return digest.hexdigest()


@contextmanager
def materialize_frozen_snapshot(manifest: CaseManifest, evidence_dir: Path):
    """Yield a private, manifest-validated snapshot for the executor.

    The executor never receives the live case evidence. Each copied byte is
    checked against the manifest before execution; later mutations of the
    original case cannot change the bytes being analyzed.

    The snapshot directory name is content-addressed
    (`.zaynor_snapshot_<manifest.content_sha256>`), not a random `tempfile`
    suffix. Confirmed by induction (external audit, then reproduced here):
    a random suffix leaks into VIGÍA's own sealed result. ZAYNOR points
    `VIGIA_EVIDENCE_DIR`/`VIGIA_ALLOWED_REGISTRY_PATHS`/
    `VIGIA_ALLOWED_DUMP_PATHS` at this directory, and VIGÍA's
    `runtime_execution_fingerprint` (vigia-repo, `vigia/core/
    runtime_fingerprint.py`) hashes every `VIGIA_*` environment variable
    into `engine.configuration_hash` — by design, since values like
    `VIGIA_EBS_RESOLVE` genuinely affect the deterministic computation and
    should be fingerprinted. A randomized path is not one of those: it
    carries no decision-relevant information, only a different value on
    every run of the identical frozen case, which the fingerprint then
    faithfully (and correctly, per its own contract) propagates into a
    different seal every time — violating CLAUDE.md §5.2's bit-for-bit
    reproducibility requirement without any evidence, decision, or
    configuration actually differing. Not a change to vigia-repo (AGENTS.md
    §2.1: integrate, never modify VIGÍA) — the fix is entirely on ZAYNOR's
    side of the environment variables it constructs. A collision (another
    process already materializing a snapshot for the same manifest
    content, or a snapshot left behind by a crashed prior run) fails
    closed rather than silently reusing or overwriting a directory this
    process did not itself just create.
    """
    expected = _validated_entries(manifest, evidence_dir)
    case_root = evidence_dir.parent
    if case_root.is_symlink() or not case_root.is_dir():
        raise FrozenSnapshotError("case root is missing or unsafe")
    if not _SAFE_CONTENT_SHA256.fullmatch(manifest.content_sha256):
        raise FrozenSnapshotError("manifest content_sha256 is not a valid hex digest")

    temporary = case_root / f".zaynor_snapshot_{manifest.content_sha256}"
    try:
        temporary.mkdir()
    except FileExistsError as exc:
        raise FrozenSnapshotError(
            f"a snapshot directory already exists for this case content: {temporary} "
            "— a concurrent analyze is in progress, or one crashed without cleaning up; "
            "remove it before retrying"
        ) from exc
    try:
        snapshot = temporary / "evidence"
        snapshot.mkdir()
        for relative, expected_hash, expected_size in expected:
            source = evidence_dir / relative
            destination = snapshot / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            with source.open("rb") as source_handle, destination.open("wb") as destination_handle:
                while chunk := source_handle.read(1024 * 1024):
                    digest.update(chunk)
                    destination_handle.write(chunk)
                destination_handle.flush()
                os.fsync(destination_handle.fileno())
            if digest.hexdigest() != expected_hash or destination.stat().st_size != expected_size:
                raise FrozenSnapshotError(f"evidence changed while snapshotting: {relative}")
            destination.chmod(0o400)

        # Files added or removed while copying are outside the authorized set;
        # fail closed rather than silently analyzing a partial case.
        _validated_entries(manifest, evidence_dir)
        yield FrozenSnapshot(
            path=snapshot,
            manifest_sha256=_manifest_digest(manifest),
            snapshot_sha256=_snapshot_digest(snapshot),
        )
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
