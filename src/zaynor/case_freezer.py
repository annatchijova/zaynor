"""Stage 4: the case-freeze boundary.

Selects the evidence files listed for a case's evidence profile, hashes
each one, writes an immutable manifest, and records a custody entry per
artifact. Everything after this point (stage 5+) reads only from the
frozen `evidence/` copy through `PathGuard` — never from the scenario's
source directory. See AGENTS.md "The case-freeze boundary".
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from zaynor.custody import ChainOfCustody
from zaynor.hash_utils import sha256_file
from zaynor.schemas import CaseManifest, ManifestEntry

_SAFE_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _confined_relative_path(source_root: Path, relative_path: str) -> Path:
    if not isinstance(relative_path, str):
        raise ValueError("evidence paths must be strings")
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("evidence paths must be relative and cannot contain '..'")
    root = source_root.resolve(strict=True)
    candidate = (root / relative).resolve(strict=False)
    if root not in candidate.parents:
        raise ValueError("evidence path escapes source_root")
    return relative


def freeze_case(
    case_id: str,
    evidence_profile: str,
    profile_map: dict[str, list[str]],
    source_root: Path,
    cases_root: Path,
) -> tuple[CaseManifest, Path]:
    """Copy the files listed under `evidence_profile` in `profile_map`
    (paths relative to `source_root`) into
    `cases_root/<case_id>/evidence/`, hash each one, and write
    `manifest.json` + `custody.json` next to it.

    Raises `KeyError` if `evidence_profile` is not in `profile_map`, and
    `FileNotFoundError` if a listed source file does not exist — freezing
    a case with missing evidence must fail loudly, not silently produce a
    partial manifest.
    """
    if evidence_profile not in profile_map:
        raise KeyError(f"unknown evidence_profile: {evidence_profile}")
    if not isinstance(case_id, str) or not _SAFE_CASE_ID.fullmatch(case_id):
        raise ValueError("case_id must be a bounded path-safe identifier")

    case_dir = cases_root / case_id
    evidence_dir = case_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    custody = ChainOfCustody(case_id=case_id)
    entries: list[ManifestEntry] = []

    for relative_path in profile_map[evidence_profile]:
        relative_path = _confined_relative_path(source_root, relative_path).as_posix()
        source_path = source_root / relative_path
        if source_path.is_symlink() or not source_path.is_file():
            raise FileNotFoundError(f"evidence file not found: {source_path}")

        dest_path = evidence_dir / relative_path
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, dest_path)

        digest = sha256_file(dest_path)
        entries.append(
            ManifestEntry(
                relative_path=relative_path,
                sha256=digest,
                size_bytes=dest_path.stat().st_size,
            )
        )
        custody.add_record("FREEZE_COPY", artifact_hash=digest, metadata={"relative_path": relative_path})

    manifest = CaseManifest(case_id=case_id, entries=tuple(entries))

    manifest_path = case_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "case_id": manifest.case_id,
                "entries": [
                    {"relative_path": e.relative_path, "sha256": e.sha256, "size_bytes": e.size_bytes}
                    for e in manifest.entries
                ],
            },
            sort_keys=True,
            indent=2,
        ),
        encoding="utf-8",
    )

    custody_path = case_dir / "custody.json"
    custody_path.write_text(
        json.dumps(custody.export_for_manifest(), sort_keys=True, indent=2), encoding="utf-8"
    )

    # Close the evidence tree to further writes from this process: every
    # frozen file becomes read-only. This does not stop a privileged actor
    # outside the process, but it does stop this codebase's own tools from
    # ever accidentally writing into evidence — the read-only tool layer in
    # tools.py is a second, independent enforcement of the same invariant.
    for entry in entries:
        (evidence_dir / entry.relative_path).chmod(0o400)

    return manifest, evidence_dir
