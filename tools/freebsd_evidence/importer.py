"""Validate and stage already-acquired FreeBSD evidence.

The importer emits typed observations about acquired bytes.  It does not
decide whether a change is malicious or whether a kernel module was loaded.
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
    write_staged_bytes,
)

MODULE = "freebsd_evidence"

_KINDS = {
    "boot_file",
    "kernel_module",
    "loader_configuration",
    "startup_configuration",
    "system_log",
    "bsm_audit_trail",
    "guest_report",
}
_DECLARED_STATUSES = {"collected", "not_collected", "unreadable", "observed_absent"}
_CONFIG_KINDS = {"loader_configuration", "startup_configuration"}
_TEXT_KINDS = {"system_log", "guest_report"}
_CONFIG_ENTRY = re.compile(r"^(?P<setting>[A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(?P<value>.*)$")


def _string(value: Any, field: str, *, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise OfflineEvidenceError(f"{field} must be a non-empty bounded string")
    return value


def _artifact_observation(
    context,
    index: int,
    artifact: dict[str, Any],
    *,
    status: str,
    manifest_path: str | None,
    sha256: str | None,
    size_bytes: int | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "record_type": "artifact",
        "logical_path": artifact["logical_path"],
        "declared_collection_status": artifact["collection_status"],
    }
    if size_bytes is not None:
        fields["size_bytes"] = size_bytes
    if artifact.get("reason") is not None:
        fields["reason"] = artifact["reason"]
    if artifact.get("search_scope") is not None:
        fields["search_scope"] = artifact["search_scope"]
    if extra:
        fields.update(extra)
    return make_observation(
        context,
        observation_id=f"freebsd:{index:06d}:artifact",
        kind=artifact["kind"],
        status=status,
        transform_name="freebsd-raw-inventory",
        manifest_path=manifest_path,
        sha256=sha256,
        fields=fields,
    )


def _normalize_config(context, index, artifact, data, manifest_path, sha256, limitations):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        limitations.append(f"utf8_decode_failed:{artifact['logical_path']}")
        return [
            _artifact_observation(
                context,
                index,
                artifact,
                status="parse_failed",
                manifest_path=manifest_path,
                sha256=sha256,
                size_bytes=len(data),
                extra={"parse_error": "content is not valid UTF-8"},
            )
        ]

    observations = [
        _artifact_observation(
            context,
            index,
            artifact,
            status="observed",
            manifest_path=manifest_path,
            sha256=sha256,
            size_bytes=len(data),
        )
    ]
    unparsed_active_lines = 0
    oversized_lines = 0
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if len(raw_line) > MAX_TEXT_LINE_CHARS:
            oversized_lines += 1
            continue
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _CONFIG_ENTRY.fullmatch(stripped)
        if match is None:
            unparsed_active_lines += 1
            continue
        observations.append(
            make_observation(
                context,
                observation_id=f"freebsd:{index:06d}:config:{line_number:06d}",
                kind=artifact["kind"],
                status="observed",
                transform_name="freebsd-simple-configuration",
                manifest_path=manifest_path,
                sha256=sha256,
                fields={
                    "record_type": "configuration_entry",
                    "logical_path": artifact["logical_path"],
                    "line_number": line_number,
                    "raw_line": raw_line,
                    "setting": match.group("setting"),
                    "value": match.group("value"),
                },
            )
        )
        if len(observations) > MAX_OBSERVATIONS:
            raise OfflineEvidenceError(
                f"package exceeds the {MAX_OBSERVATIONS}-observation limit"
            )
    if unparsed_active_lines:
        limitations.append(f"unparsed_configuration_lines:{artifact['logical_path']}")
    if oversized_lines:
        limitations.append(f"oversized_text_lines:{artifact['logical_path']}")
    return observations


def _normalize_text(context, index, artifact, data, manifest_path, sha256, limitations):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        limitations.append(f"utf8_decode_failed:{artifact['logical_path']}")
        return [
            _artifact_observation(
                context,
                index,
                artifact,
                status="parse_failed",
                manifest_path=manifest_path,
                sha256=sha256,
                size_bytes=len(data),
                extra={"parse_error": "content is not valid UTF-8"},
            )
        ]

    observations = [
        _artifact_observation(
            context,
            index,
            artifact,
            status="observed",
            manifest_path=manifest_path,
            sha256=sha256,
            size_bytes=len(data),
        )
    ]
    oversized_lines = 0
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if not raw_line:
            continue
        if len(raw_line) > MAX_TEXT_LINE_CHARS:
            oversized_lines += 1
            continue
        observations.append(
            make_observation(
                context,
                observation_id=f"freebsd:{index:06d}:line:{line_number:06d}",
                kind=artifact["kind"],
                status="observed",
                transform_name="freebsd-text-lines",
                manifest_path=manifest_path,
                sha256=sha256,
                fields={
                    "record_type": "text_line",
                    "logical_path": artifact["logical_path"],
                    "line_number": line_number,
                    "text": raw_line,
                },
            )
        )
        if len(observations) > MAX_OBSERVATIONS:
            raise OfflineEvidenceError(
                f"package exceeds the {MAX_OBSERVATIONS}-observation limit"
            )
    if oversized_lines:
        limitations.append(f"oversized_text_lines:{artifact['logical_path']}")
    return observations


def import_freebsd_evidence(
    package: dict[str, Any], source_root: Path, staging_root: Path
) -> StagedEvidence:
    """Stage one bounded FreeBSD package for the existing case freezer."""
    context = validate_package_context(package, MODULE)
    allowed_keys = {
        "schema_version", "module", "case_id", "target", "acquisition", "artifacts"
    }
    unknown = sorted(package.keys() - allowed_keys)
    if unknown:
        raise OfflineEvidenceError(f"package contains unknown fields: {', '.join(unknown)}")
    artifacts = package.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts or len(artifacts) > MAX_FILES:
        raise OfflineEvidenceError(f"package.artifacts must contain 1 to {MAX_FILES} entries")

    root = prepare_staging(staging_root)
    paths: list[str] = []
    observations: list[dict[str, Any]] = []
    limitations = ["vigia_input_contract_not_validated"]
    seen_sources: set[str] = set()
    total_bytes = 0

    for index, raw in enumerate(artifacts):
        if not isinstance(raw, dict):
            raise OfflineEvidenceError(f"package.artifacts[{index}] must be an object")
        allowed_artifact_keys = {
            "logical_path",
            "kind",
            "collection_status",
            "source_path",
            "sha256",
            "reason",
            "search_scope",
        }
        unknown_artifact = sorted(raw.keys() - allowed_artifact_keys)
        if unknown_artifact:
            raise OfflineEvidenceError(
                f"package.artifacts[{index}] contains unknown fields: {', '.join(unknown_artifact)}"
            )
        logical_path = _string(raw.get("logical_path"), f"package.artifacts[{index}].logical_path")
        kind = raw.get("kind")
        if kind not in _KINDS:
            raise OfflineEvidenceError(f"package.artifacts[{index}].kind is unsupported")
        collection_status = raw.get("collection_status")
        if collection_status not in _DECLARED_STATUSES:
            raise OfflineEvidenceError(
                f"package.artifacts[{index}].collection_status is unsupported"
            )
        artifact = dict(raw)
        artifact["logical_path"] = logical_path
        artifact["kind"] = kind
        artifact["collection_status"] = collection_status

        if collection_status != "collected":
            if raw.get("source_path") is not None or raw.get("sha256") is not None:
                raise OfflineEvidenceError("uncollected artifacts cannot name source bytes")
            artifact["reason"] = _string(
                raw.get("reason"), f"package.artifacts[{index}].reason"
            )
            if collection_status == "observed_absent":
                artifact["search_scope"] = _string(
                    raw.get("search_scope"), f"package.artifacts[{index}].search_scope"
                )
            elif raw.get("search_scope") is not None:
                raise OfflineEvidenceError("search_scope is only valid for observed_absent")
            observations.append(
                _artifact_observation(
                    context,
                    index,
                    artifact,
                    status=collection_status,
                    manifest_path=None,
                    sha256=None,
                )
            )
            continue

        if raw.get("reason") is not None or raw.get("search_scope") is not None:
            raise OfflineEvidenceError("collected artifacts cannot declare absence fields")
        source_path = validate_relative_path(
            raw.get("source_path"), f"package.artifacts[{index}].source_path"
        )
        if source_path in seen_sources:
            raise OfflineEvidenceError(f"duplicate source_path: {source_path}")
        seen_sources.add(source_path)
        digest = validate_sha256(raw.get("sha256"), f"package.artifacts[{index}].sha256")
        data = read_original(source_root, source_path, digest)
        total_bytes += len(data)
        if total_bytes > MAX_TOTAL_BYTES:
            raise OfflineEvidenceError(
                f"package exceeds the {MAX_TOTAL_BYTES}-byte aggregate limit"
            )
        manifest_path = write_staged_bytes(root, f"originals/{MODULE}/{source_path}", data)
        paths.append(manifest_path)

        if kind in _CONFIG_KINDS:
            observations.extend(
                _normalize_config(
                    context, index, artifact, data, manifest_path, digest, limitations
                )
            )
        elif kind in _TEXT_KINDS:
            observations.extend(
                _normalize_text(
                    context, index, artifact, data, manifest_path, digest, limitations
                )
            )
        else:
            observations.append(
                _artifact_observation(
                    context,
                    index,
                    artifact,
                    status="observed",
                    manifest_path=manifest_path,
                    sha256=digest,
                    size_bytes=len(data),
                )
            )
            if kind == "bsm_audit_trail":
                limitations.append("bsm_parser_unavailable")
            elif kind == "kernel_module":
                limitations.append("kernel_module_load_state_unknown")

        if len(observations) > MAX_OBSERVATIONS:
            raise OfflineEvidenceError(
                f"package exceeds the {MAX_OBSERVATIONS}-observation limit"
            )

    return finish_staging(context, root, paths, observations, limitations, package)
