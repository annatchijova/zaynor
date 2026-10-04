"""Stage static, read-only triage of already-acquired binaries.

This is the slice ADR-0003 cleared for ZAYNOR without reopening it: hashing,
ELF/PE header parsing and optional YARA signature matching over bytes that
are never executed or disassembled. It uses the shared
``tools.offline_evidence`` staging contract, so originals, observations, a
canonical copy of the input package and limitation metadata cross the
existing case-freeze boundary together and the result is
``analysis_unsupported`` (ADR-0004, ADR-0005).

Each binary yields exactly one ``binary_triage`` observation carrying its
``content_sha256``. That one-observation-per-binary shape is deliberate:
VIGIA's corroboration gate treats every D5-media artifact as an independent
fabrication act, so one binary must never surface as several artifacts.
Parser output is measurement, not judgment: no observation here says that a
binary is malicious, packed, benign or clean.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any

from tools.binary_static.elf import ELF_MAGIC, ElfFormatError, parse_elf
from tools.binary_static.measure import ENTROPY_METHOD, byte_histogram, shannon_entropy
from tools.binary_static.pe import PeFormatError, parse_pe
from tools.offline_evidence import (
    MAX_FILES,
    MAX_OBSERVATIONS,
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

MODULE = "binary_static"
TRANSFORM_SCOPE = "static_triage:no_disassembly:no_execution"

_DECLARED_KINDS = {"kernel_module", "boot_file", "executable", "shared_object", "other"}
_BINARY_KEYS = {"logical_path", "declared_kind", "source_path", "sha256"}
_SIGNATURE_KEYS = {"engine", "ruleset_source_path", "ruleset_sha256"}
_MAGIC_PREFIX_BYTES = 16
# Limitation codes that describe the module's coverage rather than one file.
_MODULE_WIDE_CODES = frozenset({"pe_data_directories_not_walked", "authenticode_not_verified"})

# YARA modules whose result depends only on the scanned bytes. `time` reads
# the wall clock, `magic` depends on the host libmagic database, `cuckoo`
# reads an external report and `console` has side effects: a ruleset that
# imports any of them would make the same frozen bytes scan differently.
_DETERMINISTIC_YARA_MODULES = frozenset(
    {"pe", "elf", "math", "hash", "dotnet", "dex", "macho", "string"}
)
_YARA_IMPORT = re.compile(r'^\s*import\s+"([^"\n]*)"', re.MULTILINE)
YARA_TIMEOUT_SECONDS = 60
MAX_MATCHES_LISTED = 256
MAX_STRING_IDENTIFIERS = 64
MAX_INSTANCES_PER_STRING = 16
MAX_META_ITEMS = 32
MAX_META_CHARS = 1024

# Parser defects on hostile input degrade one binary to `parse_failed`
# with an explicit code; they never abort the rest of the package.
_PARSER_FAULTS = (struct.error, IndexError, ValueError, OverflowError, UnicodeError)


def _string(value: Any, field: str, *, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise OfflineEvidenceError(f"{field} must be a non-empty bounded string")
    return value


def _signature_engine() -> Any | None:
    """Return the YARA binding, or None when it is not installed."""
    try:
        import yara  # optional dependency, imported on demand
    except ImportError:
        return None
    return yara


def triage_bytes(data: bytes) -> tuple[str, dict[str, Any], list[str]]:
    """Measure and parse one binary.

    Returns the observation status, format-specific fields and limitation
    codes (without the logical path suffix).
    """
    histogram = byte_histogram(data)
    fields: dict[str, Any] = {
        "size_bytes": len(data),
        "magic_hex": data[:_MAGIC_PREFIX_BYTES].hex(),
        "byte_histogram": histogram,
        "entropy_bits_per_byte": shannon_entropy(histogram),
        "entropy_method": ENTROPY_METHOD,
        "format": None,
        "parse_error": None,
        "parse_issues": [],
    }
    codes: list[str] = []
    try:
        if data[:4] == ELF_MAGIC:
            fields["format"] = "elf"
            fields["elf"], fields["parse_issues"] = parse_elf(data)
        elif data[:2] == b"MZ":
            parsed = parse_pe(data)
            if parsed is None:
                fields["format"] = "mz"
                codes.append("binary_format_unsupported")
                return "unknown", fields, codes
            fields["format"] = "pe"
            fields["pe"], fields["parse_issues"] = parsed
            codes.append("pe_data_directories_not_walked")
            if fields["pe"]["certificate_table"] is not None:
                codes.append("authenticode_not_verified")
        else:
            codes.append("binary_format_unsupported")
            return "unknown", fields, codes
    except (ElfFormatError, PeFormatError) as exc:
        fields["parse_error"] = str(exc)
        fields["parse_issues"] = []
        fields.pop("elf", None)
        fields.pop("pe", None)
        codes.append("binary_parse_failed")
        return "parse_failed", fields, codes
    except _PARSER_FAULTS as exc:
        fields["parse_error"] = f"internal_parser_error:{type(exc).__name__}"
        fields["parse_issues"] = []
        fields.pop("elf", None)
        fields.pop("pe", None)
        codes.append("binary_parser_internal_error")
        return "parse_failed", fields, codes
    if fields["parse_issues"]:
        codes.append("binary_parse_issues")
    return "observed", fields, codes


# -- signatures ---------------------------------------------------------------


class _Ruleset:
    """A compiled, determinism-checked ruleset, or the reason there is none."""

    def __init__(self) -> None:
        self.engine: Any | None = None
        self.rules: Any | None = None
        self.fields: dict[str, Any] = {}
        self.status = "unknown"
        self.reason: str | None = None


def _load_ruleset(data: bytes, source_path: str, digest: str) -> _Ruleset:
    ruleset = _Ruleset()
    engine = _signature_engine()
    ruleset.fields = {
        "record_type": "signature_ruleset",
        "engine": "yara",
        "engine_version": getattr(engine, "__version__", None),
        "library_version": getattr(engine, "YARA_VERSION", None),
        "source_path": source_path,
        "ruleset_sha256": digest,
        "size_bytes": len(data),
        "rule_count": None,
        "imported_modules": [],
        "rejection_reason": None,
    }
    if engine is None:
        ruleset.reason = "engine_unavailable"
        return ruleset
    ruleset.engine = engine
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return _reject(ruleset, "ruleset_not_utf8")
    declared = sorted(set(_YARA_IMPORT.findall(text)))
    ruleset.fields["imported_modules"] = declared
    if any(module not in _DETERMINISTIC_YARA_MODULES for module in declared):
        return _reject(ruleset, "nondeterministic_module_import")
    try:
        rules = engine.compile(source=text, includes=False)
    except engine.Error:
        return _reject(ruleset, "compile_error")
    loaded: list[str] = []

    def record_module(module_data: dict[str, Any]) -> int:
        loaded.append(str(module_data.get("module")))
        return engine.CALLBACK_CONTINUE

    # Authoritative check: the engine itself reports which modules the
    # compiled rules load, whatever the source text looked like.
    rules.match(data=b"", modules_callback=record_module)
    loaded_set = sorted(set(loaded))
    ruleset.fields["imported_modules"] = loaded_set
    if any(module not in _DETERMINISTIC_YARA_MODULES for module in loaded_set):
        return _reject(ruleset, "nondeterministic_module_import")
    ruleset.rules = rules
    ruleset.fields["rule_count"] = sum(1 for _ in rules)
    ruleset.status = "observed"
    return ruleset


def _reject(ruleset: _Ruleset, reason: str) -> _Ruleset:
    ruleset.status = "parse_failed"
    ruleset.reason = "ruleset_rejected"
    ruleset.fields["rejection_reason"] = reason
    return ruleset


def _meta_value(value: Any) -> Any:
    if isinstance(value, (bool, int)):
        return value
    text = value if isinstance(value, str) else str(value)
    return text[:MAX_META_CHARS]


def _scan(ruleset: _Ruleset, data: bytes) -> tuple[str, dict[str, Any]]:
    fields: dict[str, Any] = {
        "engine": "yara",
        "engine_version": ruleset.fields.get("engine_version"),
        "library_version": ruleset.fields.get("library_version"),
        "ruleset_sha256": ruleset.fields["ruleset_sha256"],
        "rule_count": ruleset.fields.get("rule_count"),
        "reason": ruleset.reason,
        "matched_rule_count": None,
        "reported_matches": [],
        "reported_matches_truncated": False,
    }
    engine = ruleset.engine
    if ruleset.rules is None or engine is None:
        return "unknown", fields
    try:
        matches = ruleset.rules.match(data=data, timeout=YARA_TIMEOUT_SECONDS)
    except engine.TimeoutError:
        fields["reason"] = "scan_timeout"
        return "unknown", fields
    except engine.Error:
        fields["reason"] = "scan_error"
        return "unknown", fields
    ordered = sorted(matches, key=lambda match: (match.namespace, match.rule))
    fields["matched_rule_count"] = len(ordered)
    if len(ordered) > MAX_MATCHES_LISTED:
        fields["reported_matches_truncated"] = True
        ordered = ordered[:MAX_MATCHES_LISTED]
    for match in ordered:
        meta_items = sorted(match.meta.items())[:MAX_META_ITEMS]
        strings = []
        for string in match.strings[:MAX_STRING_IDENTIFIERS]:
            instances = string.instances
            strings.append(
                {
                    "identifier": string.identifier,
                    "instance_count": len(instances),
                    "instances": [
                        {"offset": item.offset, "length": item.matched_length}
                        for item in instances[:MAX_INSTANCES_PER_STRING]
                    ],
                }
            )
        fields["reported_matches"].append(
            {
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": sorted(match.tags),
                "meta": {key: _meta_value(value) for key, value in meta_items},
                "strings": strings,
                "strings_truncated": len(match.strings) > MAX_STRING_IDENTIFIERS,
            }
        )
    return "observed", fields


# -- package boundary ---------------------------------------------------------


def import_binary_static(
    package: dict[str, Any], source_root: Path, staging_root: Path
) -> StagedEvidence:
    """Stage one bounded binary-triage package for the existing freezer."""
    context = validate_package_context(package, MODULE)
    allowed_keys = {
        "schema_version", "module", "case_id", "target", "acquisition", "binaries", "signatures"
    }
    unknown = sorted(package.keys() - allowed_keys)
    if unknown:
        raise OfflineEvidenceError(f"package contains unknown fields: {', '.join(unknown)}")
    binaries = package.get("binaries")
    if not isinstance(binaries, list) or not binaries or len(binaries) > MAX_FILES:
        raise OfflineEvidenceError(f"package.binaries must contain 1 to {MAX_FILES} entries")
    signatures = package.get("signatures")
    if signatures is not None:
        if not isinstance(signatures, dict) or set(signatures) != _SIGNATURE_KEYS:
            raise OfflineEvidenceError(
                "package.signatures requires engine, ruleset_source_path and ruleset_sha256"
            )
        if signatures["engine"] != "yara":
            raise OfflineEvidenceError("package.signatures.engine must be 'yara'")

    root = prepare_staging(staging_root)
    paths: list[str] = []
    observations: list[dict[str, Any]] = []
    limitations = [
        "vigia_input_contract_not_validated",
        "static_triage_only_no_disassembly_no_execution",
        "file_presence_does_not_establish_execution",
    ]
    seen_sources: set[str] = set()
    total_bytes = 0

    ruleset: _Ruleset | None = None
    if signatures is None:
        limitations.append("signature_matching_not_performed")
    else:
        ruleset_path = validate_relative_path(
            signatures["ruleset_source_path"], "package.signatures.ruleset_source_path"
        )
        ruleset_digest = validate_sha256(
            signatures["ruleset_sha256"], "package.signatures.ruleset_sha256"
        )
        seen_sources.add(ruleset_path)
        ruleset_bytes = read_original(source_root, ruleset_path, ruleset_digest)
        total_bytes += len(ruleset_bytes)
        manifest_path = write_staged_bytes(root, f"method/{MODULE}/{ruleset_path}", ruleset_bytes)
        paths.append(manifest_path)
        ruleset = _load_ruleset(ruleset_bytes, ruleset_path, ruleset_digest)
        if ruleset.reason == "engine_unavailable":
            limitations.append("signature_engine_unavailable")
        elif ruleset.reason == "ruleset_rejected":
            limitations.append(
                f"signature_ruleset_rejected:{ruleset.fields['rejection_reason']}"
            )
        observations.append(
            make_observation(
                context,
                observation_id=f"{MODULE}:ruleset",
                kind="signature_ruleset",
                status=ruleset.status,
                transform_name="yara-ruleset-inventory",
                manifest_path=manifest_path,
                sha256=ruleset_digest,
                fields=ruleset.fields,
            )
        )

    for index, raw in enumerate(binaries):
        if not isinstance(raw, dict) or set(raw) != _BINARY_KEYS:
            raise OfflineEvidenceError(
                f"package.binaries[{index}] requires logical_path, declared_kind, "
                "source_path and sha256"
            )
        logical_path = _string(raw["logical_path"], f"package.binaries[{index}].logical_path")
        declared_kind = raw["declared_kind"]
        if declared_kind not in _DECLARED_KINDS:
            raise OfflineEvidenceError(f"package.binaries[{index}].declared_kind is unsupported")
        source_path = validate_relative_path(
            raw["source_path"], f"package.binaries[{index}].source_path"
        )
        if source_path in seen_sources:
            raise OfflineEvidenceError(f"duplicate source_path: {source_path}")
        seen_sources.add(source_path)
        digest = validate_sha256(raw["sha256"], f"package.binaries[{index}].sha256")
        data = read_original(source_root, source_path, digest)
        total_bytes += len(data)
        if total_bytes > MAX_TOTAL_BYTES:
            raise OfflineEvidenceError(
                f"package exceeds the {MAX_TOTAL_BYTES}-byte aggregate limit"
            )
        manifest_path = write_staged_bytes(root, f"originals/{MODULE}/{source_path}", data)
        paths.append(manifest_path)

        status, measured, codes = triage_bytes(data)
        limitations.extend(
            code if code in _MODULE_WIDE_CODES else f"{code}:{logical_path}" for code in codes
        )
        if declared_kind == "kernel_module":
            limitations.append("kernel_module_load_state_unknown")
        observations.append(
            make_observation(
                context,
                observation_id=f"{MODULE}:{index:06d}:triage",
                kind="binary_triage",
                status=status,
                transform_name="binary-static-triage",
                manifest_path=manifest_path,
                sha256=digest,
                fields={
                    "record_type": "binary_triage",
                    "logical_path": logical_path,
                    "declared_kind": declared_kind,
                    "content_sha256": digest,
                    "transform_scope": TRANSFORM_SCOPE,
                    **measured,
                },
            )
        )

        if ruleset is not None:
            scan_status, scan_fields = _scan(ruleset, data)
            if scan_fields["reason"] in {"scan_timeout", "scan_error"}:
                limitations.append(f"signature_{scan_fields['reason']}:{logical_path}")
            observations.append(
                make_observation(
                    context,
                    observation_id=f"{MODULE}:{index:06d}:signatures",
                    kind="signature_scan",
                    status=scan_status,
                    transform_name="yara-scan",
                    manifest_path=manifest_path,
                    sha256=digest,
                    fields={
                        "record_type": "signature_scan",
                        "logical_path": logical_path,
                        "content_sha256": digest,
                        **scan_fields,
                    },
                )
            )
        if len(observations) > MAX_OBSERVATIONS:
            raise OfflineEvidenceError(
                f"package exceeds the {MAX_OBSERVATIONS}-observation limit"
            )

    return finish_staging(context, root, paths, observations, limitations, package)
