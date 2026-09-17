"""Command-line entry point for ZAYNOR's deterministic front end.

The CLI is an interface, not a second decision engine. It only composes the
existing replay, detection, correlation, case, and chat contracts (`freeze`,
`analyze`, `audit`, `chat`, `serve`). Every command follows the same rule:
parse at the edge, delegate to the core, and never manufacture an
authoritative result. `chat` and `serve` narrate through
`agents/chat_service.py`, the one seal-verified path both share — neither
lets the LLM touch a verdict, finding, or seal.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any, Sequence

from zaynor.argentina_time import format_argentina
from zaynor.correlation import correlate, open_case
from zaynor.case_freezer import freeze_case
from zaynor.detection import CORRELATION_WINDOW_SECONDS, detect_suspicious_privileged_login
from zaynor.frozen_snapshot import _manifest_digest, _snapshot_digest, _validated_entries
from zaynor.adapter import _evidence_path_for_mode1
from zaynor.replay import replay
from zaynor.authority_seal import AuthoritySeal, seal_authoritative_result, verify_authoritative_result
from zaynor.telemetry import annotate_with_audit_entry, postmortem_span
from zaynor.vendored_engine import VENDORED_ENGINE_PATH

_MAX_FIXTURE_BYTES = 10 * 1024 * 1024
_DEFAULT_KNOWN_DEVICES = frozenset({"DEV-CORP-01", "DEV-CORP-02", "DEV-CORP-LAPTOP-09"})
_SAFE_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class CliInputError(ValueError):
    """A command-line value failed validation at the CLI boundary."""


def _fixture_path(raw: str) -> Path:
    """Accept one bounded, regular, non-symlink fixture file."""
    if not isinstance(raw, str) or not raw.strip():
        raise CliInputError("fixture path must not be empty")
    path = Path(raw)
    lexical = Path.cwd() / path if not path.is_absolute() else path
    for component in (lexical, *lexical.parents):
        if component.exists() and component.is_symlink():
            raise CliInputError("fixture path must not traverse a symlink")
    try:
        resolved = path.resolve(strict=True)
        stat = resolved.stat()
    except OSError as exc:
        raise CliInputError(f"fixture cannot be read: {raw}") from exc
    if not resolved.is_file():
        raise CliInputError("fixture path must be a regular file")
    if stat.st_size > _MAX_FIXTURE_BYTES:
        raise CliInputError(f"fixture exceeds {_MAX_FIXTURE_BYTES} bytes")
    return resolved


def _directory_path(raw: str, *, create: bool = False) -> Path:
    if not isinstance(raw, str) or not raw.strip():
        raise CliInputError("directory path must not be empty")
    path = Path(raw)
    lexical = Path.cwd() / path if not path.is_absolute() else path

    def reject_symlink_components() -> None:
        for component in (lexical, *lexical.parents):
            if component.exists() and component.is_symlink():
                raise CliInputError("directory path must not traverse a symlink")

    reject_symlink_components()
    if create:
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise CliInputError(f"directory cannot be created: {raw}") from exc
        reject_symlink_components()
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CliInputError(f"directory cannot be read: {raw}") from exc
    if not resolved.is_dir() or resolved.is_symlink():
        raise CliInputError("path must be a regular directory")
    return resolved


def _default_engine_repo() -> Path:
    """Zaynor's own vendored VIGÍA engine — no separate clone needed for
    `analyze` to work out of the box. `--engine-repo` still overrides this
    for anyone pointing at a live VIGÍA checkout instead (development on
    VIGÍA itself, or a newer engine version than the vendored snapshot).
    """
    if not VENDORED_ENGINE_PATH.is_dir():
        raise CliInputError(
            f"no --engine-repo given and the vendored engine is missing: {VENDORED_ENGINE_PATH}"
        )
    return _directory_path(str(VENDORED_ENGINE_PATH))


def _known_devices(values: Sequence[str] | None) -> set[str]:
    devices = set(_DEFAULT_KNOWN_DEVICES if not values else values)
    if any(not isinstance(device, str) or not device.strip() for device in devices):
        raise CliInputError("known device identifiers must be non-empty strings")
    return devices


def _json_default(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return asdict(value)
    raise TypeError(f"cannot serialize {type(value).__name__}")


def _emit(value: Any, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(value, default=_json_default, ensure_ascii=False, sort_keys=True, indent=2))
        return
    if isinstance(value, dict) and value.get("alerts") is not None:
        print(f"Eventos: {value['events']}")
        print(f"Alertas: {len(value['alerts'])}")
        for alert in value["alerts"]:
            print(f"- {alert['rule_id']}: {alert['reason']} [{alert['severity']}]")
        if value.get("case"):
            print(f"Caso: {value['case']['case_id']} ({value['case']['priority']})")
        return
    if isinstance(value, list):
        for item in value:
            print(json.dumps(item, default=_json_default, ensure_ascii=False, sort_keys=True))
        return
    if isinstance(value, dict) and value.get("overall") in {"VERIFIED", "FAILED"}:
        labels = (
            ("case_id", "CASE"),
            ("snapshot", "SNAPSHOT"),
            ("manifest", "MANIFEST"),
            ("evidence", "EVIDENCE"),
            ("engine", "ENGINE"),
            ("result", "RESULT"),
            ("seal", "SEAL"),
            ("verdict", "VERDICT"),
            ("confidence", "CONFIDENCE"),
            ("findings", "FINDINGS"),
            ("provenance", "PROVENANCE"),
            ("overall", "OVERALL"),
        )
        for key, label in labels:
            if key in value:
                print(f"{label:<12} {value[key]}")
        for unknown in value.get("unknowns", []):
            print(f"UNKNOWN      {unknown}")
        if value.get("error"):
            print(f"ERROR        {value['error']}")
        return
    print(json.dumps(value, default=_json_default, ensure_ascii=False, sort_keys=True))


def _atomic_json_write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.is_symlink():
        raise CliInputError(f"output path must not be a symlink: {path}")
    encoded = json.dumps(value, default=_json_default, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", mode="w", encoding="utf-8", delete=False) as temp:
        temp.write(encoded)
        temp.flush()
        os.fsync(temp.fileno())
        temporary = Path(temp.name)
    os.replace(temporary, path)


def _replayed_events(fixture: str):
    path = _fixture_path(fixture)
    try:
        return list(replay(path))
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise CliInputError(f"fixture is invalid: {path}") from exc


def _run_replay(args: argparse.Namespace) -> int:
    events = _replayed_events(args.fixture)
    _emit(events, as_json=args.json)
    return 0


def _run_detect(args: argparse.Namespace) -> int:
    events = _replayed_events(args.fixture)
    alerts = detect_suspicious_privileged_login(events, _known_devices(args.known_device))
    payload = {"events": len(events), "alerts": alerts}
    _emit(payload, as_json=args.json)
    return 0


def _run_case(args: argparse.Namespace) -> int:
    events = _replayed_events(args.fixture)
    alerts = detect_suspicious_privileged_login(events, _known_devices(args.known_device))
    payload: dict[str, Any] = {"events": len(events), "alerts": alerts, "case": None}
    if alerts:
        triggering = next(event for event in events if event.event_id in alerts[0].triggering_event_ids)
        related = [event for event in events if abs(event.logical_time - triggering.logical_time) <= args.window]
        correlation = correlate(alerts[0], triggering, related, window_seconds=args.window)
        payload["case"] = open_case(alerts[0], correlation, evidence_profile=args.evidence_profile)
    _emit(payload, as_json=args.json)
    return 0


def _run_freeze(args: argparse.Namespace) -> int:
    source_root = _directory_path(args.source_root)
    cases_root = _directory_path(args.cases_root, create=True)
    profile_path = _fixture_path(args.profile_map)
    try:
        profile_map = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CliInputError(f"profile map is invalid: {profile_path}") from exc
    if (
        not isinstance(profile_map, dict)
        or any(not isinstance(name, str) or not isinstance(paths, list) for name, paths in profile_map.items())
        or any(not isinstance(path, str) for paths in profile_map.values() for path in paths)
    ):
        raise CliInputError("profile map must be an object of string profiles and path lists")
    try:
        manifest, evidence_dir = freeze_case(
            args.case_id,
            args.evidence_profile,
            profile_map,
            source_root,
            cases_root,
        )
    except (KeyError, OSError, ValueError) as exc:
        raise CliInputError(f"case freeze failed: {exc}") from exc
    from zaynor.audit_log import AuditLog

    audit = AuditLog(cases_root / args.case_id / "audit.jsonl", case_id=args.case_id)
    with postmortem_span(args.case_id, "zaynor.case_frozen") as span:
        frozen_entry = audit.append(
            "CASE_FROZEN",
            {"manifest_sha256": manifest.content_sha256, "sealed_at": manifest.sealed_at},
            reason=f"case evidence frozen under profile {args.evidence_profile!r}",
        )
        annotate_with_audit_entry(span, frozen_entry)
    payload = {"manifest": manifest, "evidence_dir": str(evidence_dir)}
    _emit(payload, as_json=args.json)
    return 0


def _load_case_manifest(case_dir: Path):
    from zaynor.schemas import CaseManifest, ManifestEntry

    manifest_path = case_dir / "manifest.json"
    manifest_file = _fixture_path(str(manifest_path))
    try:
        raw = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CliInputError(f"manifest is invalid: {manifest_file}") from exc
    if not isinstance(raw, dict) or raw.get("case_id") != case_dir.name:
        raise CliInputError("manifest case_id does not match the selected case")
    entries = raw.get("entries")
    if not isinstance(entries, list):
        raise CliInputError("manifest entries must be a list")
    parsed_entries = []
    for entry in entries:
        if not isinstance(entry, dict) or not all(key in entry for key in ("relative_path", "sha256", "size_bytes")):
            raise CliInputError("manifest contains an invalid entry")
        if not isinstance(entry["relative_path"], str) or not isinstance(entry["sha256"], str):
            raise CliInputError("manifest entry fields have invalid types")
        if not isinstance(entry["size_bytes"], int) or isinstance(entry["size_bytes"], bool) or entry["size_bytes"] < 0:
            raise CliInputError("manifest entry size_bytes must be a non-negative integer")
        parsed_entries.append(ManifestEntry(**entry))
    for key in ("content_sha256", "sealed_at", "sealed_at_sha256"):
        if not isinstance(raw.get(key), str) or not raw[key]:
            raise CliInputError(f"manifest field {key} is invalid")
    return CaseManifest(
        case_id=raw["case_id"],
        entries=tuple(parsed_entries),
        content_sha256=raw["content_sha256"],
        sealed_at=raw["sealed_at"],
        sealed_at_sha256=raw["sealed_at_sha256"],
    )


def _run_analyze(args: argparse.Namespace) -> int:
    if args.python is not None and not args.dev:
        raise CliInputError("--python is dev-only; use --dev explicitly")
    if not _SAFE_CASE_ID.fullmatch(args.case_id):
        raise CliInputError("case-id must be a bounded path-safe identifier")
    cases_root = _directory_path(args.cases_root)
    case_dir = cases_root / args.case_id
    if case_dir.is_symlink() or not case_dir.is_dir():
        raise CliInputError("selected case directory is missing or unsafe")
    manifest = _load_case_manifest(case_dir)
    evidence_dir = case_dir / "evidence"
    engine_repo = _directory_path(args.engine_repo) if args.engine_repo else _default_engine_repo()
    output_root = _directory_path(args.output_root, create=True)
    from zaynor.audit_log import AuditLog

    audit = AuditLog(case_dir / "audit.jsonl", case_id=args.case_id)
    with postmortem_span(args.case_id, "zaynor.engine_invoked") as span:
        engine_entry = audit.append(
            "ENGINE_INVOKED",
            {"engine_repo": str(engine_repo), "timeout_seconds": args.timeout},
            reason="running the deterministic engine against the frozen evidence",
        )
        annotate_with_audit_entry(span, engine_entry)
        try:
            from zaynor.adapter import ZaynorMode1Adapter

            result = ZaynorMode1Adapter(
                engine_repo,
                output_root,
                python_executable=args.python or sys.executable,
                timeout_seconds=args.timeout,
            ).analyze(manifest, evidence_dir)
        except (OSError, RuntimeError, ValueError) as exc:
            raise CliInputError(f"case analysis failed: {exc}") from exc
    result = replace(result, audit_refs=(engine_entry.entry_hash,))
    result_path = output_root / args.case_id / "result.json"
    seal = seal_authoritative_result(result)
    seal_path = output_root / args.case_id / "result.seal.json"
    # Architecture audit finding (GAP-05): this used to write result.json
    # and result.seal.json *before* appending RESULT_SEALED. A crash in
    # that window left a fully verifiable, sealed MALICE-verdict result on
    # disk with no audit-trail entry ever recording that it was sealed --
    # the one artifact this pipeline cares most about, silently missing
    # from its own history. Appending the audit entry first instead means
    # the only reachable partial state is the opposite and detectable one:
    # a RESULT_SEALED entry whose files never landed, which
    # compute_case_audit can (and, per GAP-01, now does) recognize as an
    # incomplete analyze rather than mistaking it for a healthy case.
    with postmortem_span(args.case_id, "zaynor.result_sealed") as span:
        sealed_entry = audit.append(
            "RESULT_SEALED",
            {"result_sha256": seal.sha256, "verdict": result.verdict},
            reason="authoritative result sealed",
        )
        annotate_with_audit_entry(span, sealed_entry)
    _atomic_json_write(result_path, result)
    _atomic_json_write(seal_path, seal)
    _write_case_index_entry(output_root, args.case_id, result, seal)
    _emit({"result": result, "seal": seal, "result_path": str(result_path), "seal_path": str(seal_path)}, as_json=args.json)
    return 0


def _run_audit_trail(args: argparse.Namespace) -> int:
    """Show and verify a case's real hash-chained audit.jsonl.

    `AuditLog` (audit_log.py) has logged CASE_FROZEN/ENGINE_INVOKED/
    RESULT_SEALED since it was built, but nothing ever read it back --
    this command and the API's `/cases/{case_id}/audit-trail` route are
    the first exposure of it. Verification and reading are kept as two
    explicit steps: the chain can be reported broken while its entries
    are still shown, never silently hidden.
    """
    cases_root = _directory_path(args.cases_root)
    if not _SAFE_CASE_ID.fullmatch(args.case_id):
        raise CliInputError("case-id must be a bounded path-safe identifier")
    case_dir = cases_root / args.case_id
    if case_dir.is_symlink() or not case_dir.is_dir():
        raise CliInputError("selected case directory is missing or unsafe")

    from zaynor.audit_log import AuditLog

    log_path = case_dir / "audit.jsonl"
    chain_valid, chain_detail = AuditLog.verify_with_report(log_path, case_id=args.case_id)
    entries = AuditLog.load_entries(log_path)
    payload = {
        "case_id": args.case_id,
        "chain_valid": chain_valid,
        "chain_detail": chain_detail,
        "total_entries": len(entries),
        "entries": entries,
    }
    if args.json:
        _emit(payload, as_json=True)
    else:
        print(f"CASE         {args.case_id}")
        print(f"CHAIN        {'VALID' if chain_valid else 'BROKEN'} ({chain_detail})")
        print(f"ENTRIES      {len(entries)}")
        for entry in entries:
            print(f"  #{entry['seq']:<3} {entry['action']:<22} {entry['created_at']}  {entry['reason']}")
    return 0 if chain_valid else 1


def _load_stored_result(case_id: str, result_path: Path):
    from zaynor.adapter import translate_result

    result_file = _fixture_path(str(result_path))
    try:
        raw = json.loads(result_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CliInputError(f"stored result is invalid: {result_file}") from exc
    if not isinstance(raw, dict):
        raise CliInputError("stored result must be a JSON object")
    return translate_result(case_id, raw)


def _load_stored_seal(seal_path: Path) -> AuthoritySeal:
    seal_file = _fixture_path(str(seal_path))
    try:
        raw = json.loads(seal_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CliInputError(f"stored result seal is invalid: {seal_file}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("canonicalize_version"), str) or not isinstance(raw.get("sha256"), str):
        raise CliInputError("stored result seal has invalid fields")
    return AuthoritySeal(raw["canonicalize_version"], raw["sha256"])


def load_verified_stored_case(
    case_id: str, result_path: Path, seal_path: Path
) -> tuple[Any, AuthoritySeal]:
    """Load one stored result and prove that its seal covers that result."""
    try:
        result = _load_stored_result(case_id, result_path)
        seal = _load_stored_seal(seal_path)
        verify_authoritative_result(result, seal)
    except (RuntimeError, ValueError) as exc:
        raise CliInputError("stored authority verification failed") from exc
    if result.case_id != case_id:
        raise CliInputError("stored authority case_id does not match requested case")
    return result, seal


def _case_index_path(output_root: Path) -> Path:
    return output_root / "index.json"


def _case_index_entry(case_id: str, result: Any, seal: AuthoritySeal) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "verdict": result.verdict,
        "result_sha256": seal.sha256,
        "updated_at": format_argentina(),
    }


def _write_case_index_entry(output_root: Path, case_id: str, result: Any, seal: AuthoritySeal) -> None:
    """Update one case's row in the derived, non-authoritative case index.

    Architecture audit finding (GAP-08): `GET /cases` had nothing to show
    per case except `NOT_CHECKED`/`UNKNOWN` placeholders, because listing
    verdicts would otherwise mean fully re-verifying every case on every
    page load. This index is explicitly NOT a source of truth -- it is
    never read by `compute_case_audit`, `chat`, or `report`, only by the
    listing route, and `zaynor reindex` can always regenerate it byte-for-
    byte from the real, sealed results on disk (see `_rebuild_case_index`).
    """
    index_path = _case_index_path(output_root)
    try:
        index = json.loads(index_path.read_text(encoding="utf-8")) if index_path.is_file() else {}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        index = {}
    if not isinstance(index, dict):
        index = {}
    index[case_id] = _case_index_entry(case_id, result, seal)
    _atomic_json_write(index_path, index)


def _rebuild_case_index(output_root: Path) -> dict[str, Any]:
    """Rebuild the derived case index from scratch, from the real sealed
    results on disk -- nothing about it is read from the index it replaces.
    A case whose result/seal no longer verifies is simply omitted, not
    reported: the index only ever claims what it could re-derive.
    """
    index: dict[str, Any] = {}
    if output_root.is_dir():
        for entry in sorted(output_root.iterdir()):
            if not entry.is_dir() or entry.is_symlink():
                continue
            result_path = entry / "result.json"
            seal_path = entry / "result.seal.json"
            if not result_path.is_file() or not seal_path.is_file():
                continue
            try:
                result, seal = load_verified_stored_case(entry.name, result_path, seal_path)
            except CliInputError:
                continue
            index[entry.name] = _case_index_entry(entry.name, result, seal)
    _atomic_json_write(_case_index_path(output_root), index)
    return index


def _run_reindex(args: argparse.Namespace) -> int:
    output_root = _directory_path(args.output_root)
    index = _rebuild_case_index(output_root)
    _emit({"cases_indexed": len(index), "index_path": str(_case_index_path(output_root))}, as_json=args.json)
    return 0


def compute_case_audit(case_id: str, cases_root: Path, output_root: Path) -> dict[str, Any]:
    """Re-verify a case's manifest, snapshot, evidence, bundle, and sealed
    result from scratch, without trusting any producer-side state.

    Pure function over already-resolved directories, shared by `zaynor
    audit` and the API's `/cases/{case_id}/audit` route -- one
    verification implementation, not two that could quietly drift apart.
    Never raises for an expected failure: every failure mode is reported
    inside the returned dict's "error" field with `overall: FAILED`.
    """
    report: dict[str, Any] = {
        "case_id": case_id,
        "manifest": "FAILED",
        "snapshot": "FAILED",
        "evidence": "FAILED",
        "engine": "UNKNOWN",
        "chain": "FAILED",
        "result": "FAILED",
        "seal": "FAILED",
        "verdict": "UNKNOWN",
        "confidence": "UNKNOWN",
        "findings": 0,
        "unknowns": [],
        "provenance": "UNKNOWN",
        "overall": "FAILED",
    }
    try:
        if not _SAFE_CASE_ID.fullmatch(case_id):
            raise CliInputError("case-id must be a bounded path-safe identifier")
        case_dir = cases_root / case_id
        if case_dir.is_symlink() or not case_dir.is_dir():
            raise CliInputError("selected case directory is missing or unsafe")
        manifest = _load_case_manifest(case_dir)
        manifest_digest = _manifest_digest(manifest)
        report["manifest"] = "VERIFIED"
        evidence_dir = case_dir / "evidence"
        entries = _validated_entries(manifest, evidence_dir)
        snapshot_digest = _snapshot_digest(evidence_dir)
        mode1_evidence_path = _evidence_path_for_mode1(evidence_dir)
        bundle_evidence_digest = (
            snapshot_digest
            if mode1_evidence_path == evidence_dir
            else hashlib.sha256(mode1_evidence_path.read_bytes()).hexdigest()
        )
        report["snapshot"] = "VERIFIED"
        report["evidence"] = f"{len(entries)}/{len(manifest.entries)} VERIFIED"

        output_case_dir = output_root / case_id
        bundle_path = output_case_dir / "bundle.json"
        bundle_file = _fixture_path(str(bundle_path))
        bundle_bytes = bundle_file.read_bytes()
        bundle = json.loads(bundle_bytes.decode("utf-8"))
        if not isinstance(bundle, dict) or bundle.get("case_id") != case_id:
            raise CliInputError("stored bundle case_id does not match selected case")
        sidecar_path = bundle_path.with_suffix(bundle_path.suffix + ".sha256")
        fields = _fixture_path(str(sidecar_path)).read_text(encoding="utf-8").strip().split()
        if not fields or fields[0] != hashlib.sha256(bundle_bytes).hexdigest():
            raise CliInputError("stored bundle sidecar does not match bundle")
        if bundle.get("evidence_sha256") != bundle_evidence_digest:
            raise CliInputError("stored bundle evidence hash does not match current snapshot")
        report["engine"] = str(bundle.get("vigia_agent_version", "UNKNOWN"))

        result = _load_stored_result(case_id, output_case_dir / "result.json")
        seal = _load_stored_seal(output_case_dir / "result.seal.json")
        verify_authoritative_result(result, seal)
        if result.integrity.get("authorized_manifest_sha256") != manifest_digest:
            raise CliInputError("result manifest hash does not match selected manifest")
        if result.integrity.get("analyzed_snapshot_sha256") != snapshot_digest:
            raise CliInputError("result snapshot hash does not match current evidence")
        if result.integrity.get("authorized_case_id") != case_id:
            raise CliInputError("result authorized case_id does not match selected case")

        # Architecture audit finding (GAP-01): every other artifact here
        # gets re-verified from scratch, but the hash-chained audit trail
        # -- the one artifact whose whole purpose is proving this case
        # wasn't quietly altered -- was never even asked. A case with a
        # truncated, forged, or entirely deleted audit.jsonl used to come
        # back "overall: VERIFIED" with nobody having looked at it. A real
        # analyzed case always has one (`_run_freeze`/`_run_analyze` both
        # append to it); its absence is itself suspicious, not neutral, so
        # it fails closed the same as a chain that doesn't verify. A
        # legitimately degraded but honest chain (hash-only mode, no HMAC
        # key configured) still counts as verified -- the caveat travels
        # in the message, per CLAUDE.md 5.3 (a WARN is not a FAIL).
        from zaynor.audit_log import AuditLog

        audit_log_path = case_dir / "audit.jsonl"
        chain_ok, chain_detail = AuditLog.verify_with_report(audit_log_path, case_id=case_id)
        if not chain_ok:
            raise CliInputError(f"audit trail does not verify: {chain_detail}")
        if not audit_log_path.is_file():
            raise CliInputError("no audit trail found for this case")
        sealed_entries = [
            entry for entry in AuditLog.load_entries(audit_log_path)
            if entry.get("action") == "RESULT_SEALED"
        ]
        if not any(entry.get("detail", {}).get("result_sha256") == seal.sha256 for entry in sealed_entries):
            raise CliInputError("audit trail has no RESULT_SEALED entry matching the stored seal")
        report["chain"] = f"VERIFIED ({chain_detail})" if "hash-only" in chain_detail or "not verified" in chain_detail else "VERIFIED"

        report.update(
            {
                "result": "VERIFIED",
                "seal": "VERIFIED",
                "verdict": result.verdict,
                "confidence": result.integrity.get("confidence", "UNKNOWN"),
                "findings": len(result.findings),
                "unknowns": list(result.unknowns),
                # A non-empty provenance field proves presence only. The
                # current contract does not independently validate every
                # provenance edge against an external authority.
                "provenance": "PRESENT" if result.provenance else "EMPTY",
                "overall": "VERIFIED",
            }
        )
    except (CliInputError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        report["error"] = str(exc)
    return report


def _run_audit(args: argparse.Namespace) -> int:
    cases_root = _directory_path(args.cases_root)
    output_root = _directory_path(args.output_root)
    report = compute_case_audit(args.case_id, cases_root, output_root)
    _emit(report, as_json=args.json)
    return 0 if report["overall"] == "VERIFIED" else 1


_MODEL_ENV_VAR = "ZAYNOR_OLLAMA_MODEL"


def _resolve_model(explicit: str | None) -> str:
    """Nobody is required to run one specific model.

    Precedence: `--model` on the command line, then `$ZAYNOR_OLLAMA_MODEL`
    (a per-machine default), then a bundled fallback. `zaynor models` shows
    suggested models by hardware tier, and what is already pulled locally.
    """
    from zaynor.agents.model_catalog import _FALLBACK_MODEL

    if explicit:
        return explicit
    from_env = os.environ.get(_MODEL_ENV_VAR, "").strip()
    return from_env or _FALLBACK_MODEL


def _run_chat(args: argparse.Namespace) -> int:
    from zaynor.agents.chat_service import answer_question
    from zaynor.agents.contracts import Audience
    from zaynor.agents.ollama_client import OllamaClient, OllamaError

    if not _SAFE_CASE_ID.fullmatch(args.case_id):
        raise CliInputError("case-id must be a bounded path-safe identifier")
    if not isinstance(args.question, str) or not args.question.strip():
        raise CliInputError("question must not be empty")
    output_root = _directory_path(args.output_root)
    output_case_dir = output_root / args.case_id
    result, seal = load_verified_stored_case(
        args.case_id, output_case_dir / "result.json", output_case_dir / "result.seal.json"
    )
    try:
        audience = Audience(args.audience)
    except ValueError as exc:
        raise CliInputError(f"unknown audience: {args.audience}") from exc
    try:
        client = OllamaClient(host=args.host, model=_resolve_model(args.model), timeout_seconds=args.timeout)
        checked = answer_question(args.question, result=result, seal=seal, client=client, audience=audience)
    except OllamaError as exc:
        raise CliInputError(f"chat failed: {exc}") from exc
    if args.json:
        payload = {"narration": checked.safe_narration, **checked.to_dict()}
        _emit(payload, as_json=True)
    else:
        print(checked.safe_narration)
        if checked.suspicious:
            print(
                f"\n[warning] {checked.claims_hallucinated} unsupported claim(s) removed "
                f"out of {checked.claims_total}; see --json for detail",
                file=sys.stderr,
            )
    return 0


def _run_serve(args: argparse.Namespace) -> int:
    output_root = _directory_path(args.output_root)
    cases_root = _directory_path(args.cases_root) if args.cases_root else None
    try:
        import uvicorn

        from zaynor.api import create_app
    except ImportError as exc:
        raise CliInputError(
            "serve requires the optional 'api' dependencies: pip install -e '.[api]'"
        ) from exc
    app = create_app(
        output_root=output_root,
        cases_root=cases_root,
        ollama_host=args.ollama_host,
        model=_resolve_model(args.model),
        timeout_seconds=args.timeout,
    )
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


def _run_report(args: argparse.Namespace) -> int:
    from zaynor.report import ReportError, render_html, render_markdown, render_pdf

    if not _SAFE_CASE_ID.fullmatch(args.case_id):
        raise CliInputError("case-id must be a bounded path-safe identifier")
    output_root = _directory_path(args.output_root)
    output_case_dir = output_root / args.case_id
    result = _load_stored_result(args.case_id, output_case_dir / "result.json")
    seal = _load_stored_seal(output_case_dir / "result.seal.json")
    try:
        if args.format == "md":
            rendered: str | bytes = render_markdown(result, seal)
            mode = "w"
        elif args.format == "html":
            rendered = render_html(result, seal)
            mode = "w"
        else:
            rendered = render_pdf(result, seal)
            mode = "wb"
    except ReportError as exc:
        raise CliInputError(str(exc)) from exc
    out_path = Path(args.out) if args.out else output_case_dir / f"report.{args.format}"
    if out_path.exists() and out_path.is_symlink():
        raise CliInputError(f"output path must not be a symlink: {out_path}")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if mode == "w":
        out_path.write_text(rendered, encoding="utf-8")
    else:
        out_path.write_bytes(rendered)
    print(str(out_path))
    return 0


def _run_hunts(args: argparse.Namespace) -> int:
    """DISPATCHER, wired for real: a deterministic catalog lookup, no LLM
    round-trip needed (see agents/README.md's "before wiring a new role").
    """
    from zaynor.agents.dispatcher_tools import build_dispatcher_tools

    payload = build_dispatcher_tools()["list_hunts"]({})
    if args.json:
        _emit(payload, as_json=True)
    else:
        for hunt in payload["hunts"]:
            print(f"- {hunt['id']}: {hunt['description']}")
    return 0


def _run_consult(args: argparse.Namespace) -> int:
    """CONSULT, wired for real: read-only, sealed-package view of an already
    analyzed case -- the shape an external agent (a future MCP consumer
    included) is allowed to see. Never re-invokes the engine and never
    grants tool execution rights (see agents/README.md's package-seal
    mismatch note; this closes it by building the package from the
    already-verified stored result, not by changing what `analyze` seals).
    """
    from zaynor.agents.consult_tools import ConsultTools
    from zaynor.agents.dispatcher_tools import DEFAULT_HUNT_CATALOG
    from zaynor.framework_context import build_consult_package

    if not _SAFE_CASE_ID.fullmatch(args.case_id):
        raise CliInputError("case-id must be a bounded path-safe identifier")
    output_root = _directory_path(args.output_root)
    output_case_dir = output_root / args.case_id
    result, seal = load_verified_stored_case(
        args.case_id, output_case_dir / "result.json", output_case_dir / "result.seal.json"
    )
    package, package_seal = build_consult_package(result, seal)
    tools = ConsultTools(package, package_seal, hunts=DEFAULT_HUNT_CATALOG)
    payload = {
        "result": tools.explain_result(args.case_id),
        "framework": tools.explain_framework(),
        "hunts": tools.list_hunts(),
    }
    _emit(payload, as_json=args.json)
    return 0


def _run_models(args: argparse.Namespace) -> int:
    from zaynor.agents.model_catalog import SUGGESTED_MODELS
    from zaynor.agents.ollama_client import OllamaError, list_available_models

    installed: list[str] | None
    error: str | None
    try:
        installed = list_available_models(args.host)
        error = None
    except OllamaError as exc:
        installed = None
        error = str(exc)
    payload = {
        "installed": installed,
        "error": error,
        "suggested": [{"name": model.name, "tier": model.tier, "note": model.note} for model in SUGGESTED_MODELS],
        "env_var": _MODEL_ENV_VAR,
    }
    if args.json:
        _emit(payload, as_json=True)
        return 0
    if installed is None:
        print(f"No se pudo consultar Ollama en {args.host}: {error}")
    elif installed:
        print("Instalados localmente:")
        for name in installed:
            print(f"- {name}")
    else:
        print("Ningún modelo instalado todavía en Ollama.")
    print(f"\nNinguno es obligatorio — elegí el que quieras con --model o ${_MODEL_ENV_VAR}.")
    print("Sugeridos por tamaño de hardware:")
    for model in SUGGESTED_MODELS:
        print(f"- [{model.tier}] {model.name} — {model.note}  (ollama pull {model.name})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zaynor", description="Investigación DFIR local y trazable")
    subparsers = parser.add_subparsers(dest="command", required=True)

    replay_parser = subparsers.add_parser("replay", help="reproduce eventos de un fixture JSONL")
    replay_parser.add_argument("--fixture", required=True)
    replay_parser.add_argument("--json", action="store_true", help="emitir JSON estable")
    replay_parser.set_defaults(handler=_run_replay)

    detect_parser = subparsers.add_parser("detect", help="ejecutar la detección determinista")
    detect_parser.add_argument("--fixture", required=True)
    detect_parser.add_argument("--known-device", action="append", dest="known_device")
    detect_parser.add_argument("--json", action="store_true", help="emitir JSON estable")
    detect_parser.set_defaults(handler=_run_detect)

    case_parser = subparsers.add_parser("case", help="reproducir detección y abrir un caso candidato")
    case_parser.add_argument("--fixture", required=True)
    case_parser.add_argument("--known-device", action="append", dest="known_device")
    case_parser.add_argument("--window", type=int, default=CORRELATION_WINDOW_SECONDS)
    case_parser.add_argument("--evidence-profile", default="admin-session-investigation")
    case_parser.add_argument("--json", action="store_true", help="emitir JSON estable")
    case_parser.set_defaults(handler=_run_case)

    freeze_parser = subparsers.add_parser("freeze", help="congelar evidencia y crear el manifest del caso")
    freeze_parser.add_argument("--case-id", required=True)
    freeze_parser.add_argument("--evidence-profile", required=True)
    freeze_parser.add_argument("--profile-map", required=True)
    freeze_parser.add_argument("--source-root", required=True)
    freeze_parser.add_argument("--cases-root", required=True)
    freeze_parser.add_argument("--json", action="store_true", help="emitir JSON estable")
    freeze_parser.set_defaults(handler=_run_freeze)

    analyze_parser = subparsers.add_parser("analyze", help="analizar únicamente la evidencia del caso congelado")
    analyze_parser.add_argument("--case-id", required=True)
    analyze_parser.add_argument("--cases-root", required=True)
    analyze_parser.add_argument(
        "--engine-repo",
        default=None,
        help="path to the VIGÍA engine checkout; defaults to Zaynor's own vendored copy (vendor/vigia_engine/)",
    )
    analyze_parser.add_argument("--output-root", required=True)
    analyze_parser.add_argument("--python", default=None, help=argparse.SUPPRESS)
    analyze_parser.add_argument("--dev", action="store_true", help="habilitar opciones de desarrollo")
    analyze_parser.add_argument("--timeout", type=int, default=300)
    analyze_parser.add_argument("--json", action="store_true", help="emitir JSON estable")
    analyze_parser.set_defaults(handler=_run_analyze)

    audit_parser = subparsers.add_parser("audit", help="verificar artefactos almacenados sin reanalizar")
    audit_parser.add_argument("--case-id", required=True)
    audit_parser.add_argument("--cases-root", required=True)
    audit_parser.add_argument("--output-root", required=True)
    audit_parser.add_argument("--json", action="store_true", help="emitir JSON estable")
    audit_parser.set_defaults(handler=_run_audit)

    audit_trail_parser = subparsers.add_parser(
        "audit-trail", help="mostrar y verificar el audit.jsonl hash-chained de un caso"
    )
    audit_trail_parser.add_argument("--case-id", required=True)
    audit_trail_parser.add_argument("--cases-root", required=True)
    audit_trail_parser.add_argument("--json", action="store_true", help="emitir JSON estable")
    audit_trail_parser.set_defaults(handler=_run_audit_trail)

    reindex_parser = subparsers.add_parser(
        "reindex", help="reconstruir el índice derivado de casos (no autoritativo) desde cero"
    )
    reindex_parser.add_argument("--output-root", required=True)
    reindex_parser.add_argument("--json", action="store_true", help="emitir JSON estable")
    reindex_parser.set_defaults(handler=_run_reindex)

    chat_parser = subparsers.add_parser(
        "chat", help="preguntar sobre un caso ya analizado, narrado por un LLM local y verificado contra el sello"
    )
    chat_parser.add_argument("--case-id", required=True)
    chat_parser.add_argument("--output-root", required=True)
    chat_parser.add_argument("--question", required=True)
    chat_parser.add_argument("--audience", default="senior", choices=["junior", "senior"])
    chat_parser.add_argument("--host", default="http://127.0.0.1:11434", help="Ollama local-only")
    chat_parser.add_argument(
        "--model", default=None, help=f"por defecto, ${_MODEL_ENV_VAR} o el fallback de model_catalog.py"
    )
    chat_parser.add_argument("--timeout", type=int, default=120)
    chat_parser.add_argument("--json", action="store_true", help="emitir JSON estable")
    chat_parser.set_defaults(handler=_run_chat)

    serve_parser = subparsers.add_parser(
        "serve", help="exponer un API compatible con OpenAI/OpenWebUI sobre casos ya analizados"
    )
    serve_parser.add_argument("--output-root", required=True)
    serve_parser.add_argument(
        "--cases-root", default=None,
        help="raíz de casos congelados; habilita /cases/{id}/evidence y auditoría completa (opcional)",
    )
    serve_parser.add_argument("--host", default="127.0.0.1", help="dirección de escucha de este API")
    serve_parser.add_argument("--port", type=int, default=8420)
    serve_parser.add_argument("--ollama-host", default="http://127.0.0.1:11434", help="Ollama local-only")
    serve_parser.add_argument(
        "--model", default=None, help=f"por defecto, ${_MODEL_ENV_VAR} o el fallback de model_catalog.py"
    )
    serve_parser.add_argument("--timeout", type=int, default=120)
    serve_parser.set_defaults(handler=_run_serve)

    hunts_parser = subparsers.add_parser(
        "hunts", help="catálogo de tipos de investigación que Mode 1 puede analizar realmente (rol DISPATCHER)"
    )
    hunts_parser.add_argument("--json", action="store_true", help="emitir JSON estable")
    hunts_parser.set_defaults(handler=_run_hunts)

    consult_parser = subparsers.add_parser(
        "consult",
        help="vista de solo lectura sobre un caso ya sellado -- resultado, contexto MITRE/NIST/OWASP y catálogo de hunts (rol CONSULT)",
    )
    consult_parser.add_argument("--case-id", required=True)
    consult_parser.add_argument("--output-root", required=True)
    consult_parser.add_argument("--json", action="store_true", help="emitir JSON estable")
    consult_parser.set_defaults(handler=_run_consult)

    models_parser = subparsers.add_parser(
        "models", help="mostrar modelos de Ollama instalados y sugeridos por tamaño de hardware"
    )
    models_parser.add_argument("--host", default="http://127.0.0.1:11434", help="Ollama local-only")
    models_parser.add_argument("--json", action="store_true", help="emitir JSON estable")
    models_parser.set_defaults(handler=_run_models)

    report_parser = subparsers.add_parser(
        "report", help="generar un reporte legible (md/html/pdf) sobre un resultado ya sellado"
    )
    report_parser.add_argument("--case-id", required=True)
    report_parser.add_argument("--output-root", required=True)
    report_parser.add_argument("--format", choices=["md", "html", "pdf"], default="md")
    report_parser.add_argument("--out", default=None, help="por defecto, <output-root>/<case-id>/report.<format>")
    report_parser.set_defaults(handler=_run_report)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "window", 1) <= 0 or getattr(args, "timeout", 1) <= 0:
        parser.error("--window y --timeout deben ser positivos")
    try:
        return args.handler(args)
    except CliInputError as exc:
        print(f"zaynor: error de entrada: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
