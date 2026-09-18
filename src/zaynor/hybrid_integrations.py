"""Offline evidence, reasoning-trace, and memory integration boundaries.

This module is deliberately small. ZAYNOR owns the adapted Velociraptor
collection adapter under ``tools/velociraptor`` and accepts its sealed,
verified evidence window through the existing case-freeze boundary. The
``annaconda`` names below are compatibility labels for the original window
contract and hash recipe, not a claim that collection still lives in another
repository. CRONOS and MNEME are optional sinks for investigation context.
They receive observations and summaries, never authoritative results or seals.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Protocol

from vendor.vigia_engine.vigia.core.canonicalize import _canonicalize


class HybridIntegrationError(ValueError):
    """A boundary input is invalid or failed closed."""


def _canonical_hash(value: Any) -> bytes:
    # Keep byte-for-byte lockstep with ANNACONDA's _sha256_canonical().
    return json.dumps(_canonicalize(value), sort_keys=True, ensure_ascii=True).encode()


def _json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _safe_output_path(root: Path, relative: str) -> Path:
    """Return a confined output path and reject symlink components."""
    root = root.resolve(strict=True)
    candidate = root / relative
    resolved = candidate.resolve(strict=False)
    if resolved != root and root not in resolved.parents:
        raise HybridIntegrationError("materialized evidence path escapes staging root")
    current = root
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink():
            raise HybridIntegrationError("materialized evidence path contains a symlink")
    return candidate


def verify_annaconda_window(window: dict[str, Any]) -> None:
    """Fail closed unless the adapted evidence-window contract verifies."""
    if not isinstance(window, dict) or not isinstance(window.get("window_hash"), str):
        raise HybridIntegrationError("evidence window is missing window_hash")
    body = {key: value for key, value in window.items() if key != "window_hash"}
    actual = hashlib.sha256(_canonical_hash(body)).hexdigest()
    if actual != window["window_hash"]:
        raise HybridIntegrationError("evidence window hash does not verify")
    if not isinstance(window.get("case_id"), str) or not window["case_id"]:
        raise HybridIntegrationError("evidence window is missing case_id")
    if not isinstance(window.get("artifacts"), list):
        raise HybridIntegrationError("evidence window artifacts must be a list")


def materialize_window(
    window: dict[str, Any], staging_root: Path, *, expected_case_id: str | None = None
) -> tuple[Path, dict[str, list[str]]]:
    """Write a verified window as freezeable JSON evidence.

    The returned profile map is intended for ``case_freezer.freeze_case``.
    Files are content-addressed and contain the normalized artifact records;
    no score or verdict is computed here. Existing ZAYNOR freeze code remains
    responsible for manifest and custody creation.
    """
    verify_annaconda_window(window)
    root = Path(staging_root)
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink():
        raise HybridIntegrationError("staging root cannot be a symlink")
    if expected_case_id is not None and window["case_id"] != expected_case_id:
        raise HybridIntegrationError("evidence window case_id does not match requested case")
    files: list[str] = []
    for index, artifact in enumerate(window["artifacts"]):
        if not isinstance(artifact, dict):
            raise HybridIntegrationError(f"artifact {index} is not an object")
        artifact_id = artifact.get("artifact_id")
        if not isinstance(artifact_id, str) or not artifact_id:
            raise HybridIntegrationError(f"artifact {index} is missing artifact_id")
        filename = f"velociraptor/{index:06d}-{artifact_id}.json"
        path = _safe_output_path(root, filename)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            raise HybridIntegrationError("materialized evidence path cannot be a symlink")
        path.write_bytes(_json(artifact) + b"\n")
        files.append(filename)
    metadata = {
        "case_id": window["case_id"],
        "window_id": window.get("window_id", ""),
        "window_hash": window["window_hash"],
        "artifact_count": len(files),
    }
    (root / "velociraptor").mkdir(parents=True, exist_ok=True)
    window_path = _safe_output_path(root, "velociraptor/window.json")
    if window_path.is_symlink():
        raise HybridIntegrationError("materialized window metadata cannot be a symlink")
    window_path.write_bytes(_json(metadata) + b"\n")
    files.append("velociraptor/window.json")
    return root, {"annaconda-window": files}


def freeze_verified_window(
    window: dict[str, Any], staging_root: Path, cases_root: Path, *, expected_case_id: str | None = None
):
    """Materialize and freeze a verified window through ZAYNOR's freezer."""
    from zaynor.case_freezer import freeze_case

    verify_annaconda_window(window)
    case_id = expected_case_id or window["case_id"]
    root, profile_map = materialize_window(
        window, staging_root, expected_case_id=case_id
    )
    return freeze_case(case_id, "annaconda-window", profile_map, root, Path(cases_root))


class ReasoningTraceSink(Protocol):
    """Subset implemented by CRONOS or a CRONOS MCP client."""

    def record_evidence(self, text: str, *, reference: str = "") -> None: ...
    def record_tool(self, tool: str, result_summary: str) -> None: ...
    def close(self, decision_summary: str) -> None: ...


class MemorySink(Protocol):
    """Subset implemented by MNEME or a MNEME MCP client."""

    def store(self, content: str, *, topic: str, claim: str, reason: str) -> str: ...


def record_window_context(window: dict[str, Any], sink: ReasoningTraceSink | None) -> None:
    """Record collection context in CRONOS without exposing authority."""
    if sink is None:
        return
    verify_annaconda_window(window)
    sink.record_tool(
        "annaconda.evidence_window",
        f"verified window {window.get('window_id', '')}; "
        f"artifacts={len(window['artifacts'])}; hash={window['window_hash']}",
    )
    for artifact in window["artifacts"]:
        sink.record_evidence(
            f"Observed normalized artifact {artifact['artifact_id']}",
            reference=artifact["artifact_id"],
        )


def remember_window_summary(window: dict[str, Any], sink: MemorySink | None) -> str | None:
    """Store a bounded, non-authoritative evidence summary in MNEME."""
    if sink is None:
        return None
    verify_annaconda_window(window)
    content = (
        f"Verified offline evidence window {window.get('window_id', '')} for "
        f"case {window['case_id']}; artifacts={len(window['artifacts'])}; "
        f"window_hash={window['window_hash']}"
    )
    return sink.store(
        content,
        topic=f"zaynor:{window['case_id']}",
        claim="evidence-window-observed",
        reason="record verified collection context; it is not a result",
    )
