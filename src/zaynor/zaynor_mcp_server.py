"""ZAYNOR-owned MCP server for case-bound memory and audit inspection.

Inspired by CRONOS and MNEME, but implemented on ZAYNOR contracts. The
server is deliberately not a verdict engine: it can record investigator
hypotheses and questions and verify/read audit state, never authoritative
results or seals.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from zaynor.audit_log import AuditLog
from zaynor.investigation_log import (
    add_hypothesis,
    new_investigation_log,
    note_open_question,
    verify_log,
)

_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_TEXT = 2_000

mcp = FastMCP("zaynor")


class ZaynorMCPError(ValueError):
    """Invalid case-bound MCP input."""


def _case_dir(case_id: str, *, create: bool = True) -> Path:
    if not isinstance(case_id, str) or not _CASE_ID.fullmatch(case_id):
        raise ZaynorMCPError("case_id is invalid")
    root = Path(os.environ.get("ZAYNOR_MCP_STATE_DIR", "state")).resolve()
    path = (root / "cases" / case_id).resolve()
    if root not in path.parents:
        raise ZaynorMCPError("case path escapes configured state directory")
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def _text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT:
        raise ZaynorMCPError(f"{field} must be non-empty and at most {_MAX_TEXT} characters")
    return value.strip()


def _memory_path(case_id: str, *, create: bool = True) -> Path:
    return _case_dir(case_id, create=create) / "investigation.json"


def _load_memory(case_id: str) -> dict[str, Any]:
    path = _memory_path(case_id, create=False)
    if not path.exists():
        return new_investigation_log(case_id)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ZaynorMCPError("investigation memory could not be loaded") from exc
    if value.get("case_id") != case_id or not verify_log(value)["log_ok"]:
        raise ZaynorMCPError("investigation memory failed integrity verification")
    return value


def _save_memory(case_id: str, value: dict[str, Any]) -> None:
    path = _memory_path(case_id)
    payload = json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2)
    fd, temporary = tempfile.mkstemp(prefix=".investigation-", dir=path.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _audit_path(case_id: str) -> Path:
    return _case_dir(case_id, create=False) / "audit.jsonl"


@mcp.tool()
def zaynor_info() -> dict[str, Any]:
    return {
        "name": "ZAYNOR",
        "purpose": "case-bound investigation memory and audit verification",
        "authority": "result.json + result.seal.json verified by ZAYNOR",
        "verdict_mutation": False,
        "tools": [
            "zaynor_info", "zaynor_verify_audit", "zaynor_verify_memory",
            "zaynor_list_memory", "zaynor_add_hypothesis", "zaynor_note_question",
        ],
    }


@mcp.tool()
def zaynor_verify_audit(case_id: str) -> dict[str, Any]:
    """Verify the case audit chain without changing it."""
    ok, report = AuditLog.verify_with_report(_audit_path(case_id), case_id=case_id)
    return {"case_id": case_id, "verified": ok, "report": report}


@mcp.tool()
def zaynor_verify_memory(case_id: str) -> dict[str, Any]:
    """Verify the investigator memory chain without changing it."""
    memory = _load_memory(case_id)
    result = verify_log(memory)
    return {"case_id": case_id, **result}


@mcp.tool()
def zaynor_list_memory(case_id: str) -> dict[str, Any]:
    """List case-bound hypotheses and questions; no authoritative claims."""
    memory = _load_memory(case_id)
    verification = verify_log(memory)
    if not verification["log_ok"]:
        raise ZaynorMCPError("investigation memory failed integrity verification")
    return {
        "case_id": case_id,
        "hypotheses": memory["hypotheses"],
        "open_questions": memory["open_questions"],
        "verification": verification,
    }


@mcp.tool()
def zaynor_add_hypothesis(case_id: str, actor: str, text: str) -> dict[str, Any]:
    memory = _load_memory(case_id)
    result = add_hypothesis(memory, actor=_text(actor, "actor"), text=_text(text, "text"))
    _save_memory(case_id, memory)
    return {"case_id": case_id, "hypothesis": result, "authority": "none"}


@mcp.tool()
def zaynor_note_question(case_id: str, actor: str, question: str, what_would_resolve: str) -> dict[str, Any]:
    memory = _load_memory(case_id)
    result = note_open_question(
        memory,
        actor=_text(actor, "actor"),
        question=_text(question, "question"),
        what_would_resolve=_text(what_would_resolve, "what_would_resolve"),
    )
    _save_memory(case_id, memory)
    return {"case_id": case_id, "question": result, "authority": "none"}


def main() -> None:
    # Trio is required for the MCP SDK stdio backend in the supported runtime.
    import anyio
    anyio.run(mcp.run_stdio_async, backend="trio")


if __name__ == "__main__":
    main()
