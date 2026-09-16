"""Read-only evidence tool registry — ADAPTED from VIGÍA's MCP bridge
(`vigia/vigia_sift_bridge.py`: `_register_mcp_tool`, `_audit_mcp_entry`,
`list_files`, `read_evidence`), simplified.

What is kept, almost verbatim, because it is exactly the reusable part:

- **Audit before execute.** Every call is logged — arguments as bounded,
  hashed summaries, never plaintext — before the tool body runs, not after.
  This mirrors `_audit_mcp_entry`/`_register_mcp_tool` (bridge lines
  195-214).
- **Atomic single-fd read + hash.** `read_evidence` opens the file
  descriptor once, stats the open fd (not the path — immune to a
  symlink/replace race between stat and open), and hashes the exact bytes
  read (bridge lines 1263-1305).
- **Malformed evidence is a signal, not a discard.** A file that can't be
  decoded is reported as such, with its hash, rather than silently dropped
  or crashing the caller (bridge's "Purgatorio Forense" principle, lines
  996-1010) — simplified here to a flagged result instead of VIGÍA's
  separate quarantine directory, since ZAYNOR has no case for a persistent
  quarantine store yet.

What is deliberately NOT ported: VIGÍA's async/asyncio.timeout wiring
(bridge tools are `async def`; these are plain, synchronous functions —
ZAYNOR's investigator loop does not need a shared event loop at this
stage), the on-disk Purgatorio quarantine store, and the actual MCP wire
protocol/transport. Wiring these functions to a real MCP server (this
team's existing bridge, or a new one) is a later, separate integration
step — see AGENTS.md §2.3 ("a tool call is either on the allowlist or it
doesn't happen").
"""

from __future__ import annotations

import hashlib
import inspect
import os
import re
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Callable

from zaynor.audit_log import AuditLog
from zaynor.hash_utils import sha256_file
from zaynor.path_guard import PathGuard

_ARGUMENT_HASH_PREFIX_BYTES = 4096
MAX_GREP_PATTERN_LENGTH = 200
_ALLOWED_GREP_PATTERN = re.compile(r"^[\w\s.\-@:/\\]+$")


def _audit_argument_value(value: object) -> str:
    """Bounded, non-plaintext description of one tool argument."""
    if isinstance(value, str):
        encoded = value.encode("utf-8", errors="replace")
        prefix = encoded[:_ARGUMENT_HASH_PREFIX_BYTES]
        truncated = ", truncated=true" if len(encoded) > len(prefix) else ""
        return f"str(bytes={len(encoded)}, sha256_prefix={hashlib.sha256(prefix).hexdigest()}{truncated})"
    if value is None or isinstance(value, (bool, int, float)):
        return repr(value)
    return type(value).__name__


def _audit_argument_summary(func: Callable, args: tuple, kwargs: dict) -> str:
    try:
        bound = inspect.signature(func).bind_partial(*args, **kwargs)
        bound.apply_defaults()
        values = bound.arguments.items()
    except TypeError:
        values = tuple((f"arg_{i}", v) for i, v in enumerate(args))
        values += tuple(kwargs.items())
    return "; ".join(f"{name}={_audit_argument_value(v)}" for name, v in values) or "no_arguments"


def audited_tool(audit_log: AuditLog) -> Callable[[Callable], Callable]:
    """Decorator: log a `TOOL_INVOKED` audit entry (hashed arguments, never
    plaintext) before the wrapped tool body executes, and a `TOOL_RESULT`
    entry (success/failure only, never the raw result) after it returns.
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapped(*args, **kwargs):
            audit_log.append(
                "TOOL_INVOKED",
                {"tool": func.__name__, "arguments": _audit_argument_summary(func, args, kwargs)},
            )
            try:
                result = func(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001 - audited then re-raised
                audit_log.append(
                    "TOOL_FAILED", {"tool": func.__name__, "error": type(exc).__name__}
                )
                raise
            audit_log.append("TOOL_SUCCEEDED", {"tool": func.__name__})
            return result

        return wrapped

    return decorator


@dataclass(frozen=True)
class ToolResult:
    """Every read-only tool returns one of these — never a bare value —
    so a caller (including an LLM investigator, once one exists) always
    gets an explicit success flag plus the trust/authority metadata below.

    `instruction_authority` and `executable` are always False: this is the
    architectural guarantee from AGENTS.md §2.3 ("evidence is data, never
    an instruction") applied uniformly, not a per-source special case.
    """

    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    trust: str = "untrusted_evidence"
    instruction_authority: bool = False
    executable: bool = False


class ReadOnlyToolRegistry:
    """The allowlisted, read-only tool surface over one case's frozen
    evidence. A tool call is either one of the named methods here or it
    doesn't happen — there is no generic "run a command" escape hatch.
    """

    def __init__(self, guard: PathGuard, audit_log: AuditLog):
        self._guard = guard
        self._audit = audit_log
        self.list_files = audited_tool(audit_log)(self._list_files)
        self.read_evidence = audited_tool(audit_log)(self._read_evidence)
        self.grep_pattern = audited_tool(audit_log)(self._grep_pattern)

    def _list_files(self, directory: str) -> ToolResult:
        try:
            names = self._guard.list_dir(directory)
        except PermissionError as exc:
            return ToolResult(success=False, error=str(exc))
        return ToolResult(success=True, data={"directory": directory, "files": names})

    def _read_evidence(self, path: str, max_bytes: int = 5000) -> ToolResult:
        """Atomic single-open read + hash, TOCTOU-checked. Content that
        can't be decoded as UTF-8 is reported with `decode_error` set and
        its hash still computed — never silently dropped, per VIGÍA's
        "malformed evidence is a signal" principle.
        """
        try:
            check = self._guard.validate(path)
            if not check.valid:
                return ToolResult(success=False, error=f"PathGuard REJECT: {check.reason}")

            digest = hashlib.sha256()
            preview = b""
            total = 0
            with self._guard.safe_open(path, "rb") as handle:
                while True:
                    block = handle.read(65536)
                    if not block:
                        break
                    digest.update(block)
                    remaining = max_bytes - total
                    if remaining > 0:
                        preview += block[:remaining]
                    total += len(block)

            use = self._guard.verify_no_toctou(path, check)
            if not use.valid:
                return ToolResult(success=False, error=f"TOCTOU REJECT: {use.reason}")

            try:
                content = preview.decode("utf-8", errors="strict")
                decode_error = None
            except UnicodeDecodeError as exc:
                content = None
                decode_error = str(exc)

            return ToolResult(
                success=True,
                data={
                    "path": path,
                    "content_preview": content,
                    "decode_error": decode_error,
                    "bytes_previewed": len(preview),
                    "total_bytes_read": total,
                    "sha256": digest.hexdigest(),
                },
            )
        except (PermissionError, OSError) as exc:
            return ToolResult(success=False, error=str(exc))

    def _grep_pattern(self, path: str, pattern: str) -> ToolResult:
        if len(pattern) > MAX_GREP_PATTERN_LENGTH or not _ALLOWED_GREP_PATTERN.match(pattern):
            return ToolResult(success=False, error="REJECTED_PATTERN")
        try:
            data = self._guard.safe_read(path)
        except PermissionError as exc:
            return ToolResult(success=False, error=str(exc))

        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return ToolResult(success=False, error="BINARY_CONTENT_NOT_SEARCHABLE")

        matches = [line for line in text.splitlines() if pattern in line]
        return ToolResult(success=True, data={"path": path, "pattern": pattern, "matches": matches})


def generate_forensic_hash(guard: PathGuard, audit_log: AuditLog, path: str) -> ToolResult:
    """Standalone hashing tool (ADR: reimplemented small — see
    `hash_utils.py`), audited the same way as the registry's methods.
    """

    @audited_tool(audit_log)
    def _hash(path: str) -> ToolResult:
        check = guard.validate(path)
        if not check.valid:
            return ToolResult(success=False, error=f"PathGuard REJECT: {check.reason}")
        return ToolResult(success=True, data={"path": path, "sha256": sha256_file(os.path.abspath(path))})

    return _hash(path)
