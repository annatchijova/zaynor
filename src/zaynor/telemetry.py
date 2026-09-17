"""Optional OpenTelemetry spans over ZAYNOR's postmortem pipeline.

This is observability, not evidence. Importing opentelemetry, exporting a
span, or a collector being unreachable must never change a sealed result
or the audit log's hash chain — telemetry stays strictly downstream of the
sealed decision, the same rule CLAUDE.md 5.1 applies to the LLM narrator.
If `opentelemetry-sdk` is not installed, every function here degrades to a
no-op: the postmortem pipeline runs identically with or without it
(CLAUDE.md 5.3 — an absent optional component degrades the feature, never
the core).

Design: rather than a stored/looked-up span context — a second piece of
per-case mutable state to keep consistent with the audit log — the trace
id and the pipeline's root span id are BOTH pure functions of `case_id`,
same derivation discipline as `audit_log.genesis_hash`. Any process that
knows a case_id (this CLI, a future MCP consumer, an external OTel
dashboard correlating against the team's live Velociraptor/OpenTelemetry
telemetry) can recompute the identical trace id with zero coordination and
no shared file that could go stale.

Each real pipeline step (CASE_FROZEN, ENGINE_INVOKED, RESULT_SEALED,
TOOL_INVOKED, ...) becomes one child span of that deterministic root,
annotated from the very `AuditEntry` already written to `audit.jsonl` —
one source of truth for what happened, not a second independent account
of it.
"""

from __future__ import annotations

import hashlib
import warnings
from contextlib import contextmanager
from typing import Any, Iterator

_TRACE_ID_NAMESPACE = b"ZAYNOR_OTEL_TRACE:"
_ROOT_SPAN_NAMESPACE = b"ZAYNOR_OTEL_ROOT_SPAN:"
_TRACER_NAME = "zaynor.postmortem"

_warned_missing_sdk = False


def _require_case_id(case_id: str) -> str:
    if not isinstance(case_id, str) or not case_id:
        raise ValueError("case_id must be a non-empty string")
    return case_id


def case_trace_id(case_id: str) -> int:
    """128-bit W3C trace id, deterministic from `case_id` alone.

    Two runs of the pipeline against the same case — freeze in one process,
    analyze in another, chat in a third — land in the same trace without
    any span context ever crossing a process boundary.
    """
    digest = hashlib.sha256(_TRACE_ID_NAMESPACE + _require_case_id(case_id).encode("utf-8")).digest()[:16]
    value = int.from_bytes(digest, "big")
    # W3C forbids an all-zero trace id. Astronomically unreachable via
    # SHA-256, guarded anyway rather than trusted to never happen.
    return value or 1


def case_root_span_id(case_id: str) -> int:
    """64-bit root span id, deterministic from `case_id`.

    Derived under a different namespace prefix than `case_trace_id` so one
    is not trivially recoverable from the other — not a security boundary,
    just avoiding an accidental structural coupling between the two ids.
    """
    digest = hashlib.sha256(_ROOT_SPAN_NAMESPACE + _require_case_id(case_id).encode("utf-8")).digest()[:8]
    value = int.from_bytes(digest, "big")
    return value or 1  # W3C forbids an all-zero span id


@contextmanager
def postmortem_span(
    case_id: str, name: str, attributes: dict[str, Any] | None = None, *, tracer: Any = None
) -> Iterator[Any]:
    """Start one child span of the case's deterministic root span.

    Degrades honestly: absent `opentelemetry-sdk`, yields `None` and warns
    once per process — the caller's real work runs unaffected either way,
    since nothing in the pipeline reads the yielded span to make a
    decision. `tracer` is exposed for tests; production callers omit it and
    get the process's real global tracer.
    """
    try:
        from opentelemetry import trace
        from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags
    except ImportError:
        global _warned_missing_sdk
        if not _warned_missing_sdk:
            warnings.warn(
                "opentelemetry-sdk not installed -- postmortem spans disabled, "
                "the pipeline itself is unaffected (install the 'telemetry' extra to enable)",
                RuntimeWarning,
                stacklevel=2,
            )
            _warned_missing_sdk = True
        yield None
        return

    parent_context = SpanContext(
        trace_id=case_trace_id(case_id),
        span_id=case_root_span_id(case_id),
        is_remote=True,
        trace_flags=TraceFlags(TraceFlags.SAMPLED),
    )
    ctx = trace.set_span_in_context(NonRecordingSpan(parent_context))
    active_tracer = tracer if tracer is not None else trace.get_tracer(_TRACER_NAME)
    with active_tracer.start_as_current_span(name, context=ctx, attributes=attributes or {}) as span:
        yield span


def annotate_with_audit_entry(span: Any, entry: Any) -> None:
    """Copy an `AuditEntry`'s own fields onto an already-open span.

    The span carries exactly what the audit log recorded — case_id,
    action, reason, the entry's own hash and sequence number — never a
    second, independently-assembled account of what happened. A `None`
    span (SDK absent) is a silent no-op.
    """
    if span is None:
        return
    span.set_attribute("zaynor.case_id", entry.case_id)
    span.set_attribute("zaynor.audit.action", entry.action)
    span.set_attribute("zaynor.audit.reason", entry.reason)
    span.set_attribute("zaynor.audit.entry_hash", entry.entry_hash)
    span.set_attribute("zaynor.audit.seq", entry.seq)
