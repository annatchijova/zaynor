"""Typed contracts for stages 1-4 of the ZAYNOR pipeline (telemetry replay
through case freeze). Stage 5+ contracts (EvidenceRef, Finding, the
ZaynorAuthoritativeResult returned by the VIGÍA adapter) are defined when
that adapter is built, not here — see AGENTS.md ("Scope: the hybrid
pipeline") for the stage boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class TelemetryEvent:
    """One synthetic telemetry record from the stage-1 replay.

    `event_id` is assigned by the replay when the event is emitted, not
    stored in the fixture file — it is a hash of the event's own fields, so
    two fixtures with identical content produce identical ids.
    """

    event_id: str
    logical_time: int
    event_type: str
    fields: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Alert:
    """Output of a stage-2 detection rule firing on one or more events."""

    alert_id: str
    rule_id: str
    severity: str
    reason: str
    triggering_event_ids: tuple[str, ...]


@dataclass(frozen=True)
class Correlation:
    """Output of stage-3 correlation: groups alerts into a candidate case."""

    correlation_id: str
    alert_ids: tuple[str, ...]
    fingerprint: str
    priority: str


@dataclass(frozen=True)
class Case:
    """A declared incident, before it is frozen (stage 4)."""

    case_id: str
    opened_by_rule_id: str
    opened_by_alert_ids: tuple[str, ...]
    correlation_id: str
    priority: str
    evidence_profile: str


@dataclass(frozen=True)
class ManifestEntry:
    """One artifact captured by the case freezer, with its integrity hash."""

    relative_path: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class CaseManifest:
    """The frozen case: an immutable, hashed inventory of evidence.

    `sha256` is *byte identity/integrity* under this manifest — it says the
    bytes referenced here are the bytes read at freeze time. It is not proof
    of truth, authorship, or completeness of the underlying evidence.
    """

    case_id: str
    entries: tuple[ManifestEntry, ...]
