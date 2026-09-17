"""Typed contracts for stages 1-4 of the ZAYNOR pipeline (telemetry replay
through case freeze). Stage 5+ contracts (EvidenceRef, Finding, the
ZaynorAuthoritativeResult returned by the VIGÍA adapter) are defined when
that adapter is built, not here — see AGENTS.md ("Scope: the hybrid
pipeline") for the stage boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar


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

    `sha256` (per entry) is *byte identity/integrity* under this manifest —
    it says the bytes referenced here are the bytes read at freeze time. It
    is not proof of truth, authorship, or completeness of the underlying
    evidence.

    Two manifest-level hashes, deliberately distinct:

    - `content_sha256` is fully DETERMINISTIC: a hash over the sorted
      (relative_path, sha256) pairs alone. Freezing the same evidence set
      twice produces the same `content_sha256`, at any time, on any
      machine — it is the case's content identity.
    - `sealed_at_sha256` additionally folds in `sealed_at` (the freeze
      timestamp), so it is DIFFERENT for every freeze even when
      `content_sha256` is identical — it is this specific sealing EVENT's
      identity, not the content's. Comparing the two tells you whether two
      manifests describe the same evidence (`content_sha256` matches) that
      was frozen at different times (`sealed_at_sha256` differs) — a
      replayed-old-bundle-as-if-new attempt changes `sealed_at_sha256`
      only if `sealed_at` itself is honestly refreshed; this field does not
      by itself prove *when* something happened, only that a comparison
      says "not the same sealing event."
    """

    case_id: str
    entries: tuple[ManifestEntry, ...]
    content_sha256: str
    sealed_at: str
    sealed_at_sha256: str


@dataclass(frozen=True)
class EvidenceRef:
    """Stable reference to frozen evidence, including its lineage."""

    # Architecture audit finding (GAP-02): `authority_seal.py::_typed` used
    # to embed `f"{__module__}.{__qualname__}"` in the canonical, sealed
    # payload for every dataclass reachable from a sealed result. Moving
    # this class to a different module -- a plain import-hygiene refactor,
    # not a data change -- would have invalidated every previously-sealed
    # result's digest, indistinguishable from real tampering. A literal,
    # explicitly-chosen name decouples the digest from where the code
    # happens to live. ClassVar: not a dataclass field, never touches
    # `fields()`/the constructor.
    _CANONICAL_TYPE_NAME: ClassVar[str] = "zaynor.evidence_ref"

    artifact: str
    lineage_id: str


@dataclass(frozen=True)
class AuthoritativeFinding:
    """ZAYNOR-owned finding contract translated from VIGÍA output."""

    _CANONICAL_TYPE_NAME: ClassVar[str] = "zaynor.authoritative_finding"

    finding_id: str
    state: str
    evidence_refs: tuple[EvidenceRef, ...] = ()
    lineage_ids: tuple[str, ...] = ()
    rationale: str = ""
    mitre: dict[str, Any] | None = None
    nist: dict[str, Any] | None = None


# Architecture audit finding (GAP-02), the other half: `CANONICALIZE_VERSION`
# in authority_seal.py versions the canonicalization *algorithm*, not the
# *shape* of this dataclass. Adding a field here (even with a default) makes
# a historical result rehydrate with that field present, produce different
# canonical bytes than whatever sealed it originally, and fail with the
# exact same "authoritative result seal mismatch" a real tamper produces --
# no way to tell the two apart. Bump this string, deliberately, whenever a
# field is added, removed, or renamed on this class or on `AuthoritativeFinding`/
# `EvidenceRef`; `verify_authoritative_result` checks it before the digest
# comparison and raises a distinct, named error when it differs, instead of
# folding a schema change into a generic "mismatch".
RESULT_SCHEMA_VERSION = "zaynor-result-v1"


@dataclass(frozen=True)
class ZaynorAuthoritativeResult:
    """Stable authority-boundary contract; no VIGÍA object crosses it."""

    _CANONICAL_TYPE_NAME: ClassVar[str] = "zaynor.authoritative_result"

    case_id: str
    engine: dict[str, str]
    verdict: str = "UNKNOWN"
    observations: tuple[dict[str, Any], ...] = ()
    timeline: tuple[dict[str, Any], ...] = ()
    fractures: tuple[dict[str, Any], ...] = ()
    hypotheses: tuple[dict[str, Any], ...] = ()
    findings: tuple[AuthoritativeFinding, ...] = ()
    unknowns: tuple[str, ...] = ()
    provenance: tuple[dict[str, Any], ...] = ()
    integrity: dict[str, Any] = field(default_factory=dict)
    audit_refs: tuple[str, ...] = ()
    schema_version: str = RESULT_SCHEMA_VERSION
