"""Proposed defensive response actions.

Zaynor proposes; it never remediates automatically. There is no function
anywhere in this module that executes an action — only ones that
construct and validate a proposal. `status` and `requires_human_approval`
are fixed by construction (the dataclass fields are `init=False`, so no
caller can pass a different value in): a `ResponseAction` that claims to
be already executed, or that skips human approval, cannot be constructed
at all. An execution path, if one is ever built, is a deliberate, separate,
human-gated system this module does not provide.

Schema follows the shape agreed for the product:

    action:
      category: containment
      reason: ...
      evidence_refs: [...]
      risk: ...
      reversibility: ...
      requires_human_approval: true
      status: proposed
"""

from __future__ import annotations

from dataclasses import dataclass, field

from zaynor.schemas import EvidenceRef, ZaynorAuthoritativeResult

# NIST incident-response lifecycle categories (SP 800-61) — this module
# structures *when in the response cycle* an action belongs, it does not
# implement or execute the NIST process itself.
_VALID_CATEGORIES = frozenset({"identification", "containment", "eradication", "recovery"})
_VALID_RISK = frozenset({"LOW", "MEDIUM", "HIGH"})
_VALID_REVERSIBILITY = frozenset({"REVERSIBLE", "PARTIALLY_REVERSIBLE", "IRREVERSIBLE"})


class ResponseActionError(ValueError):
    """A proposed response action failed validation before it could exist."""


@dataclass(frozen=True)
class ResponseAction:
    action_id: str
    category: str
    reason: str
    evidence_refs: tuple[EvidenceRef, ...]
    risk: str
    reversibility: str
    requires_human_approval: bool = field(default=True, init=False)
    status: str = field(default="proposed", init=False)

    def __post_init__(self) -> None:
        if not self.action_id.strip():
            raise ResponseActionError("action_id must be a non-empty string")
        if self.category not in _VALID_CATEGORIES:
            raise ResponseActionError(f"category must be one of {sorted(_VALID_CATEGORIES)}, not {self.category!r}")
        if not self.reason.strip():
            raise ResponseActionError("reason must be a non-empty string")
        if not self.evidence_refs:
            raise ResponseActionError("a proposed action must cite at least one evidence_ref — no unsupported proposals")
        if self.risk not in _VALID_RISK:
            raise ResponseActionError(f"risk must be one of {sorted(_VALID_RISK)}, not {self.risk!r}")
        if self.reversibility not in _VALID_REVERSIBILITY:
            raise ResponseActionError(
                f"reversibility must be one of {sorted(_VALID_REVERSIBILITY)}, not {self.reversibility!r}"
            )

    def to_dict(self) -> dict:
        return {
            "action": {
                "action_id": self.action_id,
                "category": self.category,
                "reason": self.reason,
                "evidence_refs": [{"artifact": r.artifact, "lineage_id": r.lineage_id} for r in self.evidence_refs],
                "risk": self.risk,
                "reversibility": self.reversibility,
                "requires_human_approval": self.requires_human_approval,
                "status": self.status,
            }
        }


def propose_response_action(
    *,
    action_id: str,
    category: str,
    reason: str,
    evidence_refs: tuple[EvidenceRef, ...],
    risk: str,
    reversibility: str,
    authorized_result: ZaynorAuthoritativeResult,
) -> ResponseAction:
    """The only way to create a `ResponseAction` — a thin, named
    constructor kept separate from the dataclass itself so a future
    execution-tracking system (if one is ever built) cannot be added by
    quietly extending this function; it would need its own, explicitly
    human-gated module.

    `authorized_result` is required and every `evidence_refs` entry is
    checked against it (red-team round 7, RT-02): before this fix, the
    only validation was "at least one evidence_ref exists" — a caller
    could cite `EvidenceRef("fabricated", "not-bound-to-any-result")` and
    the action would construct successfully. This module already requires
    human approval before any action executes, but a human reviewing a
    proposal has no reason to doubt that its cited evidence is real; a
    fabricated reference reaching them as a "recommendation" is exactly
    the authority-boundary failure AGENTS.md exists to prevent, even
    though nothing in the current codebase yet wires an LLM's output into
    this constructor.
    """
    authorized_refs = {
        (ref.artifact, ref.lineage_id)
        for finding in authorized_result.findings
        for ref in finding.evidence_refs
    }
    for ref in evidence_refs:
        if (ref.artifact, ref.lineage_id) not in authorized_refs:
            raise ResponseActionError(
                f"evidence_ref {ref.artifact!r}/{ref.lineage_id!r} is not "
                "present in the sealed authoritative result — a response "
                "action cannot cite evidence VIGÍA never produced"
            )
    return ResponseAction(
        action_id=action_id,
        category=category,
        reason=reason,
        evidence_refs=evidence_refs,
        risk=risk,
        reversibility=reversibility,
    )
