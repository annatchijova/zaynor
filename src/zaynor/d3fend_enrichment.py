"""D3FEND defensive-technique annotation over a MITRE ATT&CK-mapped
finding.

Extends the already-confirmed MITRE ATT&CK annotation layer (Phase 0: TTPs
are visible in VIGÍA's real signal `finding_types`, e.g.
`vigia/sift/event_log_correlator.py`'s named patterns each carry a TTP —
"PASS_THE_HASH" -> "T1550.002") one hop further: ATT&CK technique ->
D3FEND defensive technique. Same non-authoritative contract as MITRE
ATT&CK itself (AGENTS.md §2.4, extended here to D3FEND):

    D3FEND -> evidence        NEVER
    D3FEND -> hypothesis      NEVER
    D3FEND -> score           NEVER
    D3FEND -> verdict         NEVER

D3FEND only ever flows one direction, from an already-`CORROBORATED`-or-
equivalent finding's ATT&CK technique toward a defensive recommendation —
it cannot promote, corroborate, or otherwise feed back into anything
upstream of it. This is also what makes the product concretely
demonstrable: not just "we see T1078", but "these are the related
defensive countermeasures" — while staying pure annotation.

Honesty note on ID precision: ATT&CK technique IDs below (T-numbers) are
the same ones already confirmed present in VIGÍA's own
`event_log_correlator.py` source. The D3FEND technique IDs (D3-numbers)
are recorded as HIGH_CONFIDENCE (the mapping is well-known/commonly cited)
or NEEDS_VERIFICATION (the direction of the countermeasure is right, but
the exact D3FEND matrix ID was not looked up against a live copy of
d3fend.mitre.org before writing this module) — never presented as
verified when it wasn't. Confirm NEEDS_VERIFICATION entries against the
live D3FEND matrix before they appear in a demo as authoritative.
"""

from __future__ import annotations

from dataclasses import dataclass

# Red-team round 7 (RT-06): `HIGH_CONFIDENCE`/`NEEDS_VERIFICATION` are
# ZAYNOR's own editorial judgment about how well-established a mapping is in
# general security guidance — MITRE D3FEND does not itself publish a
# per-relationship confidence rating, so a bare "HIGH_CONFIDENCE" label
# reaching an analyst with no context could read as an official MITRE
# certification it is not. This explanatory text travels WITH the label in
# every emitted dict (`enrich_finding_d3fend`), not just in this module's
# source docstring — a docstring an analyst reading a report will never see.
_CONFIDENCE_BASIS = {
    "HIGH_CONFIDENCE": (
        "ZAYNOR's own editorial judgment that this mapping reflects "
        "well-established, commonly cited security guidance — not an "
        "official confidence rating published by MITRE D3FEND, which does "
        "not itself grade relationship confidence."
    ),
    "NEEDS_VERIFICATION": (
        "The defensive direction is plausible, but the exact D3FEND "
        "technique ID was not checked against a live copy of the D3FEND "
        "matrix (d3fend.mitre.org) before this mapping was written. "
        "Verify before treating as authoritative."
    ),
}


@dataclass(frozen=True)
class D3fendTechnique:
    technique_id: str
    name: str
    category: str
    confidence: str  # "HIGH_CONFIDENCE" | "NEEDS_VERIFICATION"


# Only covers ATT&CK techniques already confirmed reachable through VIGÍA's
# real event_log_correlator.py (Phase 0) — not a general ATT&CK<->D3FEND
# crosswalk. Extend as more techniques are confirmed to actually surface in
# a real bundle, not speculatively ahead of that.
_ATTACK_TO_D3FEND: dict[str, tuple[D3fendTechnique, ...]] = {
    "T1550.002": (  # Pass the Hash
        D3fendTechnique("D3-CH", "Credential Hardening", "Harden", "NEEDS_VERIFICATION"),
        D3fendTechnique("D3-MFA", "Multi-factor Authentication", "Harden", "HIGH_CONFIDENCE"),
    ),
    "T1110": (  # Brute Force
        D3fendTechnique("D3-AL", "Account Locking", "Model", "NEEDS_VERIFICATION"),
        D3fendTechnique("D3-MFA", "Multi-factor Authentication", "Harden", "HIGH_CONFIDENCE"),
    ),
    "T1070.001": (  # Clear Windows Event Logs
        D3fendTechnique("D3-RFS", "Remote File Storage (centralized/forwarded logging)", "Isolate", "NEEDS_VERIFICATION"),
        D3fendTechnique("D3-FAPA", "File Access Pattern Analysis", "Detect", "NEEDS_VERIFICATION"),
    ),
    "T1543.003": (  # Create or Modify Windows Service
        D3fendTechnique("D3-PSA", "Process Spawn Analysis", "Detect", "NEEDS_VERIFICATION"),
    ),
    "T1558.001": (  # Golden Ticket
        D3fendTechnique("D3-CH", "Credential Hardening", "Harden", "NEEDS_VERIFICATION"),
    ),
    "T1055": (  # Process Injection
        D3fendTechnique("D3-PSA", "Process Spawn Analysis", "Detect", "NEEDS_VERIFICATION"),
    ),
}


def d3fend_for_attack_technique(attack_technique_id: str) -> tuple[D3fendTechnique, ...]:
    """Return the D3FEND defensive techniques mapped to one ATT&CK
    technique ID, or an empty tuple if this module has no mapping for it
    yet (an empty result is "not mapped here", never "confirmed no
    countermeasure exists").
    """
    return _ATTACK_TO_D3FEND.get(attack_technique_id, ())


def enrich_finding_d3fend(attack_technique_ids: tuple[str, ...]) -> dict:
    """Build the pure-annotation D3FEND block for a finding that already
    carries the given ATT&CK technique IDs. Returns a plain dict (not a
    schema field on `AuthoritativeFinding` — same reasoning as MITRE/NIST
    in AGENTS.md §2.4: this is contextualization the narrator/report layer
    reads, not something that can ever be mistaken for part of the
    authoritative finding itself).
    """
    by_technique: dict[str, list[dict[str, str]]] = {}
    for attack_id in attack_technique_ids:
        mapped = d3fend_for_attack_technique(attack_id)
        if mapped:
            by_technique[attack_id] = [
                {
                    "d3fend_id": d.technique_id,
                    "name": d.name,
                    "category": d.category,
                    "confidence": d.confidence,
                    "confidence_basis": _CONFIDENCE_BASIS[d.confidence],
                }
                for d in mapped
            ]
    return {"attack_to_d3fend": by_technique}
