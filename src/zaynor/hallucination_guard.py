# zaynor/hallucination_guard.py
#
# Hallucination Guard — Narrative Verification Layer
# =============================================================================
# ADAPTED, almost verbatim, from ANNACONDA's `core/hallucination_guard.py`
# (annatchijova/annaconda), itself adapted from VIGÍA
# (github.com/annatchijova/vigia-intent-analysis, Apache 2.0). The
# mechanism ports cleanly because it never depended on VIGÍA/ANNACONDA
# internals — it only ever reads a plain result dict.
#
# PLACEHOLDER NOTE: `_VERDICT_RE` / `_FRACTURE_TYPE_RE` below still carry
# ANNACONDA's own closed vocabulary (MALICE/BENIGN/NOISE/SUSPICION,
# LOG_VS_MEMORY, etc.) and `extract_authorized_facts` still walks
# ANNACONDA's own result shape (fractures[]/raw_scores[]/golden_rules).
# ZAYNOR's own `ZaynorAuthoritativeResult` schema (produced by the VIGÍA
# adapter, not built yet) will replace both once it exists — ported now so
# the mechanism is in the repo and testable; the vocabulary is next.
#
# Philosophy:
#   The LLM is outside the verdict path. But the LLM *narrates* the verdict.
#   If the narration invents facts the motor never computed, the forensic
#   record is contaminated even though the verdict is correct.
#
#   This module enforces: the narrative cannot amplify the evidence; it can
#   only express facts that already exist in the deterministic state.
#
# Key design decisions (unchanged from the source):
#   - No float anywhere — numeric comparison uses Decimal with localcontext
#   - match_strategy is explicit per fact ("exact" | "numeric")
#   - Three-valued match: True=verified, False=hallucinated, None=unverifiable
#   - field_path is for traceability only, not for matching
#   - No str.replace() for redaction — uses char-index reconstruction

from __future__ import annotations

import decimal
import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Optional

logger = logging.getLogger("zaynor.hallucination_guard")


@dataclass(frozen=True)
class AuthorizedFact:
    """A single fact authorized by the deterministic result.

    Invariants:
    - value is ALWAYS a str — Decimal/Fraction serialized via str()
    - value is NEVER a float
    - match_strategy determines how claim_value is compared to value

    field_path is for traceability only (appears in GuardResult for
    debugging). It does not participate in matching.
    """

    fact_type: str
    field_path: str
    value: str
    match_strategy: str  # "exact" | "numeric"


def extract_authorized_facts(result: dict) -> frozenset:
    """Extract authorized facts from a deterministic result dict.

    Only uses known field paths. No dict flattening, no assumptions about
    unknown fields — an unrecognized key is simply not a fact, not an error.
    """
    facts: set[AuthorizedFact] = set()

    for key in ("verdict", "structural_verdict", "probabilistic_verdict"):
        v = result.get(key)
        if v and isinstance(v, str):
            facts.add(
                AuthorizedFact(
                    fact_type="verdict",
                    field_path=key,
                    value=v.strip().upper(),
                    match_strategy="exact",
                )
            )

    for key in ("composite_score", "probabilistic_score"):
        v = result.get(key)
        if v is not None:
            facts.add(
                AuthorizedFact(
                    fact_type="score", field_path=key, value=str(v), match_strategy="numeric"
                )
            )

    for i, f in enumerate(result.get("fractures", [])):
        if ftype := f.get("type"):
            facts.add(
                AuthorizedFact(
                    fact_type="fracture_type",
                    field_path=f"fractures[{i}].type",
                    value=str(ftype).upper(),
                    match_strategy="exact",
                )
            )
        if sev := f.get("severity"):
            facts.add(
                AuthorizedFact(
                    fact_type="severity",
                    field_path=f"fractures[{i}].severity",
                    value=str(sev),
                    match_strategy="numeric",
                )
            )
        if ttp := f.get("mitre_ttp"):
            facts.add(
                AuthorizedFact(
                    fact_type="mitre_ttp",
                    field_path=f"fractures[{i}].mitre_ttp",
                    value=str(ttp).upper(),
                    match_strategy="exact",
                )
            )

    for i, rs in enumerate(result.get("raw_scores", [])):
        for subkey in ("adjusted", "raw_score"):
            v = rs.get(subkey)
            if v is not None:
                facts.add(
                    AuthorizedFact(
                        fact_type="score",
                        field_path=f"raw_scores[{i}].{subkey}",
                        value=str(v),
                        match_strategy="numeric",
                    )
                )

    gr = result.get("golden_rules_triggered")
    if gr is not None:
        facts.add(
            AuthorizedFact(
                fact_type="golden_rules",
                field_path="golden_rules_triggered",
                value=str(gr),
                match_strategy="exact",
            )
        )

    hmac = result.get("_operation_hmac")
    if hmac and isinstance(hmac, str):
        facts.add(
            AuthorizedFact(
                fact_type="hash",
                field_path="_operation_hmac",
                value=hmac.lower(),
                match_strategy="exact",
            )
        )

    return frozenset(facts)


def match_fact(claim_type: str, claim_value: str, facts: frozenset) -> tuple[Optional[bool], str]:
    """Match a claim against the authorized fact set.

    Returns:
        (True,  field_path) — claim verified against a known fact
        (False, "")         — candidates exist but none matched (hallucinated)
        (None,  "")         — no facts of this type at all (unverifiable)

    The three-valued return distinguishes hallucinated (False) from
    unverifiable (None); only False counts against the narration.
    """
    candidates = [f for f in facts if f.fact_type == claim_type]
    if not candidates:
        return None, ""

    for fact in candidates:
        if fact.match_strategy == "exact":
            if claim_type == "hash":
                if claim_value.lower() == fact.value:
                    return True, fact.field_path
            elif claim_value.strip().upper() == fact.value:
                return True, fact.field_path
        elif fact.match_strategy == "numeric":
            try:
                ctx = decimal.Context(prec=28, rounding=decimal.ROUND_HALF_EVEN)
                with decimal.localcontext(ctx):
                    if decimal.Decimal(claim_value) == decimal.Decimal(fact.value):
                        return True, fact.field_path
            except decimal.InvalidOperation:
                continue

    return False, ""


@dataclass
class NarrativeClaim:
    """A claim extracted from LLM narrative text."""

    text: str
    claim_type: str
    extracted_value: str
    start: int
    end: int
    verified: Optional[bool] = None
    ground_truth_path: str = ""


# Deliberately conservative extraction — prefer false negatives over false
# positives. A missed claim is not verified (neutral); a false claim match
# would be worse.
_VERDICT_RE = re.compile(r"\b(MALICE|BENIGN|NOISE|SUSPICION|ABSTAIN|UNKNOWN|INCONCLUSIVE)\b", re.IGNORECASE)
_SCORE_RE = re.compile(r"(?:score|composite|posterior|confidence)[:\s]+([0-9]+\.[0-9]+)", re.IGNORECASE)
_SEVERITY_RE = re.compile(r"(?:severity)[:\s]+([0-9]+\.[0-9]+)", re.IGNORECASE)
_FRACTURE_TYPE_RE = re.compile(
    r"\b(LOG_VS_MEMORY|MEMORY_VS_DISK|TIMELINE_PARADOX|EFFECT_BEFORE_CAUSE|"
    r"NARRATIVE_POISONING_DETECTED|TEMPORAL_IMPOSSIBILITY|"
    r"CROSS_TOOL_CONTRADICTION|FALSE_FLAG_PATTERN)\b",
    re.IGNORECASE,
)
_MITRE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")
_SHA256_RE = re.compile(r"\b([0-9a-f]{64})\b", re.IGNORECASE)


def extract_claims(narration: str) -> list[NarrativeClaim]:
    """Extract verifiable claims from narrative text, with char-level
    start/end positions for index-based redaction (no str.replace).
    """
    claims: list[NarrativeClaim] = []

    for m in _VERDICT_RE.finditer(narration):
        claims.append(
            NarrativeClaim(
                text=m.group(0), claim_type="verdict", extracted_value=m.group(1).upper(),
                start=m.start(), end=m.end(),
            )
        )
    for m in _SCORE_RE.finditer(narration):
        claims.append(
            NarrativeClaim(
                text=m.group(0), claim_type="score", extracted_value=m.group(1),
                start=m.start(), end=m.end(),
            )
        )
    for m in _SEVERITY_RE.finditer(narration):
        claims.append(
            NarrativeClaim(
                text=m.group(0), claim_type="severity", extracted_value=m.group(1),
                start=m.start(), end=m.end(),
            )
        )
    for m in _FRACTURE_TYPE_RE.finditer(narration):
        claims.append(
            NarrativeClaim(
                text=m.group(0), claim_type="fracture_type", extracted_value=m.group(1).upper(),
                start=m.start(), end=m.end(),
            )
        )
    for m in _MITRE_RE.finditer(narration):
        claims.append(
            NarrativeClaim(
                text=m.group(0), claim_type="mitre_ttp", extracted_value=m.group(1).upper(),
                start=m.start(), end=m.end(),
            )
        )
    for m in _SHA256_RE.finditer(narration):
        claims.append(
            NarrativeClaim(
                text=m.group(0)[:16] + "...", claim_type="hash", extracted_value=m.group(1).lower(),
                start=m.start(), end=m.end(),
            )
        )

    return claims


@dataclass
class GuardResult:
    original_narration: str
    safe_narration: str
    claims_total: int = 0
    claims_verified: int = 0
    claims_hallucinated: int = 0
    claims_unverifiable: int = 0
    hallucination_rate: Fraction = field(default_factory=lambda: Fraction(0))
    suspicious: bool = False
    audit_sha256: str = ""
    hallucinated_claims: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "claims_total": self.claims_total,
            "claims_verified": self.claims_verified,
            "claims_hallucinated": self.claims_hallucinated,
            "claims_unverifiable": self.claims_unverifiable,
            "hallucination_rate": str(self.hallucination_rate),
            "suspicious": self.suspicious,
            "audit_sha256": self.audit_sha256,
            "hallucinated_claims": [
                {
                    "text": c.text,
                    "type": c.claim_type,
                    "llm_said": c.extracted_value,
                    "ground_truth_path": c.ground_truth_path,
                }
                for c in self.hallucinated_claims
            ],
        }


class HallucinationGuard:
    """Verifies narrative text against a deterministic result's authorized
    facts.

    Usage:
        facts = extract_authorized_facts(authoritative_result)
        guard = HallucinationGuard(facts)
        result = guard.check(llm_narration)
        if result.suspicious:
            use result.safe_narration instead of llm_narration
    """

    def __init__(
        self,
        authorized_facts: frozenset,
        hallucination_threshold: Fraction = Fraction(1, 5),
        redact_marker: str = "[CLAIM NOT VERIFIED]",
    ):
        self.facts = authorized_facts
        self.threshold = hallucination_threshold
        self.redact_marker = redact_marker

    def check(self, narration: str) -> GuardResult:
        claims = extract_claims(narration)

        for claim in claims:
            matched, path = match_fact(claim.claim_type, claim.extracted_value, self.facts)
            claim.verified = matched
            claim.ground_truth_path = path

        total = len(claims)
        verified = sum(1 for c in claims if c.verified is True)
        hallucinated = sum(1 for c in claims if c.verified is False)
        unverifiable = sum(1 for c in claims if c.verified is None)
        hallucinated_claims = [c for c in claims if c.verified is False]

        # Unverifiable claims are excluded from the rate — they cannot
        # count as evidence against the narration.
        verifiable_total = verified + hallucinated
        rate = Fraction(hallucinated, verifiable_total) if verifiable_total > 0 else Fraction(0)
        # A non-empty narrative with no machine-recognized claims cannot be
        # authorized by this conservative guard. Do not pass arbitrary prose
        # merely because the extractor failed to classify it.
        unrecognized_narrative = bool(narration.strip()) and not claims
        suspicious = rate > self.threshold or unrecognized_narrative

        # Index-based redaction, applied from end to start so earlier
        # indices stay valid as later ones are replaced.
        safe = narration
        if unrecognized_narrative:
            safe = self.redact_marker
        if hallucinated_claims:
            intervals = sorted(
                [(c.start, c.end) for c in hallucinated_claims], key=lambda x: x[0], reverse=True
            )
            merged: list[list[int]] = []
            for start, end in intervals:
                if merged and start < merged[-1][1]:
                    merged[-1] = [min(start, merged[-1][0]), max(end, merged[-1][1])]
                else:
                    merged.append([start, end])
            for start, end in merged:
                safe = safe[:start] + self.redact_marker + safe[end:]

        payload = {
            "claims_total": total,
            "claims_hallucinated": hallucinated,
            "hallucination_rate": str(rate),
            "suspicious": suspicious,
        }
        sha = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

        if suspicious:
            logger.warning(
                "Suspicious narrative: %d/%d verifiable claims not in the "
                "authorized result. Rate: %s. SHA256: %s",
                hallucinated, verifiable_total, rate, sha,
            )
        elif hallucinated > 0:
            logger.warning(
                "%d claim(s) not verified (below threshold %s). Rate: %s.",
                hallucinated, self.threshold, rate,
            )
        else:
            logger.info("Narrative verified. %d/%d claims confirmed. SHA256: %s", verified, total, sha)

        return GuardResult(
            original_narration=narration,
            safe_narration=safe,
            claims_total=total,
            claims_verified=verified,
            claims_hallucinated=hallucinated,
            claims_unverifiable=unverifiable,
            hallucination_rate=rate,
            suspicious=suspicious,
            audit_sha256=sha,
            hallucinated_claims=hallucinated_claims,
        )
