from fractions import Fraction

from zaynor.hallucination_guard import HallucinationGuard, extract_authorized_facts

FAKE_RESULT = {
    "verdict": "SUSPICION",
    "composite_score": "0.5000",
    "fractures": [{"type": "EFFECT_BEFORE_CAUSE", "severity": "0.7500"}],
    "golden_rules_triggered": 0,
}


def test_verified_claim_is_not_redacted():
    facts = extract_authorized_facts(FAKE_RESULT)
    guard = HallucinationGuard(facts)
    result = guard.check("The verdict is SUSPICION, composite score: 0.5000.")
    assert result.claims_hallucinated == 0
    assert "[CLAIM NOT VERIFIED]" not in result.safe_narration


def test_hallucinated_claim_is_redacted():
    facts = extract_authorized_facts(FAKE_RESULT)
    guard = HallucinationGuard(facts, hallucination_threshold=Fraction(0))
    narration = "The verdict is MALICE with composite score: 9.99."
    result = guard.check(narration)
    assert result.claims_hallucinated == 2
    assert result.suspicious
    assert "MALICE" not in result.safe_narration
    assert "9.99" not in result.safe_narration
    assert "[CLAIM NOT VERIFIED]" in result.safe_narration


def test_unverifiable_claim_does_not_count_as_hallucinated():
    facts = extract_authorized_facts(FAKE_RESULT)  # no mitre_ttp fact present
    guard = HallucinationGuard(facts)
    result = guard.check("Technique T1070.001 was observed.")
    assert result.claims_hallucinated == 0
    assert result.claims_unverifiable == 1
