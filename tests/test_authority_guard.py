from fractions import Fraction

import pytest

from zaynor.agents.authority_guard import (
    AuthorityGuardError,
    check_narrative,
    check_structured_output,
)
from zaynor.authority_seal import seal_authoritative_result
from zaynor.schemas import AuthoritativeFinding, EvidenceRef, ZaynorAuthoritativeResult


def _result() -> ZaynorAuthoritativeResult:
    return ZaynorAuthoritativeResult(
        case_id="CASE-GUARD",
        engine={"name": "zaynor-test", "version": "1"},
        findings=(AuthoritativeFinding(
            finding_id="F-1", state="UNKNOWN",
            evidence_refs=(EvidenceRef("auth:E1", "lineage:E1"),),
            mitre={"technique": "T1070.006"},
        ),),
        unknowns=("credential origin",),
        verdict="ABSTAIN",
        integrity={"confidence": Fraction(1, 2)},
    )


def _presented(result, seal):
    return {
        "case_id": result.case_id,
        "result_sha256": seal.sha256,
        "verdict": "ABSTAIN",
        "findings": [{
            "finding_id": "F-1",
            "state": "UNKNOWN",
            "evidence_refs": [{"artifact": "auth:E1", "lineage_id": "lineage:E1"}],
        }],
        "unknowns": ["credential origin"],
        "mitre_techniques": ["T1070.006"],
    }


def test_structural_guard_accepts_exact_authorized_projection():
    result = _result()
    seal = seal_authoritative_result(result)
    check_structured_output(result, seal, _presented(result, seal))


def test_structural_guard_rejects_finding_state_change():
    result = _result()
    seal = seal_authoritative_result(result)
    presented = _presented(result, seal)
    presented["findings"][0]["state"] = "MALICE"
    with pytest.raises(AuthorityGuardError, match="state"):
        check_structured_output(result, seal, presented)


def test_structural_guard_rejects_dropped_unknown():
    result = _result()
    seal = seal_authoritative_result(result)
    presented = _presented(result, seal)
    presented["unknowns"] = []
    with pytest.raises(AuthorityGuardError, match="UNKNOWN"):
        check_structured_output(result, seal, presented)


def test_structural_guard_rejects_unauthorized_technique():
    result = _result()
    seal = seal_authoritative_result(result)
    presented = _presented(result, seal)
    presented["mitre_techniques"] = ["T1059.001"]
    with pytest.raises(AuthorityGuardError, match="technique"):
        check_structured_output(result, seal, presented)


def test_narrative_guard_is_semantic_check_not_authority():
    result = _result()
    checked = check_narrative(result, "El resultado permanece ABSTAIN y el origen es UNKNOWN.")
    assert checked.claims_hallucinated == 0
    suspicious = check_narrative(result, "El resultado es MALICE.")
    assert suspicious.suspicious
