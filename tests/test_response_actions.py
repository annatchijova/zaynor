import pytest

from zaynor.response_actions import ResponseActionError, propose_response_action
from zaynor.schemas import AuthoritativeFinding, EvidenceRef, ZaynorAuthoritativeResult

REF = EvidenceRef(artifact="auth:E001", lineage_id="auth")


def _authorized_result(*refs: EvidenceRef) -> ZaynorAuthoritativeResult:
    return ZaynorAuthoritativeResult(
        case_id="CASE-RESPONSE-ACTIONS",
        engine={"name": "zaynor-test", "version": "1"},
        findings=(AuthoritativeFinding(finding_id="F-1", state="SUSPICION", evidence_refs=refs),),
    )


def test_proposed_action_is_always_proposed_and_requires_approval():
    action = propose_response_action(
        action_id="A-1",
        category="containment",
        reason="Disable the compromised account pending investigation",
        evidence_refs=(REF,),
        risk="MEDIUM",
        reversibility="REVERSIBLE",
        authorized_result=_authorized_result(REF),
    )
    assert action.status == "proposed"
    assert action.requires_human_approval is True


def test_status_cannot_be_set_to_anything_else():
    """There is no constructor parameter for status/requires_human_approval
    at all — this documents that as an executable invariant, not just a
    docstring claim.
    """
    with pytest.raises(TypeError):
        propose_response_action(  # type: ignore[call-arg]
            action_id="A-2",
            category="containment",
            reason="x",
            evidence_refs=(REF,),
            risk="LOW",
            reversibility="REVERSIBLE",
            authorized_result=_authorized_result(REF),
            status="executed",
        )


def test_action_without_evidence_refs_is_rejected():
    with pytest.raises(ResponseActionError, match="evidence_ref"):
        propose_response_action(
            action_id="A-3",
            category="containment",
            reason="unsupported",
            evidence_refs=(),
            risk="LOW",
            reversibility="REVERSIBLE",
            authorized_result=_authorized_result(REF),
        )


def test_invalid_category_is_rejected():
    with pytest.raises(ResponseActionError, match="category"):
        propose_response_action(
            action_id="A-4",
            category="remediate_automatically",
            reason="x",
            evidence_refs=(REF,),
            risk="LOW",
            reversibility="REVERSIBLE",
            authorized_result=_authorized_result(REF),
        )


def test_to_dict_matches_the_agreed_schema():
    action = propose_response_action(
        action_id="A-5",
        category="eradication",
        reason="Rotate the leaked credential",
        evidence_refs=(REF,),
        risk="HIGH",
        reversibility="IRREVERSIBLE",
        authorized_result=_authorized_result(REF),
    )
    payload = action.to_dict()["action"]
    assert payload["status"] == "proposed"
    assert payload["requires_human_approval"] is True
    assert payload["evidence_refs"] == [{"artifact": "auth:E001", "lineage_id": "auth"}]


def test_action_citing_evidence_not_in_the_authoritative_result_is_rejected():
    """Red-team round 7 (RT-02): confirmed by induction that, before this
    fix, `EvidenceRef("fabricated", "not-bound-to-any-result")` constructed
    a `ResponseAction` successfully — no check tied the citation back to
    anything VIGÍA actually produced.
    """
    fabricated = EvidenceRef(artifact="fabricated", lineage_id="not-bound-to-any-result")
    with pytest.raises(ResponseActionError, match="not present in the sealed authoritative result"):
        propose_response_action(
            action_id="A-6",
            category="containment",
            reason="Block the fabricated indicator",
            evidence_refs=(fabricated,),
            risk="LOW",
            reversibility="REVERSIBLE",
            authorized_result=_authorized_result(REF),
        )


def test_action_citing_a_mix_of_real_and_fabricated_evidence_is_rejected():
    fabricated = EvidenceRef(artifact="fabricated", lineage_id="not-bound-to-any-result")
    with pytest.raises(ResponseActionError, match="not present in the sealed authoritative result"):
        propose_response_action(
            action_id="A-7",
            category="containment",
            reason="Block the account and the fabricated indicator",
            evidence_refs=(REF, fabricated),
            risk="LOW",
            reversibility="REVERSIBLE",
            authorized_result=_authorized_result(REF),
        )
