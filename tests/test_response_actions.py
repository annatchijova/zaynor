import pytest

from zaynor.response_actions import ResponseActionError, propose_response_action
from zaynor.schemas import EvidenceRef

REF = EvidenceRef(artifact="auth:E001", lineage_id="auth")


def test_proposed_action_is_always_proposed_and_requires_approval():
    action = propose_response_action(
        action_id="A-1",
        category="containment",
        reason="Disable the compromised account pending investigation",
        evidence_refs=(REF,),
        risk="MEDIUM",
        reversibility="REVERSIBLE",
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
        )


def test_to_dict_matches_the_agreed_schema():
    action = propose_response_action(
        action_id="A-5",
        category="eradication",
        reason="Rotate the leaked credential",
        evidence_refs=(REF,),
        risk="HIGH",
        reversibility="IRREVERSIBLE",
    )
    payload = action.to_dict()["action"]
    assert payload["status"] == "proposed"
    assert payload["requires_human_approval"] is True
    assert payload["evidence_refs"] == [{"artifact": "auth:E001", "lineage_id": "auth"}]
