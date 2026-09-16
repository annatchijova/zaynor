import pytest

from zaynor.schemas import EvidenceRef
from zaynor.sigma_candidate import propose_sigma_candidate

REF = EvidenceRef(artifact="auth:E001", lineage_id="auth")


def _candidate(**overrides):
    defaults = dict(
        finding_id="F-003",
        evidence_refs=(REF,),
        title="Privileged login from uninventoried device",
        logsource={"category": "authentication", "product": "linux"},
        detection={
            "selection": {"event": "vpn_login", "account_role": "privileged"},
            "condition": "selection",
        },
    )
    defaults.update(overrides)
    return propose_sigma_candidate(**defaults)


def test_candidate_is_never_marked_validated():
    candidate = _candidate()
    assert candidate.validated is False
    assert candidate.to_dict()["validated"] is False


def test_banner_appears_in_every_representation():
    candidate = _candidate()
    banner_fragments = ["CANDIDATE SIGMA RULE", "F-003", "auth:E001", "Not independently validated"]
    for fragment in banner_fragments:
        assert fragment in candidate.banner()
        assert fragment in candidate.to_yaml_text()
    for fragment in banner_fragments:
        assert fragment in candidate.to_dict()["banner"]


def test_rejects_candidate_with_no_evidence():
    with pytest.raises(ValueError, match="evidence_ref"):
        _candidate(evidence_refs=())


def test_rejects_detection_without_condition():
    with pytest.raises(ValueError, match="condition"):
        _candidate(detection={"selection": {"event": "x"}})


def test_yaml_text_is_well_formed_enough_to_round_trip_basic_structure():
    candidate = _candidate()
    text = candidate.to_yaml_text()
    assert "title: Privileged login from uninventoried device" in text
    assert "status: experimental" in text
    assert "logsource:" in text
    assert "condition: selection" in text
