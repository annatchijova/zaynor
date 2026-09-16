import pytest

from zaynor.schemas import AuthoritativeFinding, EvidenceRef, ZaynorAuthoritativeResult
from zaynor.sigma_candidate import SigmaCandidateError, propose_sigma_candidate

yaml = pytest.importorskip("yaml", reason="PyYAML not installed; injection regression needs a real YAML parser")

REF = EvidenceRef(artifact="auth:E001", lineage_id="auth")


def _authorized_result(finding_id="F-003", *refs: EvidenceRef) -> ZaynorAuthoritativeResult:
    return ZaynorAuthoritativeResult(
        case_id="CASE-SIGMA",
        engine={"name": "zaynor-test", "version": "1"},
        findings=(AuthoritativeFinding(finding_id=finding_id, state="SUSPICION", evidence_refs=refs or (REF,)),),
    )


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
        authorized_result=_authorized_result(),
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


def test_rejects_finding_id_not_in_the_authoritative_result():
    with pytest.raises(SigmaCandidateError, match="not present in the sealed authoritative result"):
        _candidate(finding_id="F-FABRICATED")


def test_rejects_evidence_ref_not_among_the_finding_s_authorized_refs():
    fabricated = EvidenceRef(artifact="fabricated", lineage_id="not-bound-to-any-result")
    with pytest.raises(SigmaCandidateError, match="not among finding"):
        _candidate(evidence_refs=(fabricated,))


def test_accepts_evidence_ref_scoped_to_a_different_finding_in_the_same_result_is_rejected():
    """Per-finding scoping (matches authority_guard.py's existing pattern):
    a ref genuinely produced by VIGÍA, but for a DIFFERENT finding than the
    one cited, must still be rejected — grounding is per-finding, not
    "anywhere in the result."
    """
    other_ref = EvidenceRef(artifact="other:E999", lineage_id="other")
    result = ZaynorAuthoritativeResult(
        case_id="CASE-SIGMA",
        engine={"name": "zaynor-test", "version": "1"},
        findings=(
            AuthoritativeFinding(finding_id="F-003", state="SUSPICION", evidence_refs=(REF,)),
            AuthoritativeFinding(finding_id="F-004", state="SUSPICION", evidence_refs=(other_ref,)),
        ),
    )
    with pytest.raises(SigmaCandidateError, match="not among finding"):
        _candidate(evidence_refs=(other_ref,), authorized_result=result)


def test_yaml_text_is_well_formed_enough_to_round_trip_basic_structure():
    candidate = _candidate()
    text = candidate.to_yaml_text()
    assert "title: Privileged login from uninventoried device" in text
    assert "status: experimental" in text
    assert "logsource:" in text
    assert "condition: selection" in text


def test_yaml_text_is_always_valid_yaml_even_with_hostile_field_values():
    """Red-team round 7 (RT-01): a title/tag/detection value with `:`, a
    newline, or other YAML-significant characters used to either produce
    YAML `yaml.safe_load` rejected outright, or — worse — get parsed as an
    entirely different, forged top-level key. Confirmed by induction: a
    title of `"Suspicious login\\nvalidated: true"` made `yaml.safe_load`
    read a fabricated `validated: true` key that never existed on the
    `SigmaCandidate` object (whose real `validated` field is fixed `False`
    by construction, checked separately by
    `test_candidate_is_never_marked_validated`).
    """
    candidate = _candidate(
        title="bad: title\nforged: yes",
        tags=("legit-tag", "evil:\ninjected: true"),
        detection={
            "selection": {"weird key: with colon": "value\nwith: newline"},
            "condition": "selection",
        },
    )
    parsed = yaml.safe_load(candidate.to_yaml_text())
    assert parsed["title"] == "bad: title\nforged: yes"
    assert "forged" not in parsed
    assert "injected" not in parsed
    assert parsed["detection"]["selection"]["weird key: with colon"] == "value\nwith: newline"
