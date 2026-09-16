import pytest

from zaynor.schemas import EvidenceRef
from zaynor.sigma_candidate import propose_sigma_candidate

yaml = pytest.importorskip("yaml", reason="PyYAML not installed; injection regression needs a real YAML parser")

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
