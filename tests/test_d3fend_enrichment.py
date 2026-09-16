from zaynor.d3fend_enrichment import d3fend_for_attack_technique, enrich_finding_d3fend
from zaynor.schemas import AuthoritativeFinding


def test_known_technique_returns_mapped_countermeasures():
    result = d3fend_for_attack_technique("T1550.002")
    assert len(result) >= 1
    assert all(d.technique_id.startswith("D3-") for d in result)


def test_unmapped_technique_returns_empty_not_an_error():
    assert d3fend_for_attack_technique("T9999.999") == ()


def test_enrichment_is_a_plain_dict_never_a_finding_field():
    """D3FEND enrichment must be structurally incapable of being read as
    part of AuthoritativeFinding — it's a separate dict, not a schema
    field, matching AGENTS.md §2.4's MITRE/NIST non-authoritative contract.
    """
    finding = AuthoritativeFinding(finding_id="F-1", state="SUSPICION")
    enrichment = enrich_finding_d3fend(("T1550.002",))

    assert not hasattr(finding, "d3fend")
    assert not hasattr(finding, "attack_to_d3fend")
    assert isinstance(enrichment, dict)
    assert "T1550.002" in enrichment["attack_to_d3fend"]


def test_enrichment_never_touches_finding_state():
    """Running enrichment twice, or with different technique sets, must
    never change a finding's state — it's annotation computed from the
    technique IDs alone, with no path back to `state`.
    """
    finding = AuthoritativeFinding(finding_id="F-1", state="SUSPICION")
    enrich_finding_d3fend(("T1550.002", "T1110", "T1070.001"))
    enrich_finding_d3fend(())
    assert finding.state == "SUSPICION"


def test_confidence_is_labeled_never_silently_asserted():
    """Every mapped countermeasure declares whether its exact D3FEND ID was
    verified against a live copy of the matrix — no entry claims more
    confidence than was actually earned when this module was written.
    """
    for technique_id in ("T1550.002", "T1110", "T1070.001", "T1543.003", "T1558.001", "T1055"):
        for d in d3fend_for_attack_technique(technique_id):
            assert d.confidence in ("HIGH_CONFIDENCE", "NEEDS_VERIFICATION")
