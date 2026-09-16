from fractions import Fraction

import pytest

from zaynor.agents.consult_tools import ConsultTools
from zaynor.authority_seal import AuthoritySeal, seal_authoritative_result
from zaynor.framework_context import AuthoritativePackage, FrameworkContext, MitreAnnotation
from zaynor.schemas import AuthoritativeFinding, EvidenceRef, ZaynorAuthoritativeResult


def _package():
    result = ZaynorAuthoritativeResult(
        case_id="CASE-CONSULT",
        engine={"name": "engine", "version": "1"},
        verdict="ABSTAIN",
        findings=(AuthoritativeFinding(
            finding_id="F-1", state="UNKNOWN",
            evidence_refs=(EvidenceRef("auth:E1", "lineage:E1"),),
        ),),
        unknowns=("credential origin",),
        integrity={"confidence": Fraction(1, 2)},
    )
    package = AuthoritativePackage(
        result=result,
        framework=FrameworkContext(mitre=(MitreAnnotation("T1070.006", "candidate", "context"),)),
    )
    return package, seal_authoritative_result(package)


def test_consult_tools_expose_sealed_facts_and_unknowns():
    package, seal = _package()
    tools = ConsultTools(package, seal, hunts={"registry": "registry artifacts"})
    view = tools.explain_result("CASE-CONSULT")
    assert view["result_sha256"] == seal.sha256
    assert view["verdict"] == "ABSTAIN"
    assert view["findings"][0]["state"] == "UNKNOWN"
    assert view["unknowns"] == ["credential origin"]


def test_consult_tools_keep_framework_context_non_authoritative():
    package, seal = _package()
    tools = ConsultTools(package, seal)
    context = tools.explain_framework()
    assert context["mitre"][0]["technique"] == "T1070.006"
    assert context["changes_verdict"] is False


def test_consult_tools_reject_tampered_seal():
    package, _ = _package()
    with pytest.raises(ValueError, match="mismatch|invalid"):
        ConsultTools(package, AuthoritySeal("zaynor-authority-v1", "0" * 64))
