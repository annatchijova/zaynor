import pytest

from zaynor.authority_seal import AuthoritySeal, seal_authoritative_result
from zaynor.framework_context import (
    AuthoritativePackage,
    ConsultPackageError,
    FrameworkContext,
    MitreAnnotation,
    NistAnnotation,
    OwaspAnnotation,
    build_consult_package,
    seal_authoritative_package,
    verify_authoritative_package,
)
from zaynor.schemas import AuthoritativeFinding, ZaynorAuthoritativeResult


def _result() -> ZaynorAuthoritativeResult:
    return ZaynorAuthoritativeResult(
        case_id="CASE-1",
        engine={"name": "engine", "version": "1"},
        findings=(AuthoritativeFinding(finding_id="F-1", state="UNKNOWN"),),
    )


def test_framework_context_is_separate_from_finding_state():
    result = _result()
    package = AuthoritativePackage(
        result=result,
        framework=FrameworkContext(
            mitre=(MitreAnnotation("T1070.006", "candidate", "timestamp anomaly"),),
            nist=(NistAnnotation("Respond", "Analysis", "context", "triage"),),
            owasp=(OwaspAnnotation("API-2023", "API1", "candidate", "authorization", ("auth:E1",)),),
        ),
    )
    assert package.result.findings[0].state == "UNKNOWN"
    assert package.framework.mitre[0].mapping_status == "candidate"
    assert package.framework.owasp[0].category == "API1"


def test_framework_context_is_covered_by_package_seal():
    base = AuthoritativePackage(result=_result())
    annotated = AuthoritativePackage(
        result=_result(),
        framework=FrameworkContext(
            mitre=(MitreAnnotation("T1070.006", "candidate", "timestamp anomaly"),)
        ),
    )
    base_seal = seal_authoritative_package(base)
    annotated_seal = seal_authoritative_package(annotated)
    assert base_seal != annotated_seal
    assert verify_authoritative_package(annotated, annotated_seal)


def test_owasp_context_cannot_promote_authoritative_state():
    result = _result()
    package = AuthoritativePackage(
        result=result,
        framework=FrameworkContext(
            owasp=(OwaspAnnotation("ASVS-5", "V5.1", "candidate", "authorization"),)
        ),
    )
    assert package.result.verdict == "UNKNOWN"
    assert package.result.findings[0].state == "UNKNOWN"


def test_build_consult_package_bridges_an_analyze_style_seal():
    """`zaynor analyze` seals the bare result, not a package -- this is the
    resolution to that documented mismatch (agents/README.md).
    """
    result = _result()
    seal = seal_authoritative_result(result)
    package, package_seal = build_consult_package(result, seal)
    assert package.result is result
    assert package.framework == FrameworkContext()
    assert verify_authoritative_package(package, package_seal)
    # The package seal is a DIFFERENT sealed object than the original
    # result seal -- never conflate the two.
    assert package_seal.sha256 != seal.sha256


def test_build_consult_package_rejects_a_result_that_does_not_verify():
    result = _result()
    tampered_seal = AuthoritySeal(canonicalize_version="v1", sha256="0" * 64)
    with pytest.raises(ConsultPackageError, match="does not verify"):
        build_consult_package(result, tampered_seal)


def test_build_consult_package_carries_a_provided_framework_context():
    result = _result()
    seal = seal_authoritative_result(result)
    framework = FrameworkContext(mitre=(MitreAnnotation("T1070.006", "candidate", "timestamp anomaly"),))
    package, package_seal = build_consult_package(result, seal, framework=framework)
    assert package.framework.mitre[0].technique == "T1070.006"
    assert verify_authoritative_package(package, package_seal)
