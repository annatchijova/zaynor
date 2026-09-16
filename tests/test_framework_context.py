from zaynor.framework_context import (
    AuthoritativePackage,
    FrameworkContext,
    MitreAnnotation,
    NistAnnotation,
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
        ),
    )
    assert package.result.findings[0].state == "UNKNOWN"
    assert package.framework.mitre[0].mapping_status == "candidate"


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
