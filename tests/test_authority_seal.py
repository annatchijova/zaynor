from fractions import Fraction

import pytest

from zaynor.authority_seal import (
    CANONICALIZE_VERSION,
    AuthoritySeal,
    SealError,
    seal_authoritative_result,
    verify_authoritative_result,
)
from zaynor.schemas import AuthoritativeFinding, EvidenceRef, ZaynorAuthoritativeResult


def _result() -> ZaynorAuthoritativeResult:
    return ZaynorAuthoritativeResult(
        case_id="CASE-1",
        engine={"name": "engine", "version": "1"},
        findings=(
            AuthoritativeFinding(
                finding_id="F-1",
                state="SUSPICION",
                evidence_refs=(EvidenceRef("auth:E1", "lineage:E1"),),
                rationale="corroborated",
            ),
        ),
        integrity={"confidence": Fraction(3, 7)},
    )


def test_same_authority_result_has_same_seal():
    first = seal_authoritative_result(_result())
    second = seal_authoritative_result(_result())
    assert first == second
    assert first.canonicalize_version == CANONICALIZE_VERSION


def test_mapping_order_does_not_change_seal():
    first = seal_authoritative_result({"b": 2, "a": 1})
    second = seal_authoritative_result({"a": 1, "b": 2})
    assert first == second


def test_tampering_fails_verification():
    result = _result()
    authority_seal = seal_authoritative_result(result)
    altered = ZaynorAuthoritativeResult(
        case_id=result.case_id,
        engine=result.engine,
        findings=result.findings,
        integrity={"confidence": Fraction(4, 7)},
    )
    with pytest.raises(SealError, match="mismatch"):
        verify_authoritative_result(altered, authority_seal)


def test_float_is_rejected_from_sealed_path():
    with pytest.raises(SealError, match="float"):
        seal_authoritative_result({"confidence": 0.5})


def test_wrong_version_is_rejected():
    with pytest.raises(SealError, match="version"):
        verify_authoritative_result(
            _result(), AuthoritySeal("old-version", "0" * 64)
        )
