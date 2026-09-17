from fractions import Fraction

import pytest

from dataclasses import dataclass, replace

from zaynor.authority_seal import (
    CANONICALIZE_VERSION,
    AuthoritySeal,
    SchemaVersionMismatch,
    SealError,
    seal_authoritative_result,
    verify_authoritative_result,
)
from zaynor.schemas import AuthoritativeFinding, EvidenceRef, RESULT_SCHEMA_VERSION, ZaynorAuthoritativeResult


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


def test_moving_the_dataclass_to_a_different_module_does_not_change_the_seal():
    """GAP-02: the canonical payload used to embed
    `f"{__module__}.{__qualname__}"`, so a plain import-hygiene move (this
    class relocated to a different module) would have invalidated every
    already-sealed result's digest -- indistinguishable from tampering.
    Simulated here by hand-building the same canonical dict a class with a
    different __module__/__qualname__ but the same _CANONICAL_TYPE_NAME
    would produce, and confirming the seal is unaffected by module/qualname
    at all -- only `_CANONICAL_TYPE_NAME` and the field values matter.
    """
    from zaynor import authority_seal as authority_seal_module

    @dataclass(frozen=True)
    class _RelocatedResult:
        _CANONICAL_TYPE_NAME = ZaynorAuthoritativeResult._CANONICAL_TYPE_NAME
        case_id: str
        engine: dict
        verdict: str = "UNKNOWN"
        observations: tuple = ()
        timeline: tuple = ()
        fractures: tuple = ()
        hypotheses: tuple = ()
        findings: tuple = ()
        unknowns: tuple = ()
        provenance: tuple = ()
        integrity: dict = None
        audit_refs: tuple = ()
        schema_version: str = RESULT_SCHEMA_VERSION

    original = _result()
    relocated = _RelocatedResult(
        case_id=original.case_id,
        engine=original.engine,
        findings=original.findings,
        integrity=original.integrity,
    )
    assert authority_seal_module._typed(original) == authority_seal_module._typed(relocated)
    assert seal_authoritative_result(original) == seal_authoritative_result(relocated)


def test_schema_version_mismatch_is_distinct_from_a_real_tamper():
    """GAP-02: adding a field to ZaynorAuthoritativeResult (with a default,
    the ordinary way) used to make an old result rehydrate with a
    different shape than what originally produced its seal, and fail with
    the exact same 'seal mismatch' a genuine tamper produces. A result
    whose own schema_version disagrees with what this binary expects must
    raise a distinct, named error instead.
    """
    result = _result()
    seal = seal_authoritative_result(result)
    older = replace(result, schema_version="zaynor-result-v0")

    with pytest.raises(SchemaVersionMismatch, match="schema_version"):
        verify_authoritative_result(older, seal)

    # A real tamper under the SAME schema_version must still be the
    # ordinary, generic mismatch -- this fix must not weaken that.
    tampered = replace(result, verdict="MALICE")
    with pytest.raises(SealError, match="mismatch") as excinfo:
        verify_authoritative_result(tampered, seal)
    assert not isinstance(excinfo.value, SchemaVersionMismatch)
