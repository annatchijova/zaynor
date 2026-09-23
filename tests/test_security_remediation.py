"""Regression coverage for the two prioritized CodeQL findings."""

from zaynor.api import create_app


def _route(app, path: str):
    return next(route.endpoint for route in app.routes if route.path == path)


def test_audit_api_returns_safe_detail_not_exception_text(tmp_path):
    """HTTP audit status must not echo local filesystem exception details."""
    output_case = tmp_path / "outputs" / "CASE-API"
    output_case.mkdir(parents=True)
    # The stored-result verification path is not the subject of this test;
    # a minimal valid case is supplied by the existing API fixture contract.
    from dataclasses import asdict
    import json
    from zaynor.authority_seal import seal_authoritative_result
    from zaynor.schemas import ZaynorAuthoritativeResult

    result = ZaynorAuthoritativeResult(
        case_id="CASE-API",
        engine={"name": "fixture", "version": "1", "configuration_hash": "fixture"},
        verdict="ABSTAIN",
        integrity={"confidence": "HIGH", "score": "0"},
    )
    (output_case / "result.json").write_text(json.dumps(asdict(result)), encoding="utf-8")
    (output_case / "result.seal.json").write_text(
        json.dumps(asdict(seal_authoritative_result(result))), encoding="utf-8"
    )

    cases_case = tmp_path / "cases" / "CASE-API"
    cases_case.mkdir(parents=True)
    audit = _route(
        create_app(output_root=tmp_path / "outputs", cases_root=tmp_path / "cases"),
        "/cases/{case_id}/audit",
    )("CASE-API")

    assert audit["status"] == "FAILED"
    assert audit["detail"] == "audit verification failed"
    assert str(tmp_path) not in audit["detail"]
