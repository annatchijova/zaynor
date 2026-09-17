import json

from dataclasses import asdict

from zaynor.api import create_app
from zaynor.authority_seal import seal_authoritative_result
from zaynor.schemas import ZaynorAuthoritativeResult


def _route(app, path: str):
    return next(route.endpoint for route in app.routes if route.path == path)


def test_cases_do_not_trust_verification_fields_in_derived_index(tmp_path):
    output_root = tmp_path / "outputs"
    case_dir = output_root / "CASE-API"
    case_dir.mkdir(parents=True)
    result = ZaynorAuthoritativeResult(
        case_id="CASE-API",
        engine={"name": "fixture", "version": "1", "configuration_hash": "fixture"},
        verdict="ABSTAIN",
        integrity={"confidence": "HIGH", "score": "0"},
    )
    seal = seal_authoritative_result(result)
    (case_dir / "result.json").write_text(json.dumps(asdict(result)), encoding="utf-8")
    (case_dir / "result.seal.json").write_text(json.dumps(asdict(seal)), encoding="utf-8")
    (output_root / "index.json").write_text(json.dumps({
        "CASE-API": {
            "case_id": "CASE-API",
            "verdict": "SUSPICION",
            "updated_at": "2026-01-01T00:00:00-03:00",
            "verification": "VERIFIED",
            "seal_status": "VERIFIED",
        },
    }), encoding="utf-8")

    case = _route(create_app(output_root=output_root), "/cases")()["cases"][0]

    assert case["verdict"] == "SUSPICION"
    assert case["updated_at"] == "2026-01-01T00:00:00-03:00"
    assert case["verification"] == "NOT_CHECKED"
    assert case["seal_status"] == "UNKNOWN"
