import sys
from fractions import Fraction

from zaynor.vendored_engine import VENDORED_ENGINE_PATH

sys.path.insert(0, str(VENDORED_ENGINE_PATH))
from vigia_scorer import _fraction, _vigia_score  # noqa: E402


def _assert_no_float(value, path="result"):
    assert not isinstance(value, float), f"float escaped at {path}: {value!r}"
    if isinstance(value, dict):
        for key, child in value.items():
            _assert_no_float(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _assert_no_float(child, f"{path}[{index}]")


def test_scorer_result_contains_no_float_values():
    result = _vigia_score({
        "case_id": "FRACTION-001",
        "artifacts": [{
            "artifact_id": "a1",
            "evidence_type": "auth_log",
            "raw_score": "0.1",
            "prior_trust": "0.2",
        }],
    })

    _assert_no_float(result)
    assert result["score"] == Fraction(1, 5000)
    assert isinstance(result["confidence"], Fraction)


def test_decimal_input_is_converted_to_exact_fraction():
    assert _fraction(0.1) == Fraction(1, 10)
    assert _fraction("0.1") == Fraction(1, 10)
