from fractions import Fraction

import pytest

from zaynor.agents.contracts import Audience
from zaynor.agents.mentor import Mentor
from zaynor.agents.ollama_client import OllamaClient
from zaynor.authority_seal import SealError, seal_authoritative_result
from zaynor.schemas import ZaynorAuthoritativeResult


class _FakeClient(OllamaClient):
    def __init__(self, response):
        object.__setattr__(self, "_response", response)
        super().__init__(host="http://127.0.0.1", model="test", timeout_seconds=1)

    def generate(self, *, system, prompt):
        return self._response


def test_checked_chat_returns_safe_narration_for_unsupported_claim():
    result = ZaynorAuthoritativeResult(
        case_id="CASE-MENTOR", engine={"name": "test"}, verdict="ABSTAIN",
        unknowns=("credential origin",), integrity={"confidence": Fraction(1, 2)},
    )
    checked = Mentor(_FakeClient("The result is MALICE.")).chat_checked(
        "Explain the result", audience=Audience.JUNIOR, result=result,
        seal=seal_authoritative_result(result),
    )

    assert checked.suspicious
    assert checked.safe_narration != checked.original_narration


def test_checked_chat_preserves_authorized_claims():
    result = ZaynorAuthoritativeResult(
        case_id="CASE-MENTOR", engine={"name": "test"}, verdict="ABSTAIN",
        unknowns=("credential origin",), integrity={"confidence": Fraction(1, 2)},
    )
    checked = Mentor(_FakeClient("The result remains ABSTAIN.")).chat_checked(
        "Explain the result", audience=Audience.SENIOR, result=result,
        seal=seal_authoritative_result(result),
    )

    assert not checked.suspicious
    assert checked.safe_narration == checked.original_narration


def test_checked_chat_rejects_a_result_not_bound_to_the_given_seal():
    """Confirmed by induction (red-team audit): before this check,
    check_narrative trusted `result` as given and never re-verified its
    seal — a caller passing a forged or merely mismatched `result`
    alongside a genuinely-valid `seal` from a DIFFERENT result got a
    GuardResult that silently approved a narrative matching the forged
    result (e.g. "The result is MALICE" for a result nothing had verified
    was ever actually sealed).
    """
    real_result = ZaynorAuthoritativeResult(
        case_id="CASE-MENTOR", engine={"name": "test"}, verdict="ABSTAIN",
        unknowns=("credential origin",), integrity={"confidence": Fraction(1, 2)},
    )
    real_seal = seal_authoritative_result(real_result)
    forged_result = ZaynorAuthoritativeResult(
        case_id="CASE-MENTOR", engine={"name": "test"}, verdict="MALICE",
        integrity={"confidence": Fraction(1, 2)},
    )

    with pytest.raises(SealError):
        Mentor(_FakeClient("The result is MALICE.")).chat_checked(
            "Explain the result", audience=Audience.JUNIOR, result=forged_result, seal=real_seal,
        )
