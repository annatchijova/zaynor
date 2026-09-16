import pytest

from zaynor.investigation_log import (
    InvestigationLogError,
    add_hypothesis,
    new_investigation_log,
    note_open_question,
    resolve_open_question,
    update_hypothesis,
    verify_log,
)


def test_new_log_verifies_clean():
    log = new_investigation_log("INC-TEST-001")
    result = verify_log(log)
    assert result["log_ok"]
    assert result["errors"] == []


def test_hypothesis_lifecycle_is_recorded_and_verifiable():
    log = new_investigation_log("INC-TEST-001")
    h = add_hypothesis(log, actor="investigator", text="Stolen admin credential")
    assert h["status"] == "open"

    update_hypothesis(log, actor="investigator", hypothesis_id=h["id"], status="supported", rationale="corroborated by ci_log_archive.txt")
    assert log["hypotheses"][0]["status"] == "supported"

    result = verify_log(log)
    assert result["log_ok"]


def test_unknown_hypothesis_status_is_rejected():
    log = new_investigation_log("INC-TEST-001")
    h = add_hypothesis(log, actor="investigator", text="Insider threat")
    with pytest.raises(InvestigationLogError):
        update_hypothesis(log, actor="investigator", hypothesis_id=h["id"], status="MALICE", rationale="not a real state")


def test_open_question_is_idempotent_on_text():
    log = new_investigation_log("INC-TEST-001")
    note_open_question(log, actor="investigator", question="Was MFA bypassed?", what_would_resolve="auth provider MFA logs")
    note_open_question(log, actor="investigator", question="Was MFA bypassed?", what_would_resolve="auth provider MFA logs")
    assert len(log["open_questions"]) == 1


def test_resolving_unknown_question_raises():
    log = new_investigation_log("INC-TEST-001")
    with pytest.raises(InvestigationLogError):
        resolve_open_question(log, actor="investigator", question_id="Q999", how="n/a")


def test_unbacked_summary_entry_is_detected():
    log = new_investigation_log("INC-TEST-001")
    add_hypothesis(log, actor="investigator", text="Stolen admin credential")
    assert verify_log(log)["log_ok"]

    # Inject a hypothesis into the working-state summary with no journal
    # entry behind it at all — this is what _journal_backing catches.
    log["hypotheses"].append({"id": "H99", "text": "Fabricated", "status": "open", "rationale": None})
    result = verify_log(log)
    assert not result["log_ok"]
    assert any("journal never recorded" in e for e in result["errors"])


def test_in_place_field_flip_is_detected_by_journal_backing():
    """A summary mutation without a matching journal mutation is detected."""
    log = new_investigation_log("INC-TEST-001")
    h = add_hypothesis(log, actor="investigator", text="Stolen admin credential")
    log["hypotheses"][0]["status"] = "supported"  # no record() call
    result = verify_log(log)
    assert not result["log_ok"]
    assert any("summary differs" in e for e in result["errors"])


def test_tampering_with_a_sealed_entry_is_detected():
    log = new_investigation_log("INC-TEST-001")
    add_hypothesis(log, actor="investigator", text="Stolen admin credential")
    log["journal"][0]["detail"]["text"] = "Insider threat instead"
    result = verify_log(log)
    assert not result["log_ok"]
    assert any("altered after it was sealed" in e for e in result["errors"])
