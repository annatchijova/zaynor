import pytest

from zaynor.investigation_log import (
    InvestigationLogError,
    add_hypothesis,
    new_investigation_log,
    note_open_question,
    record,
    resolve_open_question,
    update_hypothesis,
    verify_log,
)

KEY_A = bytes.fromhex("aa" * 32)
KEY_B = bytes.fromhex("bb" * 32)


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


def test_hash_only_mode_when_no_key_is_used():
    log = new_investigation_log("INC-TEST-001")
    record(log, actor="investigator", action="NOTE", detail={"x": 1})
    result = verify_log(log)
    assert result["log_ok"]
    assert "hash-only mode: no HMAC anchor on this journal" in result["caveats"]


def test_entry_hmac_and_memory_head_hmac_verify_with_the_right_key():
    log = new_investigation_log("INC-TEST-001")
    record(log, actor="investigator", action="NOTE", detail={"x": 1}, hmac_key=KEY_A)
    assert "entry_hmac" in log["journal"][0]
    assert "memory_head_hmac" in log

    result = verify_log(log, hmac_key=KEY_A)
    assert result["log_ok"]
    assert result["caveats"] == []


def test_entry_hmac_rejects_the_wrong_key():
    log = new_investigation_log("INC-TEST-001")
    record(log, actor="investigator", action="NOTE", detail={"x": 1}, hmac_key=KEY_A)

    result = verify_log(log, hmac_key=KEY_B)
    assert not result["log_ok"]
    assert any("entry_hmac mismatch" in e for e in result["errors"])


def test_entry_hmac_detects_a_wholesale_forged_journal():
    """Confirmed by induction: recomputing every SHA-256 hash from scratch
    (what an attacker with write access to `log` can always do) still
    fails HMAC verification without the real key.
    """
    genuine = new_investigation_log("INC-TEST-001")
    record(genuine, actor="investigator", action="NOTE", detail={"x": 1}, hmac_key=KEY_A)

    forged = new_investigation_log("INC-TEST-001")
    record(forged, actor="investigator", action="NOTE", detail={"x": 1}, hmac_key=KEY_B)

    result = verify_log(forged, hmac_key=KEY_A)
    assert not result["log_ok"]
    assert any("entry_hmac mismatch" in e for e in result["errors"])


def test_missing_key_at_verification_is_a_caveat_not_a_failure():
    log = new_investigation_log("INC-TEST-001")
    record(log, actor="investigator", action="NOTE", detail={"x": 1}, hmac_key=KEY_A)

    result = verify_log(log, hmac_key=None)
    assert result["log_ok"]
    assert "entry_hmac present but not verified (no key supplied)" in result["caveats"]


def test_entries_without_hmac_are_reported_as_a_caveat_not_a_failure():
    log = new_investigation_log("INC-TEST-001")
    record(log, actor="investigator", action="NOTE_1", detail={"x": 1})  # no key yet
    record(log, actor="investigator", action="NOTE_2", detail={"x": 2}, hmac_key=KEY_A)

    result = verify_log(log, hmac_key=KEY_A)
    assert result["log_ok"]
    assert any("predate HMAC key configuration" in c for c in result["caveats"])
