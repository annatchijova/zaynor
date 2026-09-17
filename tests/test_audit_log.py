"""Tests for AuditLog's per-case genesis binding, closed vocabulary, and
HMAC-keyed anchor layer.

Plain hash-chain behavior (tampering/truncation detection) is already
covered via ReadOnlyToolRegistry in test_tools_readonly.py — these tests
are specific to the case-binding/vocabulary/entry_hmac/chain_tip_hmac layer.
"""

from __future__ import annotations

import json
import pytest

from zaynor.audit_log import AuditLog, genesis_hash
from zaynor.hmac_chain import resolve_hmac_key

KEY_A = bytes.fromhex("aa" * 32)
KEY_B = bytes.fromhex("bb" * 32)


def test_hash_only_mode_when_no_key_is_configured(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl", case_id="CASE-1")
    log.append("CASE_FROZEN", {"x": 1}, reason="case evidence frozen")
    ok, message = AuditLog.verify_with_report(tmp_path / "audit.jsonl", case_id="CASE-1")
    assert ok
    assert "hash-only" in message


def test_entry_hmac_and_chain_tip_hmac_verify_with_the_right_key(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl", case_id="CASE-1", hmac_key=KEY_A)
    log.append("CASE_FROZEN", {"x": 1}, reason="case evidence frozen")
    log.append("RESULT_SEALED", {"x": 2}, reason="analysis complete")

    path = tmp_path / "audit.jsonl"
    records = [json.loads(line) for line in path.read_text().strip().splitlines()]
    assert all("entry_hmac" in r for r in records)
    assert all(r["case_id"] == "CASE-1" for r in records)
    tail = json.loads((tmp_path / "audit.jsonl.tail").read_text())
    assert "chain_tip_hmac" in tail

    ok, message = AuditLog.verify_with_report(path, case_id="CASE-1", hmac_key=KEY_A)
    assert ok
    assert "not verified" not in message


def test_entry_hmac_rejects_the_wrong_key(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl", case_id="CASE-1", hmac_key=KEY_A)
    log.append("CASE_FROZEN", {"x": 1}, reason="case evidence frozen")

    ok, message = AuditLog.verify_with_report(tmp_path / "audit.jsonl", case_id="CASE-1", hmac_key=KEY_B)
    assert not ok
    assert "entry_hmac mismatch" in message


def test_entry_hmac_detects_a_wholesale_forged_chain(tmp_path):
    """Confirmed by induction: recomputing every SHA-256 hash from scratch
    (what an attacker with write access to the file can always do) still
    fails HMAC verification without the real key - this is exactly the gap
    plain hash-chaining cannot close on its own.
    """
    log = AuditLog(tmp_path / "audit.jsonl", case_id="CASE-1", hmac_key=KEY_A)
    log.append("CASE_FROZEN", {"x": 1}, reason="case evidence frozen")

    # Attacker forges a brand-new, internally-consistent chain without the
    # real key - by using AuditLog itself with a key it doesn't have.
    forged_path = tmp_path / "forged.jsonl"
    forged = AuditLog(forged_path, case_id="CASE-1", hmac_key=KEY_B)
    forged.append("CASE_FROZEN", {"x": 999}, reason="forged")  # different content, same shape

    ok, message = AuditLog.verify_with_report(forged_path, case_id="CASE-1", hmac_key=KEY_A)
    assert not ok
    assert "entry_hmac mismatch" in message


def test_entries_without_hmac_fail_when_a_key_is_supplied(tmp_path):
    """A verifier with a key must not accept a mixed protected/unprotected log."""
    path = tmp_path / "audit.jsonl"
    AuditLog(path, case_id="CASE-1").append("CASE_FROZEN", {"x": 1}, reason="frozen")
    AuditLog(path, case_id="CASE-1", hmac_key=KEY_A).append("RESULT_SEALED", {"x": 2}, reason="sealed")

    ok, message = AuditLog.verify_with_report(path, case_id="CASE-1", hmac_key=KEY_A)
    assert not ok
    assert "HMAC" in message


def test_missing_key_at_verification_is_a_caveat_not_a_failure(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl", case_id="CASE-1", hmac_key=KEY_A)
    log.append("CASE_FROZEN", {"x": 1}, reason="case evidence frozen")

    ok, message = AuditLog.verify_with_report(tmp_path / "audit.jsonl", case_id="CASE-1", hmac_key=None)
    assert ok
    assert "not verified" in message


def test_chain_tip_hmac_forged_tail_is_rejected(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl", case_id="CASE-1", hmac_key=KEY_A)
    log.append("CASE_FROZEN", {"x": 1}, reason="case evidence frozen")

    tail_path = tmp_path / "audit.jsonl.tail"
    tail = json.loads(tail_path.read_text())
    tail["chain_tip_hmac"] = "0" * 64
    tail_path.write_text(json.dumps(tail))

    ok, message = AuditLog.verify_with_report(tmp_path / "audit.jsonl", case_id="CASE-1", hmac_key=KEY_A)
    assert not ok
    assert "tail anchor entry_hmac mismatch" in message


def test_hmac_key_file_must_not_be_group_or_world_readable(tmp_path, monkeypatch):
    key_path = tmp_path / "hmac.key"
    key_path.write_bytes(KEY_A)
    key_path.chmod(0o640)
    monkeypatch.setenv("ZAYNOR_HMAC_KEY_FILE", str(key_path))
    monkeypatch.delenv("ZAYNOR_HMAC_KEY", raising=False)
    with pytest.raises(ValueError, match="group or other"):
        resolve_hmac_key()


def test_genesis_is_bound_to_case_id_grafting_fails_closed(tmp_path):
    """A chain built for one case cannot be presented as another case's
    chain, even though every entry after the graft point would otherwise
    be internally consistent - the graft fails at the genesis check.
    """
    path = tmp_path / "audit.jsonl"
    AuditLog(path, case_id="CASE-A").append("CASE_FROZEN", {"x": 1}, reason="frozen for A")

    ok, message = AuditLog.verify_with_report(path, case_id="CASE-B")
    assert not ok
    assert "chain grafted" in message or "belongs to case" in message


def test_reopening_an_audit_log_under_a_different_case_id_is_refused(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(path, case_id="CASE-A").append("CASE_FROZEN", {"x": 1}, reason="frozen for A")

    with pytest.raises(ValueError, match="refusing to graft"):
        AuditLog(path, case_id="CASE-B")


def test_append_rejects_an_unknown_action(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl", case_id="CASE-1")
    with pytest.raises(ValueError, match="unknown audit action"):
        log.append("SOMETHING_MADE_UP", {}, reason="whatever")


def test_append_rejects_an_empty_reason(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl", case_id="CASE-1")
    with pytest.raises(ValueError, match="reason must be a non-empty string"):
        log.append("CASE_FROZEN", {}, reason="   ")


def test_genesis_hash_differs_per_case_id():
    assert genesis_hash("CASE-A") != genesis_hash("CASE-B")
    assert genesis_hash("CASE-A") == genesis_hash("CASE-A")


def test_entries_carry_a_real_argentina_timestamp(tmp_path):
    import re

    entry = AuditLog(tmp_path / "audit.jsonl", case_id="CASE-1").append(
        "CASE_FROZEN", {}, reason="frozen"
    )
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}-03:00", entry.created_at)


def test_tampering_with_created_at_breaks_the_hash(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(path, case_id="CASE-1").append("CASE_FROZEN", {}, reason="frozen")
    record = json.loads(path.read_text().strip())
    record["created_at"] = "2000-01-01T00:00:00-03:00"
    path.write_text(json.dumps(record) + "\n")

    ok, message = AuditLog.verify_with_report(path, case_id="CASE-1")
    assert not ok
    assert "entry_hash mismatch" in message
