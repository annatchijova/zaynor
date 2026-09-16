"""Tests for AuditLog's HMAC-keyed anchor layer.

Plain hash-chain behavior (tampering/truncation detection) is already
covered via ReadOnlyToolRegistry in test_tools_readonly.py — these tests
are specific to the entry_hmac/chain_tip_hmac addition.
"""

from __future__ import annotations

import json

from zaynor.audit_log import AuditLog

KEY_A = bytes.fromhex("aa" * 32)
KEY_B = bytes.fromhex("bb" * 32)


def test_hash_only_mode_when_no_key_is_configured(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("ACTION", {"x": 1})
    ok, message = AuditLog.verify_with_report(tmp_path / "audit.jsonl")
    assert ok
    assert "hash-only" in message


def test_entry_hmac_and_chain_tip_hmac_verify_with_the_right_key(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl", hmac_key=KEY_A)
    log.append("ACTION_1", {"x": 1})
    log.append("ACTION_2", {"x": 2})

    path = tmp_path / "audit.jsonl"
    records = [json.loads(line) for line in path.read_text().strip().splitlines()]
    assert all("entry_hmac" in r for r in records)
    tail = json.loads((tmp_path / "audit.jsonl.tail").read_text())
    assert "chain_tip_hmac" in tail

    ok, message = AuditLog.verify_with_report(path, hmac_key=KEY_A)
    assert ok
    assert "not verified" not in message


def test_entry_hmac_rejects_the_wrong_key(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl", hmac_key=KEY_A)
    log.append("ACTION_1", {"x": 1})

    ok, message = AuditLog.verify_with_report(tmp_path / "audit.jsonl", hmac_key=KEY_B)
    assert not ok
    assert "entry_hmac mismatch" in message


def test_entry_hmac_detects_a_wholesale_forged_chain(tmp_path):
    """Confirmed by induction: recomputing every SHA-256 hash from scratch
    (what an attacker with write access to the file can always do) still
    fails HMAC verification without the real key — this is exactly the gap
    plain hash-chaining cannot close on its own.
    """
    log = AuditLog(tmp_path / "audit.jsonl", hmac_key=KEY_A)
    log.append("ACTION_1", {"x": 1})
    path = tmp_path / "audit.jsonl"

    # Attacker forges a brand-new, internally-consistent chain without the
    # real key — by using AuditLog itself with a key it doesn't have.
    forged_path = tmp_path / "forged.jsonl"
    forged = AuditLog(forged_path, hmac_key=KEY_B)
    forged.append("ACTION_1", {"x": 999})  # different content, same shape

    ok, message = AuditLog.verify_with_report(forged_path, hmac_key=KEY_A)
    assert not ok
    assert "entry_hmac mismatch" in message


def test_entries_without_hmac_are_reported_as_a_caveat_not_a_failure(tmp_path):
    """A log started without a key, then resumed with one configured, must
    not fail verification for its earlier, honestly-unkeyed entries —
    but the gap must be visible, not silently swallowed.
    """
    path = tmp_path / "audit.jsonl"
    AuditLog(path).append("ACTION_1", {"x": 1})
    AuditLog(path, hmac_key=KEY_A).append("ACTION_2", {"x": 2})

    ok, message = AuditLog.verify_with_report(path, hmac_key=KEY_A)
    assert ok
    assert "predate HMAC key configuration" in message


def test_missing_key_at_verification_is_a_caveat_not_a_failure(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl", hmac_key=KEY_A)
    log.append("ACTION_1", {"x": 1})

    ok, message = AuditLog.verify_with_report(tmp_path / "audit.jsonl", hmac_key=None)
    assert ok
    assert "not verified" in message


def test_chain_tip_hmac_forged_tail_is_rejected(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl", hmac_key=KEY_A)
    log.append("ACTION_1", {"x": 1})

    tail_path = tmp_path / "audit.jsonl.tail"
    tail = json.loads(tail_path.read_text())
    tail["chain_tip_hmac"] = "0" * 64
    tail_path.write_text(json.dumps(tail))

    ok, message = AuditLog.verify_with_report(tmp_path / "audit.jsonl", hmac_key=KEY_A)
    assert not ok
    assert "tail anchor entry_hmac mismatch" in message
