import json

import pytest

from zaynor.audit_log import AuditLog
from zaynor.zaynor_mcp_server import (
    ZaynorMCPError,
    zaynor_add_hypothesis,
    zaynor_list_memory,
    zaynor_note_question,
    zaynor_verify_audit,
    zaynor_verify_memory,
)


def test_case_bound_memory_is_chained_and_verifiable(tmp_path, monkeypatch):
    monkeypatch.setenv("ZAYNOR_MCP_STATE_DIR", str(tmp_path))
    zaynor_add_hypothesis("CASE-1", "agent", "possible persistence")
    zaynor_note_question("CASE-1", "agent", "Was the task present before collection?", "timeline evidence")
    result = zaynor_list_memory("CASE-1")
    assert result["case_id"] == "CASE-1"
    assert result["verification"]["log_ok"] is True
    assert result["hypotheses"][0]["status"] == "open"
    assert zaynor_verify_memory("CASE-1")["log_ok"] is True


def test_case_binding_and_traversal_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("ZAYNOR_MCP_STATE_DIR", str(tmp_path))
    with pytest.raises(ZaynorMCPError):
        zaynor_add_hypothesis("../OTHER", "agent", "no")
    zaynor_add_hypothesis("CASE-A", "agent", "only A")
    source = tmp_path / "cases" / "CASE-A" / "investigation.json"
    target = tmp_path / "cases" / "CASE-B" / "investigation.json"
    target.parent.mkdir(parents=True)
    target.write_bytes(source.read_bytes())
    with pytest.raises(ZaynorMCPError):
        zaynor_list_memory("CASE-B")


def test_tampered_memory_is_rejected_before_listing(tmp_path, monkeypatch):
    monkeypatch.setenv("ZAYNOR_MCP_STATE_DIR", str(tmp_path))
    zaynor_add_hypothesis("CASE-2", "agent", "original")
    path = tmp_path / "cases" / "CASE-2" / "investigation.json"
    data = json.loads(path.read_text())
    data["hypotheses"][0]["text"] = "tampered"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ZaynorMCPError, match="integrity"):
        zaynor_list_memory("CASE-2")


def test_audit_verification_is_read_only(tmp_path, monkeypatch):
    monkeypatch.setenv("ZAYNOR_MCP_STATE_DIR", str(tmp_path))
    audit_path = tmp_path / "cases" / "CASE-3" / "audit.jsonl"
    audit = AuditLog(audit_path, case_id="CASE-3")
    audit.append("CASE_FROZEN", {}, reason="fixture")
    before = audit_path.read_bytes()
    result = zaynor_verify_audit("CASE-3")
    assert result["verified"] is True
    assert audit_path.read_bytes() == before
    assert not (tmp_path / "cases" / "MISSING").exists()
