"""Tests for the INVESTIGATOR role's real tool implementations.

`list_hunts`/`request_adjudication` delegate to `ConsultTools` and are
tested without any VIGÍA dependency. `collect_window`/`verify_custody`
call the real VIGÍA MCP bridge — round 17: migrated onto ZAYNOR's own
vendored subset (`VigiaMCPConfig.vigia_repo_path`'s new default, see
docs/red-team/2026-09-17-round-17-vendored-mcp-tools.md), so these no
longer skip on a machine without a separate vigia-repo checkout.
"""

from __future__ import annotations

from fractions import Fraction
from pathlib import Path

import pytest

from zaynor.agents.consult_tools import ConsultTools
from zaynor.agents.investigator_tools import (
    InvestigatorToolError,
    build_investigator_tools,
    collect_window,
    verify_custody,
)
from zaynor.authority_seal import seal_authoritative_result
from zaynor.framework_context import AuthoritativePackage, FrameworkContext
from zaynor.schemas import AuthoritativeFinding, EvidenceRef, ZaynorAuthoritativeResult
from zaynor.zaynor_mcp_client import VigiaMCPConfig


def _package():
    result = ZaynorAuthoritativeResult(
        case_id="CASE-INVESTIGATOR",
        engine={"name": "engine", "version": "1"},
        verdict="SUSPICION",
        findings=(AuthoritativeFinding(
            finding_id="F-1", state="SUSPICION",
            evidence_refs=(EvidenceRef("auth:E1", "lineage:E1"),),
        ),),
        integrity={"confidence": Fraction(1, 2)},
    )
    package = AuthoritativePackage(result=result, framework=FrameworkContext())
    return package, seal_authoritative_result(package)


def test_list_hunts_and_request_adjudication_never_call_vigia_live():
    """These two must read ZAYNOR's own sealed package — never re-run
    VIGÍA — the same guarantee MENTOR's identical tools already have.
    """
    package, seal = _package()
    consult = ConsultTools(package, seal, hunts={"registry": "registry artifacts"})
    tools = build_investigator_tools(
        VigiaMCPConfig(vigia_repo_path=Path("/does-not-exist"), evidence_dir=Path("/does-not-exist")),
        consult,
    )
    hunts = tools["list_hunts"]({})
    assert hunts == {"hunts": [{"id": "registry", "description": "registry artifacts"}]}

    adjudication = tools["request_adjudication"]({"case_id": "CASE-INVESTIGATOR"})
    assert adjudication["verdict"] == "SUSPICION"
    assert adjudication["result_sha256"] == seal.sha256


def test_collect_window_requires_a_path():
    config = VigiaMCPConfig(vigia_repo_path=Path("/x"), evidence_dir=Path("/x"))
    with pytest.raises(InvestigatorToolError, match="path"):
        collect_window(config, {})


def test_verify_custody_requires_a_path():
    config = VigiaMCPConfig(vigia_repo_path=Path("/x"), evidence_dir=Path("/x"))
    with pytest.raises(InvestigatorToolError, match="path"):
        verify_custody(config, {})


class TestAgainstRealVigiaBridge:
    @pytest.fixture
    def evidence_dir(self, tmp_path):
        evidence = tmp_path / "evidence"
        evidence.mkdir()
        (evidence / "auth.jsonl").write_text('{"ref": "auth:E001", "event": "vpn_login"}\n')
        return evidence

    def test_collect_window_reads_real_evidence_through_vigia(self, evidence_dir):
        config = VigiaMCPConfig(evidence_dir=evidence_dir)
        result = collect_window(config, {"path": str(evidence_dir / "auth.jsonl")})
        assert "auth:E001" in result.get("content_preview", "") or "auth:E001" in str(result)

    def test_verify_custody_computes_a_real_sha256_through_vigia(self, evidence_dir):
        import hashlib

        config = VigiaMCPConfig(evidence_dir=evidence_dir)
        target = evidence_dir / "auth.jsonl"
        result = verify_custody(config, {"path": str(target)})
        assert result["sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()

    def test_collect_window_rejects_paths_outside_evidence_dir(self, evidence_dir):
        """VIGÍA's own path confinement, exercised through this tool — not
        raised as a protocol-level MCP error (same shape as
        test_zaynor_mcp_client.py's equivalent list_files test): the
        bridge returns a normal response whose content reports rejection.
        """
        config = VigiaMCPConfig(evidence_dir=evidence_dir)
        result = collect_window(config, {"path": "/etc/passwd"})
        rendered = str(result).lower()
        assert "blocked" in rendered or "error" in rendered or "escapes" in rendered
