"""Read-only mentor tools grounded in a sealed ZAYNOR package."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Mapping

from zaynor.authority_seal import AuthoritySeal, verify_authoritative_result
from zaynor.framework_context import AuthoritativePackage
from zaynor.schemas import ZaynorAuthoritativeResult


class ConsultToolError(ValueError):
    """A mentor lookup cannot be grounded in authorized state."""


class ConsultTools:
    """Read-only views for junior and senior analysts.

    The object owns no mutation method and verifies the seal before exposing
    authoritative fields. Evidence text is never interpreted as instructions.
    """

    def __init__(
        self,
        package: AuthoritativePackage,
        seal: AuthoritySeal,
        *,
        hunts: Mapping[str, str] | None = None,
    ) -> None:
        if not isinstance(package.result, ZaynorAuthoritativeResult):
            raise ConsultToolError("consult package must contain a ZAYNOR result")
        verify_authoritative_result(package, seal)
        self._package = package
        self._seal = seal
        self._hunts = dict(hunts or {})

    def explain_result(self, case_id: str) -> dict[str, Any]:
        """Return only sealed facts for one case; never a new interpretation."""
        result = self._package.result
        if case_id != result.case_id:
            return {"found": False, "message": "case is not in this sealed package"}
        return {
            "found": True,
            "case_id": result.case_id,
            "result_sha256": self._seal.sha256,
            "verdict": result.verdict,
            "findings": [
                {
                    "finding_id": finding.finding_id,
                    "state": finding.state,
                    "evidence_refs": [asdict(ref) for ref in finding.evidence_refs],
                    "rationale": finding.rationale,
                    "mitre": dict(finding.mitre or {}),
                    "nist": dict(finding.nist or {}),
                }
                for finding in result.findings
            ],
            "unknowns": list(result.unknowns),
            "audit_refs": list(result.audit_refs),
        }

    def explain_framework(self) -> dict[str, Any]:
        """Return framework annotations as context, separate from verdicts."""
        return {
            "mitre": [asdict(annotation) for annotation in self._package.framework.mitre],
            "nist": [asdict(annotation) for annotation in self._package.framework.nist],
            "changes_verdict": False,
        }

    def list_hunts(self) -> dict[str, Any]:
        """List configured investigations without granting execution rights."""
        return {"hunts": [{"id": name, "description": description} for name, description in sorted(self._hunts.items())]}
