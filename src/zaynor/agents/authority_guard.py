"""Two-level guard for agent output.

Structural validation is deterministic and fail-closed. Narrative checking is
conservative semantic analysis: it can flag unsupported claims, but it is not
a mathematical proof of zero hallucinations.
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, Mapping

from zaynor.hallucination_guard import AuthorizedFact, HallucinationGuard, extract_authorized_facts
from zaynor.schemas import ZaynorAuthoritativeResult
from zaynor.authority_seal import AuthoritySeal, verify_authoritative_result


class AuthorityGuardError(ValueError):
    """Structured agent output does not match authorized state."""


def _reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise AuthorityGuardError("float is not allowed in structured authority claims")
    if isinstance(value, Mapping):
        for key, item in value.items():
            _reject_floats(key)
            _reject_floats(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_floats(item)


def _as_result_dict(result: ZaynorAuthoritativeResult) -> dict[str, Any]:
    if not is_dataclass(result):
        raise AuthorityGuardError("guard requires a ZAYNOR authoritative result")
    return asdict(result)


def _techniques(result: dict[str, Any]) -> set[str]:
    found: set[str] = set()

    def walk(value: Any) -> None:
        if isinstance(value, str) and value.startswith("T") and value[1:5].isdigit():
            found.add(value.upper())
        elif isinstance(value, Mapping):
            for item in value.values():
                walk(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                walk(item)

    walk([finding.get("mitre") for finding in result["findings"]])
    return found


def _ids(records: list[dict[str, Any]]) -> set[str]:
    return {
        str(record.get(key))
        for record in records
        for key in ("id", "finding_id", "hypothesis_id", "fracture_id")
        if isinstance(record.get(key), str)
    }


def check_structured_output(
    result: ZaynorAuthoritativeResult,
    seal: AuthoritySeal,
    presented: Mapping[str, Any],
) -> None:
    """Validate the structured fields an agent is allowed to present.

    Required fields are intentionally explicit. A free-form narrative is not
    accepted as a substitute for this machine-checkable projection.
    """
    if not isinstance(presented, Mapping):
        raise AuthorityGuardError("structured output must be an object")
    _reject_floats(presented)
    verify_authoritative_result(result, seal)
    data = _as_result_dict(result)
    if presented.get("case_id") != result.case_id:
        raise AuthorityGuardError("presented case_id does not match authority")
    if presented.get("result_sha256") != seal.sha256:
        raise AuthorityGuardError("presented result hash does not match seal")

    presented_verdict = presented.get("verdict")
    authorized_verdict = result.integrity.get("agent_verdict")
    if presented_verdict is not None and presented_verdict != authorized_verdict:
        raise AuthorityGuardError("presented verdict does not match authority")

    presented_findings = presented.get("findings")
    if not isinstance(presented_findings, list):
        raise AuthorityGuardError("structured output requires findings list")
    authorized_findings = {finding.finding_id: finding for finding in result.findings}
    for finding in presented_findings:
        if not isinstance(finding, Mapping) or finding.get("finding_id") not in authorized_findings:
            raise AuthorityGuardError("presented finding_id is not authorized")
        authorized = authorized_findings[finding["finding_id"]]
        if finding.get("state") != authorized.state:
            raise AuthorityGuardError("presented finding state does not match authority")
        refs = finding.get("evidence_refs", [])
        allowed_refs = {(ref.artifact, ref.lineage_id) for ref in authorized.evidence_refs}
        if not isinstance(refs, list) or any(
            not isinstance(ref, Mapping)
            or (ref.get("artifact"), ref.get("lineage_id")) not in allowed_refs
            for ref in refs
        ):
            raise AuthorityGuardError("presented evidence reference is not authorized")

    if "unknowns" in presented and set(presented["unknowns"]) != set(result.unknowns):
        raise AuthorityGuardError("structured output dropped or altered UNKNOWN state")
    for key in ("scores", "confidence"):
        if key in presented:
            authorized = result.integrity.get(key)
            if str(presented[key]) != str(authorized):
                raise AuthorityGuardError(f"presented {key} does not match authority")
    authorized_ids = _ids(data["fractures"]) | _ids(data["hypotheses"])
    for key in ("fractures", "hypotheses"):
        if key in presented:
            if not isinstance(presented[key], list) or not set(presented[key]).issubset(authorized_ids):
                raise AuthorityGuardError(f"presented {key} contains an unauthorized id")
    if "mitre_techniques" in presented:
        allowed = _techniques(data)
        if not isinstance(presented["mitre_techniques"], list) or not set(presented["mitre_techniques"]).issubset(allowed):
            raise AuthorityGuardError("presented ATT&CK technique is not authorized")


def check_narrative(result: ZaynorAuthoritativeResult, narration: str):
    """Run conservative semantic narrative checking after structural checks."""
    data = _as_result_dict(result)
    facts = set(extract_authorized_facts(data))
    for finding in result.findings:
        facts.add(AuthorizedFact("verdict", f"findings[{finding.finding_id}].state", finding.state, "exact"))
    verdict = result.integrity.get("agent_verdict")
    if isinstance(verdict, str):
        facts.add(AuthorizedFact("verdict", "integrity.agent_verdict", verdict, "exact"))
    return HallucinationGuard(frozenset(facts)).check(narration)
