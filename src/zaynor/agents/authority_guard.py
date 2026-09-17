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


_REQUIRED_PROJECTION_FIELDS = frozenset(
    {
        "case_id",
        "result_sha256",
        "verdict",
        "findings",
        "unknowns",
        "scores",
        "confidence",
        "fractures",
        "hypotheses",
        "mitre_techniques",
    }
)


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
    """Read the specific authorized ATT&CK field, not string shape.

    A structural guard must not infer ATT&CK semantics from a value merely
    *looking like* a technique id (`T####`) — that authorizes any string of
    the right shape, regardless of where it came from. Authorization comes
    only from `finding.mitre["technique"]`, the field VIGÍA/the adapter
    actually populates (see `AuthoritativeFinding.mitre` in schemas.py).
    """
    found: set[str] = set()
    for finding in result["findings"]:
        mitre = finding.get("mitre")
        if isinstance(mitre, Mapping):
            technique = mitre.get("technique")
            if isinstance(technique, str):
                found.add(technique.upper())
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
    missing = _REQUIRED_PROJECTION_FIELDS - set(presented)
    if missing:
        raise AuthorityGuardError(f"structured output is missing authoritative fields: {sorted(missing)}")
    _reject_floats(presented)
    verify_authoritative_result(result, seal)
    data = _as_result_dict(result)
    if presented.get("case_id") != result.case_id:
        raise AuthorityGuardError("presented case_id does not match authority")
    if presented.get("result_sha256") != seal.sha256:
        raise AuthorityGuardError("presented result hash does not match seal")

    presented_verdict = presented["verdict"]
    authorized_verdict = result.verdict
    if presented_verdict != authorized_verdict:
        raise AuthorityGuardError("presented verdict does not match authority")

    presented_findings = presented.get("findings")
    if not isinstance(presented_findings, list):
        raise AuthorityGuardError("structured output requires findings list")
    authorized_findings = {finding.finding_id: finding for finding in result.findings}
    presented_finding_ids = set()
    for finding in presented_findings:
        if not isinstance(finding, Mapping) or finding.get("finding_id") not in authorized_findings:
            raise AuthorityGuardError("presented finding_id is not authorized")
        presented_finding_ids.add(finding["finding_id"])
        authorized = authorized_findings[finding["finding_id"]]
        if finding.get("state") != authorized.state:
            raise AuthorityGuardError("presented finding state does not match authority")
        refs = finding.get("evidence_refs")
        allowed_refs = {(ref.artifact, ref.lineage_id) for ref in authorized.evidence_refs}
        if not isinstance(refs, list) or {
            (ref.get("artifact"), ref.get("lineage_id"))
            for ref in refs
            if isinstance(ref, Mapping)
        } != allowed_refs or any(
            not isinstance(ref, Mapping)
            or (ref.get("artifact"), ref.get("lineage_id")) not in allowed_refs
            for ref in refs
        ):
            raise AuthorityGuardError("presented evidence reference is not authorized")

    if presented_finding_ids != set(authorized_findings):
        raise AuthorityGuardError("structured output dropped or duplicated an authoritative finding")

    if not isinstance(presented["unknowns"], list) or presented["unknowns"] != list(result.unknowns):
        raise AuthorityGuardError("structured output dropped or altered UNKNOWN state")
    for key in ("scores", "confidence"):
        authorized = result.integrity.get(key)
        if str(presented[key]) != str(authorized):
            raise AuthorityGuardError(f"presented {key} does not match authority")
    authorized_ids = _ids(data["fractures"]) | _ids(data["hypotheses"])
    for key in ("fractures", "hypotheses"):
        if not isinstance(presented[key], list) or not all(isinstance(item, str) for item in presented[key]):
            raise AuthorityGuardError(f"presented {key} must be a list of ids")
        authorized_for_key = _ids(data[key])
        if set(presented[key]) != authorized_for_key:
            raise AuthorityGuardError(f"presented {key} is not authorized")
    allowed = _techniques(data)
    if not isinstance(presented["mitre_techniques"], list) or not all(
        isinstance(item, str) for item in presented["mitre_techniques"]
    ) or set(presented["mitre_techniques"]) != allowed:
        raise AuthorityGuardError("presented ATT&CK technique is not authorized")


def check_narrative(result: ZaynorAuthoritativeResult, narration: str):
    """Run conservative semantic narrative checking after structural checks."""
    data = _as_result_dict(result)
    facts = set(extract_authorized_facts(data))
    for finding in result.findings:
        facts.add(AuthorizedFact("verdict", f"findings[{finding.finding_id}].state", finding.state, "exact"))
    if isinstance(result.verdict, str):
        facts.add(AuthorizedFact("verdict", "verdict", result.verdict, "exact"))
    return HallucinationGuard(frozenset(facts)).check(narration)
