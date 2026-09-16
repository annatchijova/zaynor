"""DETECTION_ENGINEER role tool handler — wires `draft_sigma_rule` to the
real `sigma_candidate.py` module.

`sigma_candidate.py` already existed as real, tested, standalone code
(the "candidate, never a validated rule" CANDIDATE SIGMA RULE contract);
this module is the missing connection to `AgentRuntime`, matching the
pattern already used for INVESTIGATOR (`investigator_tools.py`) and
FLEET_COMMANDER (`fleet_commander_tools.py`).
"""

from __future__ import annotations

from typing import Any

from zaynor.schemas import EvidenceRef, ZaynorAuthoritativeResult
from zaynor.sigma_candidate import SigmaCandidateError, propose_sigma_candidate


class DetectionEngineerToolError(ValueError):
    """A DETECTION_ENGINEER tool call could not be completed."""


def _evidence_refs_from_arguments(raw: Any) -> tuple[EvidenceRef, ...]:
    if not isinstance(raw, list):
        raise DetectionEngineerToolError("evidence_refs must be a list of objects")
    refs = []
    for item in raw:
        if not isinstance(item, dict):
            raise DetectionEngineerToolError("each evidence_refs entry must be an object")
        artifact, lineage_id = item.get("artifact"), item.get("lineage_id")
        if not isinstance(artifact, str) or not isinstance(lineage_id, str):
            raise DetectionEngineerToolError("evidence_refs entries require string artifact and lineage_id")
        refs.append(EvidenceRef(artifact=artifact, lineage_id=lineage_id))
    return tuple(refs)


def draft_sigma_rule(authorized_result: ZaynorAuthoritativeResult, arguments: dict[str, Any]) -> Any:
    """DERIVE:detection_rule — proposes a Sigma CANDIDATE grounded in one
    finding of the sealed result. Every field required by
    `propose_sigma_candidate` must be present; grounding (finding_id and
    evidence_refs must trace to `authorized_result`) is enforced there,
    not duplicated here.
    """
    finding_id = arguments.get("finding_id")
    title = arguments.get("title")
    logsource = arguments.get("logsource")
    detection = arguments.get("detection")
    tags = arguments.get("tags", [])
    if not isinstance(finding_id, str) or not finding_id.strip():
        raise DetectionEngineerToolError("draft_sigma_rule requires a non-empty string 'finding_id'")
    if not isinstance(title, str) or not title.strip():
        raise DetectionEngineerToolError("draft_sigma_rule requires a non-empty string 'title'")
    if not isinstance(logsource, dict):
        raise DetectionEngineerToolError("draft_sigma_rule requires an object 'logsource'")
    if not isinstance(detection, dict):
        raise DetectionEngineerToolError("draft_sigma_rule requires an object 'detection'")
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        raise DetectionEngineerToolError("draft_sigma_rule 'tags' must be a list of strings")

    try:
        candidate = propose_sigma_candidate(
            finding_id=finding_id,
            evidence_refs=_evidence_refs_from_arguments(arguments.get("evidence_refs", [])),
            title=title,
            logsource=logsource,
            detection=detection,
            tags=tuple(tags),
            authorized_result=authorized_result,
        )
    except SigmaCandidateError as exc:
        raise DetectionEngineerToolError(str(exc)) from exc
    return candidate.to_dict()


def build_detection_engineer_tools(authorized_result: ZaynorAuthoritativeResult) -> dict[str, Any]:
    """The real DETECTION_ENGINEER tool set for
    `AgentRuntime.run(AgentRole.DETECTION_ENGINEER, tools=build_detection_engineer_tools(...))`.
    """
    return {"draft_sigma_rule": lambda arguments: draft_sigma_rule(authorized_result, arguments)}
