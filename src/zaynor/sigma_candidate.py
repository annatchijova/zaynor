"""Sigma detection-rule CANDIDATE generation.

A candidate is always exactly that — never presented as a validated,
ready-to-deploy rule. Every representation of a `SigmaCandidate` (the
object's own fields, its dict form, and its rendered YAML text) carries the
same explicit warning; there is no code path that strips it.

    CANDIDATE SIGMA RULE
    Generated from finding F-003
    Evidence: E17, E21
    Not independently validated

No YAML library dependency: the rule structure this module needs is small
and fixed, so the text is built directly — avoids adding `pyyaml` for a
handful of key/value lines.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from zaynor.schemas import EvidenceRef


@dataclass(frozen=True)
class SigmaCandidate:
    finding_id: str
    evidence_refs: tuple[EvidenceRef, ...]
    title: str
    logsource: dict[str, str]
    detection: dict[str, object]
    tags: tuple[str, ...] = field(default_factory=tuple)
    validated: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if not self.finding_id.strip():
            raise ValueError("finding_id must be a non-empty string")
        if not self.evidence_refs:
            raise ValueError("a Sigma candidate must cite at least one evidence_ref")
        if not self.title.strip():
            raise ValueError("title must be a non-empty string")
        if "condition" not in self.detection:
            raise ValueError("detection must include a 'condition' key")

    def banner(self) -> str:
        evidence_ids = ", ".join(ref.artifact for ref in self.evidence_refs)
        return (
            "CANDIDATE SIGMA RULE\n"
            f"Generated from finding {self.finding_id}\n"
            f"Evidence: {evidence_ids}\n"
            "Not independently validated"
        )

    def to_dict(self) -> dict:
        return {
            "banner": self.banner(),
            "is_candidate": True,
            "validated": self.validated,
            "finding_id": self.finding_id,
            "evidence_refs": [{"artifact": r.artifact, "lineage_id": r.lineage_id} for r in self.evidence_refs],
            "title": self.title,
            "logsource": dict(self.logsource),
            "detection": dict(self.detection),
            "tags": list(self.tags),
        }

    def to_yaml_text(self) -> str:
        lines = [
            "# " + "=" * 60,
            "# CANDIDATE SIGMA RULE",
            f"# Generated from finding {self.finding_id}",
            f"# Evidence: {', '.join(r.artifact for r in self.evidence_refs)}",
            "# NOT INDEPENDENTLY VALIDATED — human review required before use",
            "# " + "=" * 60,
            f"title: {self.title}",
            "status: experimental",
            f"description: >-",
            f"  Candidate rule generated from ZAYNOR finding {self.finding_id}.",
            "  Not independently validated. Requires human review before deployment.",
            "logsource:",
        ]
        for key, value in self.logsource.items():
            lines.append(f"  {key}: {value}")
        lines.append("detection:")
        for key, value in self.detection.items():
            if isinstance(value, dict):
                lines.append(f"  {key}:")
                for inner_key, inner_value in value.items():
                    lines.append(f"    {inner_key}: {inner_value}")
            elif isinstance(value, (list, tuple)):
                lines.append(f"  {key}:")
                for item in value:
                    lines.append(f"    - {item}")
            else:
                lines.append(f"  {key}: {value}")
        if self.tags:
            lines.append("tags:")
            for tag in self.tags:
                lines.append(f"  - {tag}")
        return "\n".join(lines) + "\n"


def propose_sigma_candidate(
    *,
    finding_id: str,
    evidence_refs: tuple[EvidenceRef, ...],
    title: str,
    logsource: dict[str, str],
    detection: dict[str, object],
    tags: tuple[str, ...] = (),
) -> SigmaCandidate:
    """The only constructor — kept separate from the dataclass itself so a
    future "promote candidate to validated rule" step, if ever built, must
    be its own explicit, human-gated function rather than a quiet default
    change here.
    """
    return SigmaCandidate(
        finding_id=finding_id,
        evidence_refs=evidence_refs,
        title=title,
        logsource=logsource,
        detection=detection,
        tags=tags,
    )
