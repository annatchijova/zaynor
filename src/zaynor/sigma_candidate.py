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

import json
from dataclasses import dataclass, field

from zaynor.schemas import EvidenceRef, ZaynorAuthoritativeResult

_YAML_INDICATOR_LEADING_CHARS = set("-?:,[]{}#&*!|>'\"%@`")


def _yaml_scalar(value: object) -> str:
    """Render one value as a safe YAML scalar for `to_yaml_text`'s manual
    line-based rendering (no pyyaml dependency; see module docstring).

    Confirmed by red-team round 7 (RT-01): a title/tag/detection value
    containing `:`, a newline, or a YAML structural character, interpolated
    unescaped, either produces YAML `yaml.safe_load` rejects outright, or —
    worse — is parsed as an entirely different, forged top-level key (a
    title of `"Suspicious login\\nvalidated: true"` makes a downstream
    parser read a fabricated `validated: true` key that was never on the
    `SigmaCandidate` object, whose own `validated` field is fixed `False`
    by construction). A value with no YAML-significant character is
    rendered plain, for readability, matching prior output exactly; any
    other string is rendered as a JSON-quoted scalar — JSON string syntax
    is valid YAML double-quoted-scalar syntax, so this needs no library.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if not isinstance(value, str):
        value = str(value)
    if (
        value != ""
        and value == value.strip()
        and "\n" not in value
        and "\r" not in value
        and ": " not in value
        and not value.endswith(":")
        and value[0] not in _YAML_INDICATOR_LEADING_CHARS
        and value.lower() not in ("true", "false", "null", "yes", "no", "~")
    ):
        return value
    return json.dumps(value)


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
            f"title: {_yaml_scalar(self.title)}",
            "status: experimental",
            f"description: >-",
            f"  Candidate rule generated from ZAYNOR finding {self.finding_id}.",
            "  Not independently validated. Requires human review before deployment.",
            "logsource:",
        ]
        for key, value in self.logsource.items():
            lines.append(f"  {_yaml_scalar(key)}: {_yaml_scalar(value)}")
        lines.append("detection:")
        for key, value in self.detection.items():
            key_text = _yaml_scalar(key)
            if isinstance(value, dict):
                lines.append(f"  {key_text}:")
                for inner_key, inner_value in value.items():
                    lines.append(f"    {_yaml_scalar(inner_key)}: {_yaml_scalar(inner_value)}")
            elif isinstance(value, (list, tuple)):
                lines.append(f"  {key_text}:")
                for item in value:
                    lines.append(f"    - {_yaml_scalar(item)}")
            else:
                lines.append(f"  {key_text}: {_yaml_scalar(value)}")
        if self.tags:
            lines.append("tags:")
            for tag in self.tags:
                lines.append(f"  - {_yaml_scalar(tag)}")
        return "\n".join(lines) + "\n"


class SigmaCandidateError(ValueError):
    """A proposed Sigma candidate is not grounded in the sealed result."""


def propose_sigma_candidate(
    *,
    finding_id: str,
    evidence_refs: tuple[EvidenceRef, ...],
    title: str,
    logsource: dict[str, str],
    detection: dict[str, object],
    tags: tuple[str, ...] = (),
    authorized_result: ZaynorAuthoritativeResult,
) -> SigmaCandidate:
    """The only constructor — kept separate from the dataclass itself so a
    future "promote candidate to validated rule" step, if ever built, must
    be its own explicit, human-gated function rather than a quiet default
    change here.

    `authorized_result` is required (same reasoning and pattern as
    `response_actions.propose_response_action`, red-team round 7 RT-02):
    `finding_id` must be one produced by the sealed result, and every
    `evidence_refs` entry must be among *that finding's own* refs —
    scoped per-finding, not just anywhere in the result, matching
    `authority_guard.py`'s existing per-finding evidence check. Before
    this, a Sigma candidate could cite a `finding_id`/evidence pair VIGÍA
    never produced, reaching a detection engineer as if it were grounded.
    """
    authorized = {finding.finding_id: finding for finding in authorized_result.findings}
    finding = authorized.get(finding_id)
    if finding is None:
        raise SigmaCandidateError(f"finding_id {finding_id!r} is not present in the sealed authoritative result")
    allowed_refs = {(ref.artifact, ref.lineage_id) for ref in finding.evidence_refs}
    for ref in evidence_refs:
        if (ref.artifact, ref.lineage_id) not in allowed_refs:
            raise SigmaCandidateError(
                f"evidence_ref {ref.artifact!r}/{ref.lineage_id!r} is not "
                f"among finding {finding_id!r}'s authorized evidence"
            )
    return SigmaCandidate(
        finding_id=finding_id,
        evidence_refs=evidence_refs,
        title=title,
        logsource=logsource,
        detection=detection,
        tags=tags,
    )
