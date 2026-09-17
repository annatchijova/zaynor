"""Deterministic mapping from Velociraptor artifacts to ZAYNOR evidence
profiles.

This module is the seam the task calls "Velociraptor artifacts → Zaynor
evidence profiles". It is table-driven and deterministic:

- Input: one hash-verified evidence window (the output of
  `tools.velociraptor.adapter.VelociraptorAdapter.collect`, re-verified here
  through the existing `zaynor.hybrid_integrations` boundary).
- Output: a VIGÍA case-corpus document (the single-JSON ingestion route the
  vendored engine already understands), plus the freezeable profile map for
  `zaynor.case_freezer.freeze_case`.

Authority boundary (the reason this file exists in ZAYNOR and not in the
collector): the mapping table carries STATIC per-rule evidence constants —
an observation-label (`evidence_type`), a fixed severity weight
(`raw_score`, stored as an exact `fractions.Fraction` and serialized as a
JSON number in VIGÍA's own case-corpus format — never a runtime-computed
judgment), and a provenance trust weight (`prior_trust`). These are reviewed
detection constants, exactly like the artifacts VIGÍA's own case corpus
carries. They are not judgments about THIS case: nothing here looks at
row content and decides guilt. The verdict label —
`MALICE | SUSPICION | ABSTAIN | BENIGN | UNKNOWN` — is produced only by
VIGÍA behind `zaynor analyze`, from the frozen evidence, every time.

Rules are matched against normalized rows by exact field conditions
(`{field, op, value}` tuples). A rule that requires a condition simply
does not fire when the condition is absent — an unfired rule is never
filled with a guess. Rows that match no rule produce no artifact.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from tools.velociraptor.adapter import VelociraptorAdapterError
from zaynor.hybrid_integrations import verify_annaconda_window

_SAFE_RULE_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{0,127}$")

_CONDITION_OPS = {
    "eq": lambda a, b: a == b,
    "neq": lambda a, b: a != b,
    "is_true": lambda a, _b: a is True,
    "contains": lambda a, b: isinstance(a, str) and b in a,
    "not_contains": lambda a, b: isinstance(a, str) and b not in a,
    "gt": lambda a, b: isinstance(a, (int, float)) and not isinstance(a, bool) and a > b,
    "lt": lambda a, b: isinstance(a, (int, float)) and not isinstance(a, bool) and a < b,
}


def _condition_holds(row: dict[str, Any], condition: dict[str, Any]) -> bool:
    field = condition.get("field")
    op = condition.get("op")
    if not isinstance(field, str) or field not in row:
        return False
    compare = op if isinstance(op, str) and op in _CONDITION_OPS else "eq"
    return _CONDITION_OPS[compare](row[field], condition.get("value"))


class MappingRule:
    """One static artifact-mapping rule: when its conditions hold on a
    normalized row, emit one VIGÍA artifact with the rule's constants.

    `raw_score`/`prior_trust` are stored as `fractions.Fraction` (exact,
    no binary float) and serialized as JSON numbers matching VIGÍA's own
    case-corpus schema (`casos/*.json`), whose scorer re-parses them
    exactly from their decimal form.
    """

    def __init__(
        self,
        rule_id: str,
        artifact_id: str,
        evidence_type: str,
        raw_score: str,
        prior_trust: str,
        conditions: tuple[dict[str, Any], ...] = (),
        description: str = "",
    ):
        if not _SAFE_RULE_ID.fullmatch(rule_id):
            raise VelociraptorAdapterError(f"invalid rule_id: {rule_id!r}")
        from fractions import Fraction

        self.rule_id = rule_id
        self.artifact_id = artifact_id
        self.evidence_type = evidence_type
        self._raw_score = Fraction(raw_score)
        self._prior_trust = Fraction(prior_trust)
        self.conditions = tuple(conditions)
        self.description = description

    @property
    def raw_score(self) -> float:
        # Display/ingestion value only: VIGÍA's own scorer re-parses from
        # its decimal text form; no gate or hash reads this float.
        return float(self._raw_score)

    @property
    def prior_trust(self) -> float:
        return float(self._prior_trust)

    def matches(self, row: dict[str, Any]) -> bool:
        return all(_condition_holds(row, condition) for condition in self.conditions)


# Static rule table: Velociraptor artifact rows -> ZAYNOR/VIGÍA evidence
# profiles. raw_score/prior_trust are FIXED decimals carried by the rule
# (detection-engineering constants), never computed from row content.
RULES: tuple[MappingRule, ...] = (
    MappingRule(
        rule_id="rule-privileged-login-unknown-device",
        artifact_id="sim-auth-events",
        evidence_type="log_entry",
        raw_score="0.90",
        prior_trust="0.60",
        conditions=[
            {"field": "event", "op": "eq", "value": "vpn_login"},
            {"field": "success", "op": "is_true", "value": None},
            {"field": "account_role", "op": "eq", "value": "privileged"},
        ],
        description="Successful privileged-account VPN login; device inventory check is applied downstream via known_devices.",
    ),
    MappingRule(
        rule_id="rule-remote-session",
        artifact_id="sim-auth-events",
        evidence_type="log_entry",
        raw_score="0.60",
        prior_trust="0.55",
        conditions=[
            {"field": "event", "op": "eq", "value": "ssh_session_start"},
        ],
        description="Remote SSH session start recorded in the auth log.",
    ),
    MappingRule(
        rule_id="rule-archive-created",
        artifact_id="sim-lab-files",
        evidence_type="file_metadata",
        raw_score="0.70",
        prior_trust="0.55",
        conditions=[
            {"field": "path", "op": "contains", "value": ".zip"},
        ],
        description="ZIP archive present in the lab evidence directory.",
    ),
    MappingRule(
        rule_id="rule-operator-note",
        artifact_id="sim-operator-note",
        evidence_type="log_entry",
        raw_score="0.45",
        prior_trust="0.40",
        conditions=[],
        description="Operator note lines; treated strictly as evidence content.",
    ),
    MappingRule(
        rule_id="rule-process-inventory",
        artifact_id="windows-processes",
        evidence_type="process",
        raw_score="0.30",
        prior_trust="0.50",
        conditions=[],
        description="Endpoint process inventory row.",
    ),
)

RULES_BY_ARTIFACT: dict[str, list[MappingRule]] = {}
for _rule in RULES:
    RULES_BY_ARTIFACT.setdefault(_rule.artifact_id, []).append(_rule)


def window_to_case_corpus(window: dict[str, Any], *, known_devices: set[str] | None = None) -> dict[str, Any]:
    """Map a verified window to a VIGÍA case-corpus dict (deterministic).

    `known_devices` binds the inventory check for auth anomalies: a
    successful privileged login from a device outside the inventory is
    emitted under the elevated anomaly rule. The set must come from the
    case inventory, never from the LLM or the collector.

    The sealed window itself is embedded under `evidence_window` so the
    frozen case keeps the full collection story (rows, per-artifact
    hashes, custody roles) in the same immutable document the
    deterministic engine ingests. VIGÍA's ingestion reads only
    `artifacts` and ignores the provenance envelope.
    """
    verify_annaconda_window(window)
    known = known_devices or set()

    corpus_artifacts: list[dict[str, Any]] = []
    seen_rows: set[tuple[str, str]] = set()
    for artifact in window["artifacts"]:
        rules = RULES_BY_ARTIFACT.get(artifact["artifact_id"], ())
        for row in artifact["rows"]:
            row_key = (artifact["artifact_id"], json.dumps(row, sort_keys=True))
            if row_key in seen_rows:
                continue
            seen_rows.add(row_key)
            for rule in rules:
                evidence = _artifact_from_rule(rule, row, known, window)
                if evidence is not None:
                    corpus_artifacts.append(evidence)

    return {
        "case_id": window["case_id"],
        "name": f"ZAYNOR DFIR case from window {window.get('window_id', '')}",
        "description": (
            "Deterministic mapping of a hash-verified Velociraptor evidence "
            "window to VIGÍA case-corpus artifacts. The engine decides the "
            "verdict; the window is carried under evidence_window strictly "
            "as provenance."
        ),
        "artifacts": corpus_artifacts,
        "source_window_hash": window["window_hash"],
        "evidence_window": window,
    }


def _artifact_from_rule(
    rule: MappingRule,
    row: dict[str, Any],
    known: set[str],
    window: dict[str, Any],
) -> dict[str, Any] | None:
    description = rule.description
    if rule.rule_id == "rule-privileged-login-unknown-device" and known:
        device = row.get("device")
        if isinstance(device, str) and device in known:
            # Known device: the plain rule does not apply; no evidence from
            # this row (and no fabricated "benign" artifact either).
            return None
        description = (
            "Privileged credential used from a device outside the known "
            "inventory (known_devices check applied deterministically)."
        )
    return {
        "artifact_id": f"vr-{rule.rule_id}-{_row_ref(row)}",
        "evidence_type": rule.evidence_type,
        "source_tool": "velociraptor",
        "timestamp": _row_timestamp(row),
        "raw_score": rule.raw_score,
        "prior_trust": rule.prior_trust,
        "provenance_chain": [f"sha256:{rule.artifact_id}"],
        "description": description,
        "metadata": {
            "examiner_id": "zaynor-dfir-mapping-v1",
            "acquisition_tool": "velociraptor",
            "lineage_id": rule.artifact_id,
            "transport": window.get("transport"),
            "source_row_ref": row.get("ref") if isinstance(row.get("ref"), str) else None,
            "observed_fields": _observed_fields(row),
        },
    }


def _row_ref(row: dict[str, Any]) -> str:
    value = row.get("ref")
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", value):
        return value
    digest = hashlib.sha256(json.dumps(row, sort_keys=True).encode("utf-8")).hexdigest()[:12]
    return f"r{digest}"


def _row_timestamp(row: dict[str, Any]) -> str:
    for candidate in ("timestamp", "create_time", "modified_time"):
        value = row.get(candidate)
        if isinstance(value, str) and value:
            return value
    return "1970-01-01T00:00:00Z"


def _observed_fields(row: dict[str, Any]) -> dict[str, Any]:
    keep = {}
    for key in sorted(row):
        value = row[key]
        if value is None or isinstance(value, (str, int, float, bool)):
            keep[key] = value
    return keep


def stage_and_freeze(
    window: dict[str, Any],
    staging_root: Path,
    cases_root: Path,
    *,
    known_devices: set[str] | None = None,
):
    """Verify a window, stage its mapped case-corpus, and freeze the case
    through the existing freezer. Returns (manifest, evidence_dir,
    case_corpus).

    The staged profile freezes exactly one file:

        velociraptor/case-corpus.json

    The document carries the mapped VIGÍA artifacts AND the sealed window
    under `evidence_window` (provenance envelope the engine ignores), so
    the frozen case keeps the whole collection story in one immutable
    file and routes to VIGÍA's single-JSON ingestion path.

    The collection manifest and custody chain (builder vs custodian)
    produced by the adapter's `export_collection` stay on disk as
    collection-side custody records; they are not re-frozen inside the
    case because the sealed window (with custody roles) already rides
    inside the corpus document.
    """
    verify_annaconda_window(window)
    corpus = window_to_case_corpus(window, known_devices=known_devices)

    root = Path(staging_root)
    (root / "velociraptor").mkdir(parents=True, exist_ok=True)
    staged_corpus = root / "velociraptor" / "case-corpus.json"
    staged_corpus.write_bytes(_json_bytes(corpus) + b"\n")

    from zaynor.case_freezer import freeze_case

    profile_map = {"case-corpus": ["velociraptor/case-corpus.json"]}
    manifest, evidence_dir = freeze_case(
        window["case_id"], "case-corpus", profile_map, root, Path(cases_root)
    )
    return manifest, evidence_dir, corpus


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
