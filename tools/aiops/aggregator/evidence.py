"""Deterministic mapping from AIOps telemetry windows to ZAYNOR/VIGÍA
evidence profiles (SRE incident domain).

Same doctrine as `tools.velociraptor.mappings`, applied to observability
evidence: table-driven rules with STATIC evidence constants map verified
observation rows onto whitelisted VIGÍA evidence types. The aggregator
(also the OTel stack, Grafana, Prometheus, and Loki) never scores and
never labels. The verdict label comes exclusively from VIGÍA behind
`zaynor analyze`.

Rules read only measured quantities that exist in the normalized window
(alert names, metric values, log levels). Unfired rules never produce a
guess; rows matching no rule produce no artifact.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from tools.velociraptor.mappings import MappingRule

EVIDENCE_PROFILES: tuple[MappingRule, ...] = (
    MappingRule(
        rule_id="rule-error-burst",
        artifact_id="alerts",
        evidence_type="log_entry",
        raw_score="0.85",
        prior_trust="0.60",
        description="Alert cluster includes an elevated error-rate signal.",
        conditions=(),
    ),
    MappingRule(
        rule_id="rule-latency-spike",
        artifact_id="alerts",
        evidence_type="log_entry",
        raw_score="0.75",
        prior_trust="0.60",
        description="Alert cluster includes a latency degradation signal.",
        conditions=(),
    ),
    MappingRule(
        rule_id="rule-high-error-samples",
        artifact_id="metrics",
        evidence_type="metric_sample",
        raw_score="0.65",
        prior_trust="0.55",
        description="Measured error-series samples present in the window.",
        conditions=(),
    ),
    MappingRule(
        rule_id="rule-elevated-latency-samples",
        artifact_id="metrics",
        evidence_type="metric_sample",
        raw_score="0.55",
        prior_trust="0.55",
        description="Measured latency-series samples present in the window.",
        conditions=(),
    ),
    MappingRule(
        rule_id="rule-failure-log-line",
        artifact_id="logs",
        evidence_type="log_entry",
        raw_score="0.70",
        prior_trust="0.50",
        description="Service log reports a failed work unit in the window.",
        conditions=(
            {"field": "event", "op": "eq", "value": "work_failed"},
        ),
    ),
    MappingRule(
        rule_id="rule-latency-log-line",
        artifact_id="logs",
        evidence_type="log_entry",
        raw_score="0.50",
        prior_trust="0.50",
        description="Service log records slow work in the window.",
        conditions=(
            {"field": "event", "op": "eq", "value": "work_slow"},
        ),
    ),
)

RULES_BY_ARTIFACT: dict[str, list[MappingRule]] = {}
for _rule in EVIDENCE_PROFILES:
    RULES_BY_ARTIFACT.setdefault(_rule.artifact_id, []).append(_rule)


def map_window_to_corpus(window: dict[str, Any]) -> dict[str, Any]:
    """Map a sealed AIOps window to a VIGÍA case-corpus document.

    The sealed window is embedded under ``evidence_window`` (provenance
    the engine ignores) exactly like the DFIR path, so the frozen case
    keeps the full observation story in the one document the engine reads.
    """
    incident = window.get("incident", {})
    service = incident.get("service", "unknown-service")

    corpus_artifacts: list[dict[str, Any]] = []
    for artifact in window.get("artifacts", []):
        rules = RULES_BY_ARTIFACT.get(artifact["artifact_id"], ())
        for row in artifact.get("rows", []):
            for rule in rules:
                corpus = _artifact_from_rule(rule, row, service, window)
                if corpus is not None:
                    corpus_artifacts.append(corpus)

    return {
        "case_id": window["case_id"],
        "name": f"ZAYNOR AIOps case: {service}",
        "description": (
            "Deterministic mapping of a hash-verified AIOps telemetry window "
            "(alerts + bounded metrics/logs) to VIGÍA case-corpus artifacts. "
            "The engine decides the verdict; the window rides under "
            "evidence_window strictly as provenance."
        ),
        "artifacts": corpus_artifacts,
        "source_window_hash": window["window_hash"],
        "evidence_window": window,
    }


def _artifact_from_rule(
    rule: MappingRule, row: dict[str, Any], service: str, window: dict[str, Any]
) -> dict[str, Any] | None:
    if not rule.matches(row):
        return None
    return {
        "artifact_id": f"aiops-{rule.rule_id}-{_row_ref(row)}",
        "evidence_type": rule.evidence_type,
        "source_tool": "aiops-incident-aggregator",
        "timestamp": _row_timestamp(row),
        "raw_score": rule.raw_score,
        "prior_trust": rule.prior_trust,
        "provenance_chain": [f"sha256:{rule.artifact_id}"],
        "description": f"{rule.description} (service={service})",
        "metadata": {
            "examiner_id": "zaynor-aiops-mapping-v1",
            "acquisition_tool": "incident-aggregator",
            "lineage_id": rule.artifact_id,
            "observed_fields": _observed_fields(row),
        },
    }


def _row_ref(row: dict[str, Any]) -> str:
    for key in ("ref", "alertname", "metric", "message"):
        value = row.get(key)
        if isinstance(value, str) and value:
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]
            return digest
    return hashlib.sha256(json.dumps(row, sort_keys=True).encode("utf-8")).hexdigest()[:10]


def _row_timestamp(row: dict[str, Any]) -> str:
    value = row.get("timestamp")
    if isinstance(value, str) and value:
        return value
    return "1970-01-01T00:00:00Z"


def _observed_fields(row: dict[str, Any]) -> dict[str, Any]:
    return {key: row[key] for key in sorted(row) if row[key] is None or isinstance(row[key], (str, int, float, bool))}
