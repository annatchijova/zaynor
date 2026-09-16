"""Deterministic EBS-artifact scorer for the `INC-2026-DEMO-001` fixture.

Confirmed in Phase 0 by reading `vigia_agent.py`/`sift_orchestrator.py`
directly: pointing `--evidence` at a single `.json` file (not a directory)
routes through `_build_orchestrator_kwargs` into `log_path`, and
`_analyze_ebs_json` (since it ends in `.json`) parses
`{"case_id", "artifacts": [{"artifact_id", "evidence_type", "raw_score",
"prior_trust", "description", "source_tool"}]}` and feeds it to
`vigia_scorer._vigia_score` — the real deterministic decision ladder
(TrustFusion -> CorrelationDecay -> CAIE -> Decision -> Quadripartite,
thresholds 0.33/0.18/0.08). Confirmed empirically (not assumed) that
`raw_score` is not a free-form "severity dial": pushing one artifact's
`raw_score` past 1.0 (a 3.5/3.2 test) did not change the verdict — the
composite ladder is calibrated for `raw_score`/`prior_trust` in [0, 1] each,
and reaching a non-NOISE verdict requires independently corroborating
artifacts, not one inflated number.

`raw_score`/`prior_trust` below are RULE WEIGHTS a human analyst would
assign when writing a detection rule (like a SIEM rule's severity and
source-confidence), not something mined from a deeper unavailable signal —
documented per rule so the scoring logic is auditable, not a black box.
This module is deliberately fixture-specific (it knows this scenario's
event shapes and its known-device list), not a general detector; a general
version is future work, not claimed here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any

# Mirrors scenarios/inc-2026-demo-001/inventory.json's known_devices. Not
# read from that file because it lives outside the frozen evidence profile
# (it's a stage-1-3 detection input from before the incident was declared,
# not case evidence) — hardcoded here since this scorer is fixture-specific.
_KNOWN_DEVICES = frozenset({"DEV-CORP-01", "DEV-CORP-02", "DEV-CORP-LAPTOP-09"})


@dataclass(frozen=True)
class ScoringRule:
    """One EBS artifact, with its rule weights kept as exact `Fraction`s
    until serialization — `_vigia_score`'s ladder is Fraction-exact, and a
    rule weight is exactly the kind of value AGENTS.md's "no float in the
    decision path" invariant is about, even though this input crosses a
    process boundary as JSON text.
    """

    artifact_id: str
    evidence_type: str
    raw_score: Fraction
    prior_trust: Fraction
    description: str
    source_tool: str

    def as_ebs_artifact(self) -> dict[str, str]:
        return {
            "artifact_id": self.artifact_id,
            "evidence_type": self.evidence_type,
            "raw_score": str(self.raw_score),
            "prior_trust": str(self.prior_trust),
            "description": self.description,
            "source_tool": self.source_tool,
        }


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def score_inc_2026_demo_001(evidence_dir: Path) -> list[ScoringRule]:
    """Read this fixture's frozen `collected/*.jsonl` records and apply
    three documented rules. Returns an empty list (never an error) if a
    record a rule depends on is missing — a missing signal is honestly
    absent, not a crash.
    """
    auth = _read_jsonl(evidence_dir / "collected" / "auth.jsonl")
    process = _read_jsonl(evidence_dir / "collected" / "process.jsonl")
    filesystem = _read_jsonl(evidence_dir / "collected" / "filesystem.jsonl")
    network = _read_jsonl(evidence_dir / "collected" / "network.jsonl")

    rules: list[ScoringRule] = []

    # Rule 1: privileged login from a device outside the maintained
    # inventory. Weight rationale: a privileged-account/unknown-device
    # combination is a strong, commonly-used detection signal (this is the
    # same predicate the now-descoped detection.py front end used) — 0.7
    # severity, 0.9 trust because authentication logs are a high-reliability
    # source.
    login = next((e for e in auth if e.get("event") == "vpn_login"), None)
    if login and login.get("account_role") == "privileged" and login.get("device") not in _KNOWN_DEVICES:
        rules.append(
            ScoringRule(
                artifact_id=login["ref"],
                evidence_type="auth_log",
                raw_score=Fraction(7, 10),
                prior_trust=Fraction(9, 10),
                description=(
                    f"Privileged login by {login.get('account')} from device "
                    f"{login.get('device')!r}, not in the maintained inventory"
                ),
                source_tool="zaynor_auth_rule",
            )
        )

    # Rule 2: timestomp indicator — a file's modified_time precedes its own
    # birth_time. Weight rationale: 0.65 severity (a real but not
    # unambiguous anti-forensics signal — legitimate tooling can also alter
    # mtimes), 0.85 trust for filesystem metadata.
    ts_change = next((e for e in process if e.get("event") == "file_timestamp_change"), None)
    fs_record = next((e for e in filesystem if ts_change and e.get("path") == ts_change.get("path")), None)
    if fs_record and fs_record.get("modified_time_logical", 0) < fs_record.get("birth_time_logical", 1):
        rules.append(
            ScoringRule(
                artifact_id=fs_record["ref"],
                evidence_type="filesystem_metadata",
                raw_score=Fraction(65, 100),
                prior_trust=Fraction(85, 100),
                description=(
                    f"{fs_record.get('path')}: modified_time "
                    f"({fs_record.get('modified_time_logical')}) precedes birth_time "
                    f"({fs_record.get('birth_time_logical')}) — timestomp indicator"
                ),
                source_tool="zaynor_fs_timeline_rule",
            )
        )

    # Rule 3: outbound connection from the same pid that altered the
    # timestamped file. Weight rationale: 0.5 severity (correlation, not
    # content inspection of what was sent), 0.8 trust for network telemetry.
    egress = next((e for e in network if e.get("event") == "network_egress"), None)
    if egress and ts_change and egress.get("pid") == ts_change.get("pid"):
        rules.append(
            ScoringRule(
                artifact_id=egress["ref"],
                evidence_type="network_egress",
                raw_score=Fraction(1, 2),
                prior_trust=Fraction(4, 5),
                description=(
                    f"Outbound connection to {egress.get('destination')} from the same "
                    f"pid ({egress.get('pid')}) that altered {ts_change.get('path')}"
                ),
                source_tool="zaynor_net_correlation_rule",
            )
        )

    return rules


def write_ebs_evidence(case_id: str, rules: list[ScoringRule], output_path: Path) -> Path:
    """Serialize scored artifacts into the EBS JSON shape VIGÍA's
    `_analyze_ebs_json` expects, at `output_path`. Rejects a symlinked
    destination — this writes into per-case derived-input storage, the same
    "don't follow a link to write somewhere else" posture as
    `case_freezer.py`/`vigia_mode1_executor.py`.
    """
    if output_path.exists() and output_path.is_symlink():
        raise ValueError(f"refusing to write EBS evidence through a symlink: {output_path}")
    payload = {"case_id": case_id, "artifacts": [rule.as_ebs_artifact() for rule in rules]}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return output_path
