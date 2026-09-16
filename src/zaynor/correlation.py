"""Stage 3: group alerts into a candidate case with a deterministic
fingerprint. The fingerprint proves reproducible grouping, not causality —
see AGENTS.md's three-identifier note (event_id / alert_fingerprint /
incident_key are distinct and must not collapse into one hash).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from zaynor.schemas import Alert, Case, Correlation, TelemetryEvent


@dataclass(frozen=True)
class CorrelationInput:
    account: str
    target_host: str
    logical_window: int


def _fingerprint(rule_id: str, correlation_input: CorrelationInput) -> str:
    payload = "|".join(
        [
            rule_id,
            correlation_input.account,
            correlation_input.target_host,
            str(correlation_input.logical_window),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def correlate(
    alert: Alert,
    triggering_event: TelemetryEvent,
    related_events: list[TelemetryEvent],
    window_seconds: int,
) -> Correlation:
    """Group `alert` with any `related_events` inside `window_seconds` of the
    triggering event, keyed on account and target host.

    `related_events` is provided by the caller (a simple time-window scan of
    the replay), not discovered by this function — correlation groups what
    it is given, it does not itself search the whole stream.
    """
    account = triggering_event.fields.get("account", "")
    target_host = ""
    for event in related_events:
        host = event.fields.get("host")
        if host:
            target_host = host
            break

    logical_window = triggering_event.logical_time // window_seconds
    correlation_input = CorrelationInput(
        account=account, target_host=target_host, logical_window=logical_window
    )
    fingerprint = _fingerprint(alert.rule_id, correlation_input)

    priority = "high" if alert.severity == "high" and target_host else "medium"

    return Correlation(
        correlation_id=fingerprint,
        alert_ids=(alert.alert_id,),
        fingerprint=fingerprint,
        priority=priority,
    )


def open_case(alert: Alert, correlation: Correlation, evidence_profile: str) -> Case:
    """Declare stage-4's candidate incident. `case_id` reuses the
    correlation fingerprint: opening the same correlation twice must yield
    the same case_id, not a fresh random identity.
    """
    return Case(
        case_id=f"INC-{correlation.fingerprint[:12]}",
        opened_by_rule_id=alert.rule_id,
        opened_by_alert_ids=correlation.alert_ids,
        correlation_id=correlation.correlation_id,
        priority=correlation.priority,
        evidence_profile=evidence_profile,
    )
