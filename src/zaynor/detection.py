"""Stage 2: one real, explicit detection rule.

Deliberately not a generic rule engine — a single named Python function.
AGENTS.md "Scope: the hybrid pipeline" is explicit that stages 1-3 stay
small and genuinely deterministic; a rule engine belongs to production
AIOps infrastructure, not a demo-scale front end.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

from zaynor.schemas import Alert, TelemetryEvent

RULE_ID = "suspicious_privileged_login"

# Events within this many logical-time units of a suspicious login are
# considered part of the same candidate window for downstream correlation.
CORRELATION_WINDOW_SECONDS = 120


def _alert_id(rule_id: str, triggering_event_ids: tuple[str, ...]) -> str:
    payload = json.dumps(
        {"rule_id": rule_id, "triggering_event_ids": list(triggering_event_ids)},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def detect_suspicious_privileged_login(
    events: Iterable[TelemetryEvent], known_devices: set[str]
) -> list[Alert]:
    """Fire when a privileged account logs in from a device outside
    `known_devices`. Both predicates come directly from the event; nothing
    here infers intent — that is explicitly out of scope for a deterministic
    rule (see AGENTS.md §2.3).
    """
    alerts: list[Alert] = []
    for event in events:
        if event.event_type != "vpn_login":
            continue
        if not event.fields.get("success"):
            continue
        if event.fields.get("account_role") != "privileged":
            continue
        device = event.fields.get("device")
        if device is None or device in known_devices:
            continue

        alerts.append(
            Alert(
                alert_id=_alert_id(RULE_ID, (event.event_id,)),
                rule_id=RULE_ID,
                severity="high",
                reason="privileged_login_from_unknown_device",
                triggering_event_ids=(event.event_id,),
            )
        )
    return alerts
