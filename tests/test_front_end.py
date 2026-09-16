from pathlib import Path

from zaynor.correlation import correlate, open_case
from zaynor.detection import detect_suspicious_privileged_login
from zaynor.replay import replay

FIXTURE = Path(__file__).parent.parent / "scenarios" / "inc-2026-demo-001" / "telemetry.jsonl"
KNOWN_DEVICES = {"DEV-CORP-01", "DEV-CORP-02", "DEV-CORP-LAPTOP-09"}


def test_replay_is_deterministic_across_runs():
    first = list(replay(FIXTURE))
    second = list(replay(FIXTURE))
    assert [e.event_id for e in first] == [e.event_id for e in second]
    assert len(first) == 5


def test_detection_fires_on_unknown_device():
    events = list(replay(FIXTURE))
    alerts = detect_suspicious_privileged_login(events, KNOWN_DEVICES)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "suspicious_privileged_login"


def test_detection_negative_case_known_device_does_not_fire():
    """Acceptance criterion from the informe: marking the device 'known'
    must prevent the incident from opening at all.
    """
    events = list(replay(FIXTURE))
    known_including_this_device = KNOWN_DEVICES | {"DEV-UNKNOWN-17"}
    alerts = detect_suspicious_privileged_login(events, known_including_this_device)
    assert alerts == []


def test_correlation_and_case_open_are_reproducible():
    events = list(replay(FIXTURE))
    alerts = detect_suspicious_privileged_login(events, KNOWN_DEVICES)
    login_event = events[0]

    correlation = correlate(alerts[0], login_event, events, window_seconds=120)
    case = open_case(alerts[0], correlation, evidence_profile="admin-session-investigation")

    # Re-running the same stream must reproduce the same fingerprint and
    # case_id, not a fresh random identity.
    events_again = list(replay(FIXTURE))
    alerts_again = detect_suspicious_privileged_login(events_again, KNOWN_DEVICES)
    correlation_again = correlate(alerts_again[0], events_again[0], events_again, window_seconds=120)
    case_again = open_case(alerts_again[0], correlation_again, evidence_profile="admin-session-investigation")

    assert correlation.fingerprint == correlation_again.fingerprint
    assert case.case_id == case_again.case_id
    assert case.priority == "high"
