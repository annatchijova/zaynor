"""Tests for the AIOps incident aggregator."""

import json
from datetime import datetime, timedelta, timezone

from tools.aiops.aggregator.app import (
    Aggregator,
    alerts_from_payload,
    deterministic_incident_id,
    poll_firing_alerts,
    stage_incident_bundle,
    window_hash,
)
from tools.aiops.aggregator.evidence import map_window_to_corpus
from zaynor.hybrid_integrations import verify_annaconda_window


def _alert(name="HighErrorRate", service="demo-api", minute=0):
    base = datetime(2026, 9, 17, 2, 0, 0, tzinfo=timezone.utc)
    return {
        "alertname": name,
        "service": service,
        "environment": "lab",
        "timestamp": (base + timedelta(minutes=minute)).isoformat(),
    }


def test_alerts_within_window_correlate_into_one_candidate():
    aggregator = Aggregator("/tmp/alerts", "/tmp/staging")
    first = aggregator.ingest_alert(_alert(minute=0))
    second = aggregator.ingest_alert(_alert(name="HighLatency", minute=1))
    incidents = aggregator.incidents()
    assert len(incidents) == 1
    assert first == second
    assert {alert["alertname"] for alert in incidents[0]["alerts"]} == {"HighErrorRate", "HighLatency"}


def test_repeated_poll_observations_dedupe_into_one_entry():
    aggregator = Aggregator("/tmp/alerts", "/tmp/staging")
    aggregator.ingest_alert(_alert(minute=0))
    for offset in (10, 20, 30):
        alert = _alert(minute=0)
        alert["timestamp"] = (
            datetime(2026, 9, 17, 2, 0, offset, tzinfo=timezone.utc).isoformat()
        )
        aggregator.ingest_alert(alert)
    incidents = aggregator.incidents()
    assert len(incidents) == 1
    assert len(incidents[0]["alerts"]) == 1


def test_offline_window_records_infer_type_per_record(tmp_path):
    from tools.aiops.aggregator.app import load_typed_window_records

    window_dir = tmp_path / "window"
    window_dir.mkdir(parents=True)
    (window_dir / "metrics.jsonl").write_text(
        json.dumps({"metric": "demo_error_ratio", "service": "demo-api", "value": 0.42,
                    "timestamp": "2026-09-17T02:00:30+00:00"}) + "\n"
        + json.dumps({"level": "error", "event": "work_failed", "service": "demo-api",
                      "message": "boom", "timestamp": "2026-09-17T02:00:31+00:00"}) + "\n",
        encoding="utf-8",
    )
    samples, logs = load_typed_window_records(window_dir)
    assert len(samples) == 1 and samples[0]["evidence_type"] == "metric_sample"
    assert len(logs) == 1 and logs[0]["evidence_type"] == "log_line"
    assert logs[0]["event"] == "work_failed"


def test_alerts_beyond_window_open_new_candidates():
    aggregator = Aggregator("/tmp/alerts", "/tmp/staging")
    aggregator.ingest_alert(_alert(minute=0))
    aggregator.ingest_alert(_alert(minute=30))
    assert len(aggregator.incidents()) == 2


def test_incident_id_is_deterministic_per_minute():
    base = datetime(2026, 9, 17, 2, 0, 30, tzinfo=timezone.utc)
    id_a = deterministic_incident_id("demo-api", "lab", base)
    id_b = deterministic_incident_id("demo-api", "lab", base + timedelta(seconds=20))
    id_c = deterministic_incident_id("demo-api", "lab", base + timedelta(minutes=1))
    assert id_a == id_b
    assert id_a != id_c
    assert id_a.startswith("INC-AIOPS-")


def test_alert_without_required_fields_is_rejected():
    aggregator = Aggregator("/tmp/alerts", "/tmp/staging")
    assert aggregator.ingest_alert({"labels": {}}) is None


def test_grafana_payload_normalizes_to_alerts():
    payload = {
        "alerts": [
            {
                "labels": {"alertname": "HighErrorRate", "service": "demo-api", "environment": "lab"},
                "startsAt": "2026-09-17T02:04:00Z",
            }
        ]
    }
    alerts = alerts_from_payload(payload)
    assert len(alerts) == 1
    assert alerts[0]["service"] == "demo-api"
    assert alerts[0]["alertname"] == "HighErrorRate"


def test_staged_bundle_seals_window_and_embeds_corpus(tmp_path):
    aggregator = Aggregator("/tmp/alerts", tmp_path)
    aggregator.ingest_alert(_alert(minute=0))
    incident = aggregator.incidents()[0]
    samples = [
        {"metric": "demo_error_ratio", "service": "demo-api", "value": 0.42,
         "timestamp": "2026-09-17T02:00:30+00:00"},
    ]
    logs = [
        {"service": "demo-api", "level": "error", "event": "work_failed",
         "message": "synthetic dependency failure", "timestamp": "2026-09-17T02:00:31+00:00"},
    ]
    evidence_path = stage_incident_bundle(incident, samples, logs, tmp_path / incident["incident_id"])
    corpus = json.loads(evidence_path.read_text())
    verify_annaconda_window(corpus["evidence_window"])
    assert corpus["source_window_hash"] == corpus["evidence_window"]["window_hash"]
    assert corpus["evidence_window"]["custody"]["builder"] == "aiops-incident-aggregator"
    assert corpus["evidence_window"]["custody"]["custodian"] == "zaynor-aiops-staging"
    # The corpus carries no verdict vocabulary.
    assert "expected_verdict" not in corpus
    for artifact in corpus["artifacts"]:
        assert "expected_verdict" not in artifact


def test_window_hash_excludes_itself():
    window = {"case_id": "INC", "artifacts": []}
    assert window_hash(window) == window_hash({"case_id": "INC", "artifacts": [], "window_hash": "x"})


def test_corpus_mapping_labels_stay_absent(tmp_path):
    aggregator = Aggregator("/tmp/alerts", tmp_path)
    aggregator.ingest_alert(_alert(minute=0))
    incident = aggregator.incidents()[0]
    samples = [{"metric": "demo_error_ratio", "service": "demo-api", "value": 0.5,
                "timestamp": "2026-09-17T02:00:30+00:00"}]
    logs = [{"service": "demo-api", "event": "work_failed", "timestamp": "2026-09-17T02:00:31+00:00"}]
    evidence_path = stage_incident_bundle(incident, samples, logs, tmp_path / incident["incident_id"])
    corpus = json.loads(evidence_path.read_text())
    mapped = map_window_to_corpus(corpus["evidence_window"])
    assert mapped["case_id"] == incident["incident_id"]
    for artifact in mapped["artifacts"]:
        assert artifact["evidence_type"] in ("log_entry", "metric_sample")
        assert "verdict" not in artifact



def test_poll_firing_alerts_ingests_grafana_rules(monkeypatch):
    from tools.aiops.aggregator import app as app_module

    rules_payload = {
        "data": {
            "groups": [
                {
                    "rules": [
                        {
                            "name": "HighErrorRate",
                            "state": "firing",
                            "alerts": [
                                {
                                    "labels": {"alertname": "HighErrorRate", "service": "demo-api"},
                                    "activeAt": "2026-09-17T02:04:00Z",
                                }
                            ],
                        },
                        {"name": "Idle", "state": "inactive", "alerts": []},
                    ]
                }
            ]
        }
    }
    monkeypatch.setattr(app_module, "bounded_get", lambda url: rules_payload)
    aggregator = Aggregator("/tmp/alerts", "/tmp/staging")
    accepted = poll_firing_alerts("http://grafana:3000", aggregator)
    assert accepted == 1
    incidents = aggregator.incidents()
    assert incidents[0]["service"] == "demo-api"
