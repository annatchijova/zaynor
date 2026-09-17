"""Tests for the AIOps incident aggregator."""

import json
from datetime import datetime, timedelta, timezone

from tools.aiops.aggregator.app import (
    Aggregator,
    alerts_from_payload,
    deterministic_incident_id,
    poll_firing_alerts,
    stage_all_incidents,
    stage_incident_bundle,
    window_hash,
)
from tools.aiops.aggregator.evidence import EVIDENCE_PROFILES, map_window_to_corpus
from zaynor.hybrid_integrations import verify_annaconda_window


def _alert(name="HighErrorRate", service="demo-api", minute=0, second=0, environment="lab"):
    base = datetime(2026, 9, 17, 2, 0, second, tzinfo=timezone.utc)
    return {
        "alertname": name,
        "service": service,
        "environment": environment,
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


def test_cross_environment_alerts_stay_separate():
    """Correlation is by (service, environment): the same service firing in
    two environments is two incident domains, never one merged candidate."""
    aggregator = Aggregator("/tmp/alerts", "/tmp/staging")
    prod_id = aggregator.ingest_alert(_alert(minute=0, environment="prod"))
    staging_id = aggregator.ingest_alert(_alert(minute=0, environment="staging"))
    incidents = aggregator.incidents()
    assert len(incidents) == 2
    assert prod_id != staging_id
    environments = {incident["environment"] for incident in incidents}
    assert environments == {"prod", "staging"}
    for incident in incidents:
        assert incident["service"] == "demo-api"
        assert len(incident["alerts"]) == 1


def test_offline_bundles_scope_records_to_their_incident(tmp_path):
    """Offline/file mode must scope each bundle to its incident's service
    and time span: two incidents for two services, one shared window
    directory — each bundle carries only its own evidence, and records
    far outside the incident span are excluded even for the right
    service."""
    aggregator = Aggregator("/tmp/alerts", tmp_path)
    aggregator.ingest_alert(_alert(minute=0))
    aggregator.ingest_alert(_alert(service="batch-api", minute=0))

    window_dir = tmp_path / "window"
    window_dir.mkdir(parents=True)
    in_span = "2026-09-17T02:00:30+00:00"
    far_out = "2026-09-17T05:00:30+00:00"
    records = [
        {"metric": "demo_error_ratio", "service": "demo-api", "value": 0.42, "timestamp": in_span},
        {"level": "error", "event": "work_failed", "service": "demo-api", "message": "boom", "timestamp": in_span},
        {"metric": "batch_error_ratio", "service": "batch-api", "value": 0.30, "timestamp": in_span},
        {"level": "error", "event": "work_failed", "service": "batch-api", "message": "boom", "timestamp": in_span},
        # Right service, far outside the incident span: excluded by the
        # time filter (span + correlation margin).
        {"metric": "demo_error_ratio", "service": "demo-api", "value": 0.99, "timestamp": far_out},
    ]
    for name, subset in (("metrics.jsonl", [records[0], records[2], records[4]]),
                         ("logs.jsonl", [records[1], records[3]])):
        (window_dir / name).write_text(
            "\n".join(json.dumps(record, sort_keys=True) for record in subset) + "\n",
            encoding="utf-8",
        )

    staged = stage_all_incidents(aggregator, tmp_path, tmp_path / "staging", window_dir=window_dir)
    assert len(staged) == 2
    by_service = {}
    for bundle in staged:
        corpus = json.loads(bundle.read_text())
        by_service[corpus["evidence_window"]["incident"]["service"]] = corpus
    demo_corpus = by_service["demo-api"]
    batch_corpus = by_service["batch-api"]

    # Every bundle carries only its own incident's evidence: window rows
    # (raw observations) and mapped artifacts (VIGÍA ingestion form) both.
    for corpus, own, other in (
        (demo_corpus, "demo-api", "batch-api"),
        (batch_corpus, "batch-api", "demo-api"),
    ):
        window_services = {
            record.get("service")
            for artifact in corpus["evidence_window"]["artifacts"]
            for record in artifact["rows"]
        }
        # Alert rows carry no service field (the service is the incident's);
        # telemetry rows all belong to the incident's own service.
        window_services.discard(None)
        assert window_services == {own}
        assert other not in json.dumps(corpus)
    # The far-out record for demo-api never reaches any bundle.
    assert "0.99" not in json.dumps(demo_corpus)
    assert "0.99" not in json.dumps(batch_corpus)


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



def test_aiops_calibration_pins_the_sealed_verdict(tmp_path):
    """Regression fixture for ADR 0003: the static calibration in
    EVIDENCE_PROFILES is verdict-affecting, so a representative incident
    run through the real pipeline (stage -> freeze -> zaynor analyze ->
    seal) must keep producing this exact authoritative verdict. A change
    to the constants that moves the verdict fails here and must be
    re-reviewed. The scorer itself is untouched."""
    from zaynor.cli import main as zaynor_main
    from zaynor.case_freezer import freeze_case

    aggregator = Aggregator("/tmp/alerts", tmp_path)
    aggregator.ingest_alert(_alert(minute=0))
    aggregator.ingest_alert(_alert(name="HighLatency", minute=0, second=20))
    incident = aggregator.incidents()[0]

    samples = [
        {"evidence_type": "metric_sample", "metric": "demo_error_ratio",
         "service": "demo-api", "value": 0.85, "timestamp": "2026-09-17T02:00:05+00:00"},
        {"evidence_type": "metric_sample", "metric": "demo_request_latency_ms",
         "service": "demo-api", "value": 880.0, "timestamp": "2026-09-17T02:00:06+00:00"},
    ]
    logs = [
        {"evidence_type": "log_line", "service": "demo-api", "level": "error",
         "event": "work_failed", "message": "synthetic dependency failure",
         "timestamp": "2026-09-17T02:00:07+00:00"},
    ]
    evidence_path = stage_incident_bundle(
        incident, samples, logs, tmp_path / "staging" / incident["incident_id"]
    )
    corpus = json.loads(evidence_path.read_text())
    # Traceability: every mapped artifact carries the static constants of
    # its authoring rule, unchanged.
    rule_scores = {rule.rule_id: rule.raw_score for rule in EVIDENCE_PROFILES}
    for artifact in corpus["artifacts"]:
        for rule_id, score in rule_scores.items():
            if artifact["artifact_id"].startswith(f"aiops-{rule_id}-"):
                assert artifact["raw_score"] == score

    freeze_case(incident["incident_id"], "aiops-evidence",
                {"aiops-evidence": ["aiops/evidence.json"]},
                tmp_path / "staging" / incident["incident_id"], tmp_path / "cases")
    rc = zaynor_main(
        ["analyze", "--case-id", incident["incident_id"],
         "--cases-root", str(tmp_path / "cases"),
         "--output-root", str(tmp_path / "output"), "--json"]
    )
    assert rc == 0
    result = json.loads((tmp_path / "output" / incident["incident_id"] / "result.json").read_text())
    assert result["verdict"] == "SUSPICION"
    assert result["integrity"]["vigia_agent_verdict"] == "SUSPICION"
    assert result["unknowns"] == []
    assert (tmp_path / "output" / incident["incident_id"] / "result.seal.json").exists()


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
