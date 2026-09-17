#!/usr/bin/env python3
"""Incident aggregator for the AIOps lab (stdlib only).

Turns alert clusters into ZAYNOR-ready AIOps evidence bundles.

Pipeline per alert cluster:

1. **Subscribe** — receive alerts over HTTP (``POST /webhook/grafana``,
   Grafana's contact-point payload) or from synthetic JSON files in
   ``--alerts-dir`` (offline mode).
2. **Correlate** — group alerts by (service, environment) inside a time
   window into incident candidates. Each candidate gets a deterministic
   ``incident_id`` (SHA-256 over service|environment|first-occurrence
   minute), so the same cluster maps to the same ZAYNOR case on re-runs.
3. **Collect** — for each candidate, fetch a bounded telemetry window:
   metrics via Prometheus ``/api/v1/query_range`` and logs via Loki
   ``/loki/api/v1/query_range``, both with hard caps (max points, max
   lines, max bytes, wall-clock timeout). With ``--window-file``, read the
   telemetry window from files instead of live backends (offline mode).
4. **Stage** — normalize records (stable columns, ISO-8601 UTC) and write
   the evidence bundle for ZAYNOR's freezer:

       aiops/window.json        sealed window (window_hash inside)
       aiops/evidence.json      per-incident normalized records

   ``aiops/evidence.json`` is a single rich-case JSON the vendored engine
   ingests; ``window.json`` carries the raw observation envelope.

Authority boundary: the aggregator TRANSFORMS alerts/telemetry into
evidence (observations + provenance only). It never scores, never labels,
never decides. VIGIA, behind ``zaynor analyze``, assigns the only
authoritative claim states.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ALERTS_DIR = Path("/var/lib/zaynor-aiops/alerts")
BUNDLES_DIR = Path("/var/lib/zaynor-aiops/staging")
CORRELATION_WINDOW_SECONDS = 120
CANDIDATE_TTL_SECONDS = 3600
MAX_LINES = 500
MAX_POINTS = 300
MAX_BYTES = 2_000_000
REQUEST_TIMEOUT_SECONDS = 30


class Aggregator:
    def __init__(self, alerts_dir: Path, staging_dir: Path, *, window_seconds: int = CORRELATION_WINDOW_SECONDS):
        self._alerts_dir = alerts_dir
        self._staging_dir = staging_dir
        self._window_seconds = window_seconds
        self._lock = threading.Lock()
        self._incidents: dict[str, dict[str, Any]] = {}
        self._seen_alerts: dict[str, set[str]] = {}
        # Correlation index is keyed by (service, environment): the same
        # service in two environments is two independent incident domains.
        self._by_service_env: dict[tuple[str, str], list[str]] = {}

    def ingest_alert(self, alert: dict[str, Any]) -> str | None:
        """Correlate one alert into an incident candidate. Returns the
        candidate's incident_id, or None if the alert lacks required fields."""
        labels = alert.get("labels") or {}
        service = alert.get("service") or labels.get("service")
        environment = alert.get("environment") or labels.get("environment", "lab")
        alert_name = alert.get("alertname") or labels.get("alertname")
        if not service or not alert_name:
            return None
        started_at = parse_timestamp(alert.get("timestamp") or alert.get("startsAt")) or datetime.now(timezone.utc)
        with self._lock:
            self._evict_stale()
            incident_id = self._match_or_create(service, environment, started_at, alert_name)
        return incident_id

    def _evict_stale(self) -> None:
        """Bound the registry: candidates not updated for
        CANDIDATE_TTL_SECONDS relative to the newest observed activity are
        evicted, so a long-running aggregator does not accumulate state
        forever without rejecting legitimately backfilled alerts."""
        if not self._incidents:
            return
        newest = max(
            (parse_timestamp(incident["last_seen"]) for incident in self._incidents.values()),
            default=None,
        )
        if newest is None:
            return
        cutoff = newest - timedelta(seconds=CANDIDATE_TTL_SECONDS)
        stale = []
        for incident_id, incident in self._incidents.items():
            last = parse_timestamp(incident["last_seen"])
            if last is not None and last < cutoff:
                stale.append(incident_id)
        for incident_id in stale:
            self._incidents.pop(incident_id, None)
            self._seen_alerts.pop(incident_id, None)
            for ids in self._by_service_env.values():
                if incident_id in ids:
                    ids.remove(incident_id)

    def _match_or_create(self, service: str, environment: str, started_at: datetime, alert_name: str) -> str:
        """Correlate by (service, environment) inside the time window: an
        alert joins an existing candidate when it falls within
        window_seconds of that candidate's span; otherwise a new
        candidate opens with a deterministic id. The same service in two
        environments never shares a candidate."""
        for incident_id in self._by_service_env.get((service, environment), ()):
            incident = self._incidents.get(incident_id)
            if incident is None:
                continue
            first = parse_timestamp(incident["first_seen"])
            last = parse_timestamp(incident["last_seen"])
            if first is None or last is None:
                continue
            if first - timedelta(seconds=self._window_seconds) <= started_at <= last + timedelta(seconds=self._window_seconds):
                incident["last_seen"] = max(incident["last_seen"], started_at.isoformat())
                incident["first_seen"] = min(incident["first_seen"], started_at.isoformat())
                # Dedupe: a continuously-firing alert re-observed by the
                # poller extends the window but records once. The same
                # alertname with a NEW timestamp is still the same signal.
                seen = self._seen_alerts.setdefault(incident_id, set())
                if alert_name not in seen:
                    seen.add(alert_name)
                    incident["alerts"].append(
                        {"alertname": alert_name, "timestamp": started_at.isoformat(), "labels": {}}
                    )
                return incident_id
        incident_id = deterministic_incident_id(service, environment, started_at)
        self._incidents[incident_id] = {
            "incident_id": incident_id,
            "service": service,
            "environment": environment,
            "first_seen": started_at.isoformat(),
            "last_seen": started_at.isoformat(),
            "alerts": [
                {"alertname": alert_name, "timestamp": started_at.isoformat(), "labels": {}}
            ],
        }
        self._seen_alerts.setdefault(incident_id, set()).add(alert_name)
        self._by_service_env.setdefault((service, environment), []).append(incident_id)
        return incident_id

    def incidents(self) -> list[dict[str, Any]]:
        with self._lock:
            return [json.loads(json.dumps(incident)) for incident in self._incidents.values()]


def deterministic_incident_id(service: str, environment: str, started_at: datetime) -> str:
    """SHA-256 over service|environment|first-occurrence minute, so the same
    alert cluster maps to the same ZAYNOR case on re-runs."""
    minute = started_at.astimezone(timezone.utc).replace(second=0, microsecond=0)
    key = f"{service}|{environment}|{minute.isoformat()}"
    return "INC-AIOPS-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


def parse_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def window_hash(window: dict[str, Any]) -> str:
    """Canonical SHA-256 window seal, in byte-for-byte lockstep with the
    DFIR path and `zaynor.hybrid_integrations.verify_annaconda_window()`
    (same `_canonicalize` + canonical JSON + SHA-256 derivation)."""
    from vendor.vigia_engine.vigia.core.canonicalize import _canonicalize

    body = {key: value for key, value in window.items() if key != "window_hash"}
    return hashlib.sha256(
        json.dumps(_canonicalize(body), sort_keys=True, ensure_ascii=True).encode()
    ).hexdigest()


def collect_prometheus_window(prometheus_url: str, service: str, start: datetime, end: datetime) -> list[dict[str, Any]]:
    """Bounded metrics window for one service from Prometheus query_range.

    The query range is the incident span plus the correlation margin —
    the same intentional margin policy the offline path applies — so the
    live window honors the incident end boundary instead of a fixed span
    from the start.
    """
    margin = timedelta(seconds=CORRELATION_WINDOW_SECONDS)
    queries = [
        'sum(rate(demo_requests_total{job="%s"}[1m]))' % service,
        'sum(rate(demo_errors_total{job="%s"}[1m]))' % service,
        'histogram_quantile(0.95, sum(rate(demo_request_latency_ms_bucket{job="%s"}[5m])) by (le))' % service,
    ]
    records = []
    for query in queries:
        params = urllib.parse.urlencode(
            {
                "query": query,
                "start": (start - margin).isoformat(),
                "end": (end + margin).isoformat(),
                "step": "10s",
            }
        )
        body = bounded_get(f"{prometheus_url.rstrip('/')}/api/v1/query_range?{params}")
        if body is None:
            continue
        result = body.get("data", {}).get("result", [])
        for series in series_from_prometheus(result):
            records.append(series)
    return records


def bounded_get(url: str) -> dict[str, Any] | None:
    """GET with byte and time bounds; returns parsed JSON or None."""
    try:
        with urllib.request.urlopen(url, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            payload = response.read(MAX_BYTES + 1)
    except (urllib.error.URLError, OSError, TimeoutError):
        return None
    if len(payload) > MAX_BYTES:
        return None
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def series_from_prometheus(result: list) -> list[dict[str, Any]]:
    """Flatten Prometheus matrix result into normalized sample records."""
    records = []
    for series in result:
        metric = series.get("metric", {})
        values = series.get("values", [])[:MAX_POINTS]
        for timestamp, sample in values:
            records.append(
                {
                    "evidence_type": "metric_sample",
                    "metric": str(metric.get("__name__", "unknown")),
                    "service": str(metric.get("service", "")),
                    "value": coerce_number(sample),
                    "timestamp": float_to_iso(float(timestamp)),
                }
            )
    return records


def float_to_iso(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()


def coerce_number(value: Any) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return 0.0
    return 0.0 if parsed != parsed else parsed  # NaN shield


def collect_loki_window(loki_url: str, service: str, start: datetime, end: datetime) -> list[dict[str, Any]]:
    """Bounded log window for one service from Loki query_range.

    The query range is the incident span plus the correlation margin —
    the same intentional margin policy the offline path and the metrics
    collector apply.
    """
    margin = timedelta(seconds=CORRELATION_WINDOW_SECONDS)
    params = urllib.parse.urlencode(
        {
            "query": '{job="%s"}' % service,
            "start": str(int((start - margin).timestamp() * 1e9)),
            "end": str(int((end + margin).timestamp() * 1e9)),
            "limit": MAX_LINES,
            "direction": "forward",
        }
    )
    body = bounded_get(f"{loki_url.rstrip('/')}/loki/api/v1/query_range?{params}")
    if body is None:
        return []
    records = []
    for stream in body.get("data", {}).get("result", []):
        labels = stream.get("stream", {})
        for entry in stream.get("values", [])[:MAX_LINES]:
            ts_ns, line = entry[0], entry[1]
            records.append(
                {
                    "evidence_type": "log_line",
                    "service": str(labels.get("service", "")),
                    "level": str(labels.get("level", "")),
                    "message": line[:500],
                    "timestamp": ns_to_iso(int(ts_ns)),
                }
            )
    return records


def ns_to_iso(nanoseconds: int) -> str:
    return datetime.fromtimestamp(nanoseconds / 1e9, tz=timezone.utc).isoformat()


def stage_incident_bundle(incident: dict[str, Any], samples: list[dict[str, Any]], logs: list[dict[str, Any]], staging_dir: Path) -> Path:
    """Write one hash-sealed, ZAYNOR-freezeable bundle for an incident.

    Fails closed like the DFIR path: the sealed window is re-verified
    through the canonical boundary before a single byte is written.
    """
    window = {
        "schema_version": 1,
        "window_id": incident["incident_id"] + "-w000001",
        "case_id": incident["incident_id"],
        "incident": {
            "service": incident["service"],
            "environment": os.environ.get("ZAYNOR_DEMO_ENV", "lab"),
            "first_seen": incident["first_seen"],
            "last_seen": incident["last_seen"],
            "alert_count": len(incident["alerts"]),
        },
        "custody": {
            "builder": "aiops-incident-aggregator",
            "custodian": "zaynor-aiops-staging",
            "collected_at": datetime.now(timezone.utc).isoformat(),
        },
        "artifacts": [
            {
                "artifact_id": "alerts",
                "evidence_type": "log_entry",
                "row_count": len(incident["alerts"]),
                "lineage_id": "grafana-alertmanager",
                "rows": incident["alerts"],
            },
            {
                "artifact_id": "metrics",
                "evidence_type": "metric_sample",
                "row_count": len(samples),
                "lineage_id": "prometheus",
                "rows": samples,
            },
            {
                "artifact_id": "logs",
                "evidence_type": "log_line",
                "row_count": len(logs),
                "lineage_id": "loki",
                "rows": logs,
            },
        ],
    }
    window["window_hash"] = window_hash(window)
    from zaynor.hybrid_integrations import verify_annaconda_window

    verify_annaconda_window(window)
    staging_dir.mkdir(parents=True, exist_ok=True)
    window_path = staging_dir / "aiops" / "window.json"
    evidence_path = staging_dir / "aiops" / "evidence.json"
    window_path.parent.mkdir(parents=True, exist_ok=True)
    window_path.write_text(json.dumps(window, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    # evidence.json: the single rich-case JSON for VIGIA ingestion, derived
    # deterministically from the sealed window's observations.
    evidence = build_case_corpus(window)
    evidence_path.write_text(json.dumps(evidence, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return evidence_path


def build_case_corpus(window: dict[str, Any]) -> dict[str, Any]:
    """Map a sealed AIOps window to VIGIA case-corpus artifacts."""
    from tools.aiops.aggregator.evidence import map_window_to_corpus
    return map_window_to_corpus(window)


def make_handler(aggregator: Aggregator, staging_dir: Path):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            pass

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/webhook/grafana":
                self._json(404, {"error": "unknown endpoint"})
                return
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length <= 0 or length > MAX_BYTES:
                self._json(400, {"error": "bad payload size"})
                return
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._json(400, {"error": "unparseable payload"})
                return
            accepted = 0
            for alert in alerts_from_payload(payload):
                if aggregator.ingest_alert(alert) is not None:
                    accepted += 1
            self._json(200, {"accepted": accepted})

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/incidents":
                self._json(200, {"incidents": self._incidents_list()})
                return
            self._json(404, {"error": "unknown endpoint"})

        def _incidents_list(self) -> list[dict[str, Any]]:
            return aggregator.incidents()

        def _json(self, code: int, body: dict[str, Any]) -> None:
            payload = json.dumps(body, sort_keys=True).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    return Handler


def alerts_from_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize Grafana contact-point / Alertmanager payloads to alerts."""
    alerts: list[dict[str, Any]] = []
    if "alerts" in payload and isinstance(payload["alerts"], list):
        for alert in payload["alerts"]:
            labels = alert.get("labels", {})
            alerts.append(
                {
                    "alertname": labels.get("alertname", payload.get("title", "")),
                    "service": labels.get("service", ""),
                    "environment": labels.get("environment", os.environ.get("ZAYNOR_DEMO_ENV", "lab")),
                    "timestamp": alert.get("startsAt") or payload.get("startsAt"),
                    "labels": labels,
                }
            )
    elif "labels" in payload:  # single alert, lab format
        labels = payload.get("labels", {})
        alerts.append(
            {
                "alertname": payload.get("alertname", labels.get("alertname", "")),
                "service": payload.get("service", labels.get("service", "")),
                "environment": payload.get("environment", labels.get("environment", os.environ.get("ZAYNOR_DEMO_ENV", "lab"))),
                "timestamp": payload.get("timestamp"),
                "labels": dict(labels),
            }
        )
    return alerts


def load_alert_files(alerts_dir: Path) -> list[dict[str, Any]]:
    """Read synthetic alert JSON files (offline mode), oldest first."""
    alerts = []
    for path in sorted(alerts_dir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict):
            alerts.extend(alerts_from_payload(payload))
    return alerts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--alerts-dir", type=Path, default=ALERTS_DIR)
    parser.add_argument("--staging-dir", type=Path, default=BUNDLES_DIR)
    parser.add_argument("--prometheus-url", default=os.environ.get("ZAYNOR_PROMETHEUS_URL", "http://prometheus:9090"))
    parser.add_argument("--loki-url", default=os.environ.get("ZAYNOR_LOKI_URL", "http://loki:3100"))
    parser.add_argument("--window-file", action="store_true", help="collect telemetry from files, not live backends")
    parser.add_argument("--window-dir", type=Path, default=None, help="default window directory (window/) when per-type dirs are not given")
    parser.add_argument("--grafana-url", default=os.environ.get("ZAYNOR_GRAFANA_URL", "http://grafana:3000"))
    parser.add_argument("--poll-interval", type=int, default=20, help="seconds between Grafana rules-API polls (server mode)")
    parser.add_argument("--collect", action="store_true", help="stage bundles for all current incidents and exit")
    args = parser.parse_args(argv)

    aggregator = Aggregator(args.alerts_dir, args.staging_dir)

    if args.collect:
        alerts = load_alert_files(args.alerts_dir)
        for alert in alerts:
            aggregator.ingest_alert(alert)
        if args.window_file:
            staged = stage_all_incidents(
                aggregator, args.alerts_dir, args.staging_dir, window_dir=args.window_dir
            )
        else:
            staged = stage_all_incidents(
                aggregator,
                args.alerts_dir,
                args.staging_dir,
                prometheus_url=args.prometheus_url,
                loki_url=args.loki_url,
            )
        print(json.dumps({"staged": [str(path) for path in staged]}, sort_keys=True))
        return 0

    def poll_loop() -> None:
        while True:
            try:
                accepted = poll_firing_alerts(args.grafana_url, aggregator)
                if accepted:
                    print(f"poll: {accepted} firing alerts ingested", flush=True)
            except Exception as exc:  # noqa: BLE001 - polling must never crash the server
                print(f"poll error: {exc}", flush=True)
            time.sleep(max(5, args.poll_interval))

    threading.Thread(target=poll_loop, daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", args.port), make_handler(aggregator, args.staging_dir))
    print(f"aggregator listening on :{args.port}", flush=True)
    server.serve_forever()
    return 0


def _record_in_window(record: dict[str, Any], service: str, start: datetime, end: datetime) -> bool:
    """Evidence-typing gate for offline bundles: keep only records for the
    incident's service whose timestamp falls inside the incident span plus
    the correlation tolerance (the same margin the correlation step uses,
    so an alert and its telemetry never split across bundles)."""
    if record.get("service") != service:
        return False
    ts = parse_timestamp(record.get("timestamp"))
    if ts is None:
        return False
    margin = timedelta(seconds=CORRELATION_WINDOW_SECONDS)
    return start - margin <= ts <= end + margin


def stage_all_incidents(
    aggregator: "Aggregator",
    alerts_dir: Path,
    staging_dir: Path,
    *,
    prometheus_url: str | None = None,
    loki_url: str | None = None,
    window_dir: Path | None = None,
) -> list[Path]:
    """Stage one evidence bundle per current incident.

    Live collection (prometheus_url/loki_url given) queries the backends;
    otherwise the telemetry window is read from files under `window_dir`
    (the scenario's window/ directory). In both modes the records are
    scoped to the incident's service and time span: a bundle carries only
    the evidence of the incident it belongs to. Returns the bundle paths.
    """
    staged = []
    for incident in aggregator.incidents():
        start = parse_timestamp(incident["first_seen"]) or datetime.now(timezone.utc)
        end = parse_timestamp(incident["last_seen"]) or start
        if prometheus_url and loki_url:
            samples = collect_prometheus_window(prometheus_url, incident["service"], start, end)
            logs = collect_loki_window(loki_url, incident["service"], start, end)
        else:
            base = window_dir or alerts_dir
            loaded_samples, loaded_logs = load_typed_window_records(base)
            samples = [
                record for record in loaded_samples
                if _record_in_window(record, incident["service"], start, end)
            ]
            logs = [
                record for record in loaded_logs
                if _record_in_window(record, incident["service"], start, end)
            ]
        bundle_path = stage_incident_bundle(incident, samples, logs, staging_dir / incident["incident_id"])
        staged.append(bundle_path)
    return staged


def infer_evidence_type(record: dict[str, Any]) -> str:
    """Derive the evidence type from the record itself, never from the
    caller's guess: metric samples carry (metric, value); log lines carry
    (level, event, message)."""
    if "metric" in record and "value" in record:
        return "metric_sample"
    return "log_line"


def load_window_records(directory: Path, evidence_type: str | None = None) -> list[dict[str, Any]]:
    """Read normalized window records from files (offline mode).

    Each record's `evidence_type` is inferred from the record content so a
    metrics line is never ingested as a log line (or vice versa) when both
    files share a directory. `evidence_type` remains as an explicit
    override for callers that already know the file type.
    """
    records = []
    if not directory.is_dir():
        return records
    for path in sorted(directory.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                stamp = evidence_type or infer_evidence_type(record)
                records.append({"evidence_type": stamp, **record})
    return records


def load_typed_window_records(directory: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Load the window directory once and split records by inferred type.

    Replaces the old double-glob (which ingested every file under both
    type stamps). Returns (metric_samples, log_lines).
    """
    all_records = load_window_records(directory)
    samples = [record for record in all_records if record["evidence_type"] == "metric_sample"]
    logs = [record for record in all_records if record["evidence_type"] == "log_line"]
    return samples, logs




def poll_firing_alerts(grafana_url: str, aggregator: Aggregator, timeout_seconds: int = REQUEST_TIMEOUT_SECONDS) -> int:
    """Poll Grafana's rules API and ingest currently-firing alerts.

    This is a pull ingestion path complementing the push webhook: it makes
    incident correlation robust to dispatcher/contact-point quirks while
    staying fully local and read-only. Returns the number of alerts
    accepted into candidates.
    """
    body = bounded_get(grafana_url.rstrip("/") + "/api/prometheus/grafana/api/v1/rules")
    if body is None:
        return 0
    accepted = 0
    for group in body.get("data", {}).get("groups", []):
        for rule in group.get("rules", []):
            state = rule.get("state")
            if state not in ("firing", "alerting"):
                continue
            for alert in rule.get("alerts", []):
                labels = alert.get("labels", {})
                alert_ingested = {
                    "alertname": labels.get("alertname", rule.get("name", "")),
                    "service": labels.get("service", ""),
                    "environment": labels.get("environment", os.environ.get("ZAYNOR_DEMO_ENV", "lab")),
                    "timestamp": alert.get("activeAt"),
                }
                if aggregator.ingest_alert(alert_ingested) is not None:
                    accepted += 1
    return accepted


if __name__ == "__main__":
    raise SystemExit(main())
