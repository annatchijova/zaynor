#!/usr/bin/env python3
"""Generate the synthetic AIOps demo scenario (deterministic).

Writes `scenarios/inc-2026-aiops-001/`:

- `alerts/high-error-rate.json` — alert cluster for an error burst;
- `alerts/high-latency.json` — alert for a latency spike;
- `window/metrics.jsonl` — bounded metric samples for the window;
- `window/logs.jsonl` — structured service logs for the window.

The story mirrors the DFIR fixture's incident window (the same night):
the demo batch service degrades, Grafana fires two rules, and the
incident aggregator packages a bounded telemetry window for ZAYNOR.
Everything is synthetic; no real system produces these signals.

Usage:
    python3 scripts/generate_aiops_scenario.py
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_ROOT = REPO_ROOT / "scenarios" / "inc-2026-aiops-001"
SERVICE = "demo-api"


def iso_for(minute: int) -> str:
    return (datetime(2026, 9, 17, 2, 0, 0, tzinfo=timezone.utc) + timedelta(minutes=minute)).isoformat()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.parse_args(argv)

    alerts_dir = SCENARIO_ROOT / "alerts"
    alerts_dir.mkdir(parents=True, exist_ok=True)
    (alerts_dir / "high-error-rate.json").write_text(
        json.dumps(
            {
                "alerts": [
                    {
                        "labels": {
                            "alertname": "HighErrorRate",
                            "service": "demo-api",
                            "environment": "lab",
                        },
                        "startsAt": iso_for(4),
                        "annotations": {
                            "summary": "demo-api error ratio above 5% (synthetic fault injection)"
                        },
                    }
                ]
            },
            indent=1,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (alerts_dir / "high-latency.json").write_text(
        json.dumps(
            {
                "alerts": [
                    {
                        "labels": {
                            "alertname": "HighLatency",
                            "service": "demo-api",
                            "environment": "lab",
                        },
                        "startsAt": iso_for(4),
                        "annotations": {
                            "summary": "demo-api p95 latency above 300ms (synthetic fault injection)"
                        },
                    }
                ]
            },
            indent=1,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    out = SCENARIO_ROOT / "window" / "metrics.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    records = []
    for minute in range(6):
        ratio = 0.001 if minute < 3 else (0.42 if minute == 4 else 0.12)
        latency_ms = 42.0 if minute < 3 else (880.0 if minute == 4 else 210.0)
        requests = 120 - minute * 8
        for metric, value in (
            ("demo_error_ratio", ratio),
            ("demo_request_latency_ms", latency_ms),
            ("demo_requests_total", float(requests)),
        ):
            records.append(
                json.dumps(
                    {"metric": metric, "service": "demo-api", "value": value, "timestamp": iso_for(minute)},
                    sort_keys=True,
                )
            )
    out.write_text("\n".join(records) + "\n", encoding="utf-8")

    logs_path = SCENARIO_ROOT / "window" / "logs.jsonl"
    log_records = [
        {"level": "info", "event": "service_started", "message": "synthetic demo service started"},
        {"level": "info", "event": "work_ok", "message": "batch 0 completed"},
        {"level": "error", "event": "work_failed", "message": "synthetic dependency failure"},
        {"level": "warning", "event": "work_slow", "message": "work unit took 880ms"},
        {"level": "info", "event": "fault_injected", "message": "fault_mode=errors duration_seconds=180"},
        {"level": "warning", "event": "fault_injected", "message": "fault_mode=latency duration_seconds=30"},
    ]
    with logs_path.open("w", encoding="utf-8") as handle:
        for index, record in enumerate(log_records):
            record["service"] = "demo-api"
            record["timestamp"] = iso_for(min(5, index))
            handle.write(json.dumps(record, sort_keys=True) + "\n")

    print(f"scenario generated at {SCENARIO_ROOT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
