#!/usr/bin/env python3
"""Run the AIOps demo: synthetic telemetry -> alert cluster -> ZAYNOR.

Two modes:

- ``file`` (default): read synthetic alert JSON files from
  ``--alerts-dir``, correlate them into incident candidates with the
  incident aggregator, collect the bounded telemetry window from files,
  and stage the evidence bundle for ZAYNOR. No infrastructure needed.
- ``bundle``: run the ZAYNOR pipeline on a bundle directory already
  staged by the live aggregator (see docs/demo-lab/README.md for the
  live compose flow: fault injection -> Grafana alerts -> aggregator ->
  staged bundle).

The seam both modes share:

1. normalize alert/telemetry records and seal the evidence window
   (``window_hash``, manifest, custody roles);
2. freeze the case through the existing ZAYNOR freezer;
3. run ``zaynor analyze`` (vendored VIGIA deterministic engine);
4. run ``zaynor audit`` and print the sealed report.

Authority boundary: identical to the DFIR path — agents only investigate
and explain; the deterministic engine owns every verdict.

Usage:
    python3 scripts/demo_aiops.py --mode file --alerts-dir scenarios/inc-2026-aiops-001/alerts
    python3 scripts/demo_aiops.py --mode bundle --bundle-dir results/aiops-demo/live/<INCIDENT_ID>
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT))

from tools.aiops.aggregator.app import (  # noqa: E402
    Aggregator,
    load_alert_files,
    stage_all_incidents,
)


def run_pipeline(case_id: str, staging_dir: Path, cases_root: Path, output_root: Path) -> dict[str, Any]:
    """Freeze -> analyze -> audit on an already-staged evidence bundle."""
    from zaynor.case_freezer import freeze_case
    from zaynor.cli import main as zaynor_main

    profile_map = {"aiops-evidence": ["aiops/evidence.json"]}
    manifest, _evidence_dir = freeze_case(
        case_id, "aiops-evidence", profile_map, Path(staging_dir), Path(cases_root)
    )
    rc = zaynor_main(
        ["analyze", "--case-id", case_id, "--cases-root", str(cases_root),
         "--output-root", str(output_root), "--json"]
    )
    if rc != 0:
        return {"error": "zaynor analyze failed", "rc": rc}
    result = json.loads((Path(output_root) / case_id / "result.json").read_text())
    rc_audit = zaynor_main(
        ["audit", "--case-id", case_id, "--cases-root", str(cases_root),
         "--output-root", str(output_root), "--json"]
    )
    return {
        "case_id": case_id,
        "verdict": result["verdict"],
        "engine": result["engine"],
        "findings": [dict(f) for f in result["findings"]],
        "unknowns": list(result["unknowns"]),
        "audit_rc": rc_audit,
    }


def agent_view(case_id: str, output_root: Path) -> dict[str, Any]:
    """Read-only agent view of the sealed case (see demo_dfir.agent_view)."""
    from zaynor.cli import main as zaynor_main

    consult_rc = zaynor_main(
        ["consult", "--case-id", case_id, "--output-root", str(output_root), "--json"]
    )
    return {"consult_rc": consult_rc}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--mode", choices=["file", "bundle"], default="file",
                        help="file: synthetic alerts; bundle: stage from an already-collected bundle path (--bundle-dir)")
    parser.add_argument("--alerts-dir", type=Path,
                        default=REPO_ROOT / "scenarios" / "inc-2026-aiops-001" / "alerts")
    parser.add_argument("--staging-dir", type=Path,
                        default=REPO_ROOT / "results" / "aiops-demo")
    parser.add_argument("--bundle-dir", type=Path, default=None,
                        help="bundle directory (aiops/evidence.json) staged by the live aggregator")
    args = parser.parse_args(argv)
    args.window_dir = REPO_ROOT / "scenarios" / "inc-2026-aiops-001" / "window"

    if args.mode == "bundle":
        bundle = args.bundle_dir
        if bundle is None or not (bundle / "aiops" / "evidence.json").exists():
            print("--mode bundle requires --bundle-dir with aiops/evidence.json", file=sys.stderr)
            return 1
        case_id = json.loads((bundle / "aiops" / "evidence.json").read_text())["case_id"]
    else:
        aggregator = Aggregator(args.alerts_dir, args.staging_dir / "staging")
        for alert in load_alert_files(args.alerts_dir):
            aggregator.ingest_alert(alert)
        incidents = aggregator.incidents()
        if not incidents:
            print("no incident candidates found in alert files", file=sys.stderr)
            return 1
        case_id = incidents[0]["incident_id"]
        stage_all_incidents(aggregator, args.alerts_dir, args.staging_dir / "staging", window_dir=args.window_dir)
        bundle = args.staging_dir / "staging" / case_id

    report = run_pipeline(case_id, bundle, args.staging_dir / "cases", args.staging_dir / "output")
    report["agent_view"] = agent_view(case_id, args.staging_dir / "output")
    print(json.dumps(report, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
