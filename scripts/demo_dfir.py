#!/usr/bin/env python3
"""Run the DFIR demo: Velociraptor evidence -> ZAYNOR deterministic pipeline.

Two modes:

- ``mock``: replay the byte-stable capture in
  ``scenarios/inc-2026-demo-001/velociraptor/captured-collection.json``
  through ``tools.velociraptor.adapter.MockTransport``. No collector needed;
  the demo verdict is reproducible without any infrastructure.
- ``live``: collect the demo hunt records from a running Velociraptor
  server. Primary transport is ``tools.velociraptor.adapter.RestTransport``
  (basic auth against the GUI API proxy; pass ``--insecure`` for the lab's
  self-signed certificate). When the GUI proxy rejects scripted POSTs for
  lack of a CSRF token (behavior of some 0.7x builds), the lab falls back
  to ``--vr-container``/``--api-config``: records are captured through the
  Velociraptor API client inside the lab container and fed through the
  identical normalization seam with ``transport="rest"``.

Both modes run the identical seam afterwards:

1. normalize rows and seal the evidence window (``window_hash``, manifest,
   custody roles) on the collector side;
2. freeze the case through the existing ZAYNOR freezer;
3. run ``zaynor analyze`` (vendored VIGIA deterministic engine);
4. run ``zaynor audit`` and print the sealed report.

Authority boundary: agents only EXPLAIN. MENTOR, INVESTIGATOR,
DETECTION_ENGINEER and FLEET_COMMANDER may read the sealed case, explain
what it supports, link every claim to evidence rows and manifests, and
describe alternative hypotheses and unknowns. They never change the
verdict and never execute shell, arbitrary network, or filesystem writes.

Usage:
    python3 scripts/demo_dfir.py --mode mock
    python3 scripts/demo_dfir.py --mode live --base-url http://127.0.0.1:8889 \
        --username admin --password '...' [--insecure]
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT))

from tools.velociraptor import mappings, vql_templates  # noqa: E402
from tools.velociraptor.adapter import (  # noqa: E402
    MockTransport,
    RestTransport,
    VelociraptorAdapter,
    VelociraptorAdapterError,
)

SCENARIO_ROOT = REPO_ROOT / "scenarios" / "inc-2026-demo-001"
CAPTURE = SCENARIO_ROOT / "velociraptor" / "captured-collection.json"
def default_case_id() -> str:
    """One case per demo run: freezing twice into the same case would
    collide with the read-only frozen evidence (by design)."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M")
    return f"INC-2026-DEMO-001-VR-{stamp}"
KNOWN_DEVICES = ["DEV-CORP-01", "DEV-CORP-02", "DEV-CORP-LAPTOP-09"]


def collect_from_mock() -> list[tuple[str, list[dict[str, Any]]]]:
    """Replay the checked-in capture through the same transport boundary."""
    capture = json.loads(CAPTURE.read_text(encoding="utf-8"))
    mock = MockTransport(capture)
    artifacts = []
    for spec in vql_templates.CATALOG:
        rows = list(mock.rows_for_artifact(spec.artifact_id))
        if rows:
            artifacts.append((spec.artifact_id, rows))
    return artifacts


def collect_from_live(base_url: str, username: str, password: str, insecure: bool) -> list[tuple[str, list[dict[str, Any]]]]:
    """Pull each catalog artifact from the live Velociraptor API proxy."""
    context = None
    if insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    transport = RestTransport(base_url, username, password, ssl_context=context)
    artifacts = []
    for spec in vql_templates.CATALOG:
        records = list(transport.query(spec.vql))
        if records:
            artifacts.append((spec.artifact_id, records))
    return artifacts


def run_pipeline(case_id: str, artifacts: list[tuple[str, Any]], transport_name: str) -> dict[str, Any]:
    """Normalize -> seal -> freeze -> analyze -> audit, then report."""
    adapter = VelociraptorAdapter(builder="zaynor-dfir-demo", source="velociraptor")
    window = adapter.collect(case_id, artifacts, transport=transport_name)

    workdir = REPO_ROOT / "results" / "dfir-demo"
    workdir.mkdir(parents=True, exist_ok=True)
    manifest, _evidence_dir, corpus = mappings.stage_and_freeze(
        window,
        workdir / "stage",
        workdir / "cases",
        known_devices=set(KNOWN_DEVICES),
    )

    from zaynor.cli import main as zaynor_main

    cases_root = workdir / "cases"
    output_root = workdir / "output"
    rc = zaynor_main(
        ["analyze", "--case-id", case_id, "--cases-root", str(cases_root),
         "--output-root", str(output_root), "--json"]
    )
    if rc != 0:
        return {"error": "zaynor analyze failed", "rc": rc}
    result = json.loads((output_root / case_id / "result.json").read_text())

    rc_audit = zaynor_main(
        ["audit", "--case-id", case_id, "--cases-root", str(cases_root),
         "--output-root", str(output_root), "--json"]
    )

    return {
        "case_id": case_id,
        "transport": transport_name,
        "window_hash": window["window_hash"],
        "frozen_entries": len(manifest.entries),
        "mapped_artifacts": len(corpus["artifacts"]),
        "verdict": result["verdict"],
        "engine": result["engine"],
        "findings": [dict(f) for f in result["findings"]],
        "unknowns": list(result["unknowns"]),
        "audit_rc": rc_audit,
    }


def collect_from_container(container: str) -> list[tuple[str, list[dict[str, Any]]]]:
    """Capture live records via the Velociraptor API client inside the lab
    container (fallback transport for GUI proxies that require CSRF).

    Runs the catalog's read-only VQL with the API config minted in the
    container (`/tmp/api.config.yaml`), parses the JSON-array output, and
    returns (artifact_id, rows) pairs — the same shape `RestTransport`
    produces, so both live paths share the normalization seam.
    """
    artifacts = []
    for spec in vql_templates.CATALOG:
        vql = spec.vql
        result = subprocess.run(
            ["docker", "exec", container, "/velociraptor/velociraptor",
             "--config", "server.config.yaml", "-a", "/tmp/api.config.yaml",
             "query", vql],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            raise VelociraptorAdapterError(
                f"container query failed for {spec.artifact_id}: {result.stderr[:200]}"
            )
        try:
            records = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise VelociraptorAdapterError(f"unparseable container output for {spec.artifact_id}: {exc}") from exc
        if isinstance(records, list) and records:
            artifacts.append((spec.artifact_id, records))
    return artifacts


def agent_view(case_id: str, output_root: Path) -> dict[str, Any]:
    """Read-only agent view: the sealed package ZAYNOR's agents (MENTOR,
    INVESTIGATOR, DETECTION_ENGINEER, FLEET_COMMANDER) are allowed to see.
    Never re-invokes the engine and never grants tool execution rights.
    `zaynor consult` is called with --json; narration (`zaynor chat`) is
    only attempted when OLLAMA_HOST answers, and its output can never
    change the sealed result.
    """
    from zaynor.cli import main as zaynor_main

    consult_rc = zaynor_main(
        ["consult", "--case-id", case_id, "--output-root", str(output_root), "--json"]
    )
    view = {"consult_rc": consult_rc}
    return view


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--mode", choices=["mock", "live"], default="mock")
    parser.add_argument("--vr-container", default="velociraptor-lab",
                        help="lab container running the Velociraptor server+client (live fallback transport)")
    parser.add_argument("--base-url", default="http://127.0.0.1:8889")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default=None)
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args(argv)

    if args.mode == "live" and not args.password:
        # Without credentials the lab captures records through the
        # Velociraptor API client inside the lab container (fallback).
        artifacts = collect_from_container(args.vr_container)
    elif args.mode == "live":
        artifacts = collect_from_live(args.base_url, args.username, args.password, args.insecure)
    else:
        artifacts = collect_from_mock()
    transport = "mock" if args.mode == "mock" else "rest"
    case_id = default_case_id()
    report = run_pipeline(case_id, artifacts, transport)
    report["agent_view"] = agent_view(case_id, REPO_ROOT / "results" / "dfir-demo" / "output")
    print(json.dumps(report, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
