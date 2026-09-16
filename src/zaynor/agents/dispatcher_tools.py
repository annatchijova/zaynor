"""DISPATCHER role tool handler — a real hunt catalog, not a copy of
ANNACONDA's `agent/catalog.py`.

ANNACONDA's `catalog.py` catalogs *agents* (which department may task
which specialist, over what GCP-region-scoped data class) — enterprise
authorization machinery tied to its own Vertex AI/Firestore deployment,
not applicable here. What DISPATCHER's `list_hunts` actually needs is
much simpler and already has a working shape elsewhere in this package:
`consult_tools.ConsultTools.list_hunts`/`investigator_tools.py`'s reuse
of it both already return `{"hunts": [{"id", "description"}, ...]}` from
a plain `Mapping[str, str]`.

This module supplies that mapping's real content: the artifact-type
analyzers Mode 1 has actually been confirmed to reach (Phase 0 of this
project, and the real-forensic-image/EBS-JSON integration tests) — not a
list of live-EDR hunts ZAYNOR has no session/collection backend to run.
"""

from __future__ import annotations

from typing import Any

# Confirmed reachable from `vigia_agent.py`'s real Mode-1 path — see
# `zaynor_mode1_executor.py` and `tests/test_real_forensic_image_evidence.py`
# (registry/prefetch/browser/event-log, run against the 2019-OWL Digital
# Corpora image) and `tests/test_ebs_artifact_scorer.py` (EBS-JSON). Memory
# is confirmed reachable per red-team round 6, pending a real dump to
# exercise plugin output end-to-end (see that round's doc for the honest
# scope of "confirmed" there).
DEFAULT_HUNT_CATALOG: dict[str, str] = {
    "registry": "Windows registry hive analysis (SAM/SYSTEM/SOFTWARE/SECURITY/NTUSER.DAT) via VIGÍA's registry_timeline_reconstructor.",
    "prefetch": "Windows Prefetch execution-evidence analysis (.pf files) via VIGÍA's prefetch analyzer.",
    "browser": "Browser history/downloads analysis (Chromium History / Firefox places.sqlite) via VIGÍA's browser_forensics.",
    "event_log": "Windows Event Log analysis (.evtx) via VIGÍA's event_log_correlator, including named MITRE ATT&CK TTP patterns.",
    "memory": "Volatility3-based memory analysis (pslist/malfind/netscan) via VIGÍA's memory-analysis path — binary resolution confirmed (red-team round 6); real-dump plugin output not yet exercised end-to-end.",
    "mft": "$MFT parsing for filesystem timeline reconstruction via VIGÍA's mft_parser.",
    "ebs_json": "Scored-artifact JSON ingestion (EBS v1) for synthetic/pre-scored evidence via VIGÍA's EBS pipeline.",
}


def list_hunts(catalog: dict[str, str], arguments: dict[str, Any]) -> Any:
    """READ:hunt_catalog — list the investigation types Mode 1 can
    actually run, without granting execution rights: this is a catalog
    lookup, never a dispatch.
    """
    return {"hunts": [{"id": name, "description": description} for name, description in sorted(catalog.items())]}


def build_dispatcher_tools(catalog: dict[str, str] | None = None) -> dict[str, Any]:
    """The real DISPATCHER tool set for
    `AgentRuntime.run(AgentRole.DISPATCHER, tools=build_dispatcher_tools())`.

    Defaults to `DEFAULT_HUNT_CATALOG`; pass a narrower or case-specific
    catalog to restrict what a particular investigation may be told is
    available (e.g. omitting `memory` when no memory dump exists for
    that case).
    """
    resolved = catalog if catalog is not None else DEFAULT_HUNT_CATALOG
    return {"list_hunts": lambda arguments: list_hunts(resolved, arguments)}
