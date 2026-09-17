"""Location of ZAYNOR's vendored copy of VIGÍA's deterministic engine.

`vendor/vigia_engine/` at the repo root holds the exact subset of VIGÍA
that Mode 1 actually executes — confirmed by dynamically tracing real
runs (not a static import guess) against both real ingestion paths this
project uses: the EBS-JSON/rich-case-JSON route and the real
forensic-image route (registry/prefetch/browser/event-log/memory/USB/
shellbag/amcache, run against the real 2019-OWL Digital Corpora image).
79 files, ~41k lines — VIGÍA's own repository is roughly 800k LOC; this
is the traced runtime dependency closure of `vigia_agent.py`
(`vigia_agent.py`, `vigia_scorer.py`, `sift_orchestrator.py`, and the
`vigia/` package modules those actually import), not a manual guess at
"the important-looking files."

Same author, same license (Apache 2.0) as this repository — vendoring is
a packaging decision (single `git clone`, no second repository to manage
for a case to run), not a fork or a reimplementation: this is VIGÍA's
own, unmodified source, confirmed to run identically to the external
checkout (see docs/red-team/2026-09-16-round-14-vendored-engine.md for
the side-by-side induction). AGENTS.md §2.1's "never reimplement VIGÍA"
is unaffected — nothing here rewrites VIGÍA's logic; it relocates where
the same bytes live.

Deliberately excluded, and why: `vigia.vigia_sift_bridge` (Mode 2's MCP
bridge — never loaded by Mode 1, confirmed by the same dynamic trace) and
`vigia.scripts.run_pipeline` (VIGÍA's own text-pipeline fallback for when
`SIFTOrchestrator` is unavailable — already an optional, gracefully
degraded path in VIGÍA's own code, never exercised by ZAYNOR's confirmed
capability set).
"""

from __future__ import annotations

from pathlib import Path

import zaynor

VENDORED_ENGINE_PATH: Path = Path(zaynor.__file__).resolve().parent.parent.parent / "vendor" / "vigia_engine"
