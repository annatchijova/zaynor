# Provenance

This directory is a vendored, unmodified copy of a subset of
[`vigia-intent-analysis`](https://github.com/annatchijova/vigia-intent-analysis)
(VIGÍA), Anna Tchijova's deterministic forensic intentionality analysis
engine — same author, same license (Apache License 2.0) as this
repository. See `../../LICENSE`.

## Why vendored, not a separate clone

Zaynor integrates VIGÍA as its deterministic decision engine rather than
reimplementing it (`AGENTS.md` §2.1). Vendoring is a packaging decision,
not a fork: a single `git clone` is enough to run `zaynor analyze`
end to end, with no second repository to manage. Nothing in these files
is modified from the upstream source.

## Scope

This is not the whole VIGÍA repository (roughly 800k lines). It is the
exact runtime dependency closure of `vigia_agent.py` — confirmed by
dynamically tracing real executions (not a static import guess) against
both real ingestion paths Zaynor uses:

- the EBS-JSON / rich-case-JSON route, and
- the real forensic-image route (registry, prefetch, browser, event log,
  memory, USB, shellbag, amcache — run against the real 2019-OWL Digital
  Corpora image).

79 files, ~41,000 lines. See `docs/red-team/2026-09-16-round-14-vendored-engine.md`
in the Zaynor repository for the full trace methodology and the
side-by-side induction confirming this copy behaves identically to the
upstream checkout.

Deliberately excluded:

- `vigia.vigia_sift_bridge` — VIGÍA's Mode 2 MCP bridge, never loaded by
  Mode 1 (confirmed by the same dynamic trace).
- `vigia.scripts.run_pipeline` — VIGÍA's own text-pipeline fallback for
  when its SIFT orchestrator is unavailable; already an optional,
  gracefully degraded path in VIGÍA's own code, never exercised by
  Zaynor's confirmed capability set.

## Updating this vendored copy

If VIGÍA's upstream repository changes in a way Zaynor needs, re-run the
trace methodology in the round-14 doc against the new checkout rather
than copying files by hand — the dependency closure can shift between
versions.
