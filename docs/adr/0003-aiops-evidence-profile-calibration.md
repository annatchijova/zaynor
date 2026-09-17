# ADR 0003: AIOps evidence-profile calibration is static, table-driven,
# and PR-reviewed

Date: 2026-09-17
Status: Accepted
Supersedes: none
Related: AGENTS.md sections 0 and 2, ADR 0002 (hybrid local evidence plan)

## Context

The AIOps path of the demo lab (`tools/aiops/aggregator/`) transforms
alert clusters and telemetry into evidence bundles for ZAYNOR's
deterministic engine. The mapping from normalized observation records
onto VIGÍA case-corpus artifacts requires three per-rule constants:

- `evidence_type` — which whitelisted VIGÍA evidence type the artifact is
  scored under (`log_entry`, `metric_sample`, ...);
- `raw_score` — the artifact's severity weight;
- `prior_trust` — the provenance trust weight.

These constants are consumed downstream by VIGÍA (`raw_score` ×
`prior_trust` feeds CAIE and the verdict ladder), so they are
**verdict-affecting calibration**, even though no scorer code changed.
The same question applies to the DFIR mapping table
(`tools/velociraptor/mappings.py`), which carries identically-shaped
constants under the same doctrine.

Without a stated authorization story, a reviewer could reasonably ask
who decided that a privileged-login anomaly weighs 0.90, and whether an
agent or a collector could move those numbers to steer a verdict.

## Decision

1. **Static constants only.** `raw_score`/`prior_trust` are fixed
   decimals carried by the rule, stored as `fractions.Fraction` (exact,
   no binary float) and serialized in VIGÍA's own case-corpus format.
   Nothing in the collection or mapping path computes them from the
   content of a case. An unfired rule never produces an artifact, and a
   row matching no rule is dropped — never filled with a guess.
2. **Authorization = PR review of this repository.** The initial AIOps
   calibration (`EVIDENCE_PROFILES` in
   `tools/aiops/aggregator/evidence.py`) and the DFIR rule table
   (`RULES` in `tools/velociraptor/mappings.py`) were authored as part
   of the demo-lab feature and are reviewed in PR #12 — the same review
   process VIGÍA's own case-corpus artifacts and the DFIR rule table go
   through. They are detection-engineering data, owned by the
   deterministic side of the boundary (ZAYNOR), never by the collector
   runtime or any LLM.
3. **Verdict regression pin.** `tests/test_aiops_aggregator.py` contains
   a fixture that runs a representative AIOps incident through the real
   pipeline (bundle → freeze → `zaynor analyze` → seal) and asserts the
   authoritative verdict. Any change to the constants that changes the
   resulting verdict fails this test and must be re-reviewed here.
4. **Scorer untouched.** This ADR introduces no change to
   `vendor/vigia_engine/` — no scorer logic, thresholds, or existing
   corpus numbers.

## Consequences

- Changing a constant requires a PR whose diff shows the calibration
  change and, when the verdict changes, an updated verdict fixture.
- The demo-lab rule tables are intentionally small and calibrated for
  the 3-minute demo; they are not production detection engineering.
- The same doctrine now has one home: collectors observe, mapping tables
  calibrate, VIGÍA decides.
