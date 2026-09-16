# ZAYNOR architecture proposal: integrate VIGÍA, don't rebuild it

**Status:** decided. Supersedes any earlier plan to build local
"VIGÍA-mini" mechanisms inside ZAYNOR. `AGENTS.md` §2 is the enforced
version of this decision for anyone (human or agent) writing code against
it — this document is the "why" behind that contract.

## Context

The original framing had ZAYNOR's local LLM picking which frozen evidence
to inspect next and a deterministic gate re-verifying its claims directly
against that evidence — a self-contained investigator built from scratch.
VIGÍA already exists as a deterministic forensic engine. Building smaller,
local versions of VIGÍA's mechanisms inside ZAYNOR duplicates work, forks
semantics between two codebases, and gives Claude/Codex a mental model
("build an LLM investigator + tools + gate") that no longer matches what
the team is actually assembling.

## Decision

ZAYNOR is a hybrid DFIR system built around VIGÍA as the deterministic
forensic engine, not a system that reimplements VIGÍA's mechanisms from
scratch.

1. A small deterministic front end may detect and correlate signals over a
   deterministic replay of synthetic telemetry until an incident is
   declared.
2. The resulting case is frozen (manifest + SHA-256, immutable `case_id`)
   and handed through an explicit adapter to VIGÍA, which performs the
   authoritative deterministic forensic analysis.
3. ZAYNOR maps supported findings into applicable frameworks (MITRE
   ATT&CK, NIST) and seals an authoritative result.
4. A local LLM consumes that sealed state to explain, summarize, and
   generate reports and postmortems for different analyst audiences. It
   may optionally suggest further read-only investigative queries, but any
   resulting evidence has no effect on the authoritative result until it
   has crossed back through the deterministic authority boundary.

```
synthetic telemetry replay  ->  detection  ->  correlation/triage
   ->  INCIDENT DECLARED — case freeze (manifest + SHA-256, immutable case_id)
   ->  VIGÍA adapter  ->  deterministic forensic analysis (VIGÍA)
   ->  authoritative ZAYNOR result  ->  MITRE ATT&CK / NIST contextualization
   ->  seal  ->  local LLM narration  ->  incident report / postmortem
```

Optional, read-only branch back into the deterministic side:

```
authoritative ZAYNOR result
   ->  LLM investigative suggestion  ->  allowlisted read-only query
   ->  evidence  ->  VIGÍA / deterministic re-analysis
   ->  updated authoritative ZAYNOR result
```

## Two boundaries, not one

```
           integration boundary
ZAYNOR ─────────────────────────→ VIGÍA
 (adapter)                          │
                                    │ deterministic
                                    │ authority
                                    ▼
                          authoritative ZAYNOR result
                                    │
           narration boundary       │
   LLM  ←─────────────────────────────┘
 (required: narrator)
 (optional: investigation assistant, read-only, no authority)
```

- **ZAYNOR ↔ VIGÍA (integration boundary).** VIGÍA is an existing engine,
  not a design document to be reimplemented. A required deterministic
  capability that already exists in VIGÍA gets integrated through an
  explicit adapter; a local reimplementation needs a documented reason —
  "it was faster to write from scratch" is not one. ZAYNOR code depends on
  a stable `ZaynorAuthoritativeResult` contract translated from VIGÍA's
  output, never on VIGÍA's internal object graph.
- **Deterministic ↔ LLM (authority boundary).** Unchanged from the
  existing claim-state model: typed predicates, VERIFIED vs. CORROBORATED,
  lineage/independence tracking, evidence-as-data, the read-only tool
  allowlist, `UNKNOWN` over a smoothed guess, and no float in anything that
  feeds a status or a hash. The deterministic layer doesn't own
  investigative reasoning — it owns what's allowed to cross the boundary
  into ZAYNOR's authoritative state.

## The LLM's two roles

- **Narrator (required).** Once ZAYNOR seals an authoritative result, the
  local LLM explains, summarizes, adapts by audience, and drafts
  reports/postmortems from the sealed, authorized facts. It can propose
  actions, clearly labeled as proposals. It cannot add facts.
- **Investigation assistant (optional).** The LLM may suggest an
  additional read-only investigative query. The suggestion has no forensic
  authority by itself — any evidence it turns up goes back through VIGÍA /
  the deterministic boundary before it can affect a finding.

## Framework mappings are annotations, not evidence

MITRE ATT&CK and NIST contextualize authoritative forensic results; they do
not create them. A technique mapping never promotes a finding's epistemic
state — a framework match is not evidence of causality, intent,
attribution, or attacker identity. Finding state, framework mapping,
mapping justification, and mapping confidence stay separate fields. NIST
structures incident handling and reporting; it doesn't substitute for the
evidence model.

## Consequences

- `AGENTS.md` §2 is rewritten around this decision (VIGÍA reuse boundary,
  narrator/investigator split, framework-mapping semantics) and its
  Definition of Done gains checks for it: no undocumented VIGÍA
  reimplementation, no VIGÍA internals leaking past the adapter, no LLM
  completion writing directly to authoritative state, framework mappings
  never promoting finding state, and narrative output never modifying the
  sealed result.
- The load-bearing invariant for the narrator path:
  `run(case, llm=OFF).authoritative_result == run(case, llm=ON).authoritative_result`
  for the same frozen evidence set. If investigation-assistant suggestions
  are enabled, the comparison is scoped to the same evidence set / same
  deterministic input — a run that collected different evidence through
  different suggested queries is a different investigation, not a
  violation of this invariant.
- Everything not touched by this decision — reasoning discipline (§1),
  editing discipline (§3), git/PR workflow (§4), verification-before-claims
  (§5), and the parts of the Definition of Done (§6) unrelated to the
  VIGÍA/LLM split — stands as-is.

## Out of scope here

The concrete `ZaynorAuthoritativeResult` schema, the VIGÍA adapter's
implementation, and an implementation plan/timeline are follow-up work, not
covered by this document.
