# Improved proposal — Zaynor: hybrid DFIR with a verifiable postmortem

*[Leer en español](./propuesta.md)*

> This document replaces and extends the initial reconnaissance
> (`hackathon_dfir_recon_2026-09-15.md`) in light of two signals from the
> judges: they want to see a **postmortem** as an explicit deliverable, not
> something implicit in the incident report; and the **VIGÍA** mechanism
> (read-only sandbox + sealing a deterministic result before any narration)
> was the point that convinced them the most. Both signals change where we
> put effort, not the underlying architecture — the deterministic/LLM
> boundary from `AGENTS.md` §2 remains the backbone.

## 0. What changes relative to the initial recon

1. **Postmortem moves from "mentioned" to a first-class component.** The
   original recon ended at an "incident report renderer" (§I) that already
   included proposed actions, but not a structured, separate postmortem. It
   is now stage 10 of the pipeline (see `AGENTS.md`), with its own content
   contract (§5 below).
2. **VIGÍA moves from "design reference" to "adapted mechanism" in three
   places that used to sit at the margin:** the audit hash-chain
   (`tool_log_chain.py`) moves from P1/optional to P0 — it is exactly what
   made the demo credible to the judges, so it doesn't get cut under time
   pressure; the seal-before-narrating separation (`bundle_builder.py`)
   stops being "reference only" and is adapted directly for the postmortem
   renderer; CAIE (`caie.py`) stays a design reference — it is still not
   needed for one incident with one designed fracture, and forcing it in now
   would be the easiest way to burn the remaining time (see §K of the
   original recon, still valid).
3. **Terminology aligned with the contract already in force in the repo**
   (`AGENTS.md` §2): this no longer talks about a generic "hypothesis
   ledger" or "corroboration count ≥2" — the deterministic gate works over
   typed *claims* with typed *predicates* (`{event_id, field, op, value}`),
   each predicate is verified by re-reading the frozen evidence, and a claim
   only reaches `CORROBORATED` if it additionally satisfies the provenance
   and lineage-independence requirements (`lineage_id`, `distinct_lineages`)
   declared by the gate rule. The postmortem inherits that same discipline:
   it cannot cite anything that isn't in the ledger as `CORROBORATED` or
   explicitly flagged `UNKNOWN`.

## 1. Product thesis (updated)

Zaynor covers the incident end to end. A light, deterministic front end
(stages 1-3) detects and correlates over a deterministic replay of
synthetic telemetry until an incident is declared; at that point the
evidence is frozen (case freeze: manifest + SHA-256 + immutable
`incident_key`) and the deep investigation starts (stages 5-9): a local LLM
chooses which evidence to inspect, proposes *claims* with verifiable
predicates, and a deterministic gate re-verifies them against the frozen
evidence before letting them enter the ledger as `CORROBORATED`,
`CONTRADICTED`, or `INSUFFICIENT` (rendered as `UNKNOWN`). The final stage
(10) is the **postmortem**: a bilingual document, produced by a
deterministic template plus LLM prose, that can only narrate over facts
already authorized by the ledger — never invent a new one (ANNACONDA's
`hallucination_guard` pattern).

## 2. Differentiator (unchanged in substance, focused on what the judges valued)

The contribution is not operational (it doesn't compete with a SIEM or a
live-alert assistant): it's architectural. The LLM can only *choose what to
investigate* over a read-only toolset and *propose claims with predicates*;
it never writes a finding's status directly. The demo proves that boundary
live with an adversarial evidence item that tries and fails to seize
authority over the verdict — and now it also proves that the **final
postmortem** inherits the same discipline: every statement in the
postmortem is traceable to a `CORROBORATED` ledger entry, with its evidence
citation and its `lineage_id`.

## 3. Minimal architecture (updated)

```
 [1] Deterministic replay     [2] Detection/Correlation    [3] Case Freezer
  of synthetic telemetry  --> (rule + correlation rule) --> manifest + SHA-256
                                                              immutable incident_key
                                                                    |
                                                                    v
                                                      [4] Frozen evidence +
                                                          read-only tool layer
                                                      (list_events, read_artifact,
                                                       grep_pattern, get_timeline_window)
                                                                    |
                                                                    v
                                                      [5] Local LLM investigator
                                                      (Ollama, tool-calling loop)
                                                      proposes CLAIMS with
                                                      predicates, never a verdict
                                                                    |
                                                                    v
                                          [6] Deterministic gate (predicate re-check)
                                          VERIFIED by re-reading evidence directly;
                                          CORROBORATED only if it also satisfies
                                          provenance + lineage-independence
                                                                    |
                                                                    v
                                          [7] Claim ledger (sole authority)
                                          CORROBORATED / CONTRADICTED / INSUFFICIENT
                                                                    |
                                            +-----------------------+-----------------------+
                                            v                                               v
                                  [8] Incident report renderer                   [9] POSTMORTEM renderer
                                  (bilingual)                                    (bilingual, stage 10)
                                  narrative sealed alongside,                    deterministic template +
                                  never inside the verdict                       LLM prose validated by
                                                                                  hallucination_guard;
                                                                                  audit hash-chain
                                                                                  (VIGÍA) cited as evidence
                                                                                  of process integrity
```

The postmortem (component 9) is deliberately a separate renderer from the
incident report (component 8), not an extra section of the same document:
the incident report answers "what happened, and with what confidence?" for
whoever is responding now; the postmortem answers "what did we learn and
what changes?" for whoever audits it later — different audiences and
different moments, and separating them is what lets the judges see exactly
what they asked for without having to extract it from a larger document.

## 4. Repository reconnaissance (updated table)

| Mechanism | Repo | Previous decision | Decision now | Why it changed |
|---|---|---|---|---|
| Read-only evidence sandbox | VIGÍA (`vigia_sift_bridge.py`) | ADAPT | ADAPT (unchanged) | already P0 |
| Canonicalizer | VIGÍA (`canonicalize.py`) | REUSE | REUSE (unchanged) | already P0 |
| **Audit hash-chain** | VIGÍA (`tool_log_chain.py`, `hash_chain.py`) | ADAPT, **P1/optional** | ADAPT, **P0** | the judges explicitly valued VIGÍA's integrity chain; the postmortem cites this chain as evidence that the investigation process was not tampered with |
| Deterministic gate (shape) | VIGÍA (`collapse_decision.py`) | ADAPT | ADAPT (unchanged, now expressed as the predicate/claim gate per `AGENTS.md` §2) | terminology aligned, mechanism unchanged |
| **Seal-before-narrate** | VIGÍA (`bundle_builder.py`) | design reference | **adapt directly** for the postmortem renderer | exactly the pattern component 9 needs |
| CAIE cross-artifact scoring | VIGÍA (`caie.py`) | design reference | design reference (unchanged) | still not needed for one incident with one designed fracture |
| Hallucination guard | ANNACONDA (`hallucination_guard.py`) | REUSE | REUSE (unchanged) | validates both the incident report and the postmortem |
| Chain of custody | ANNACONDA (`chain_of_custody.py`) | REUSE | REUSE (unchanged) | — |
| OpenHands (agent loop, sandboxing, self-reported risk) | — | IGNORE | IGNORE (unchanged) | the original recon's cost/benefit analysis still holds: a Python ≥3.12 pin, a LiteLLM dependency, and either Docker or an unsandboxed `LocalWorkspace`, for capabilities this project doesn't need |

## 5. Postmortem — content contract

The postmortem is a generated document, not hand-written, with this fixed
structure (deterministic template; the LLM only fills the marked prose
sections, and only with `CORROBORATED` facts):

1. **Executive summary** (LLM prose, validated) — one to three sentences.
2. **Reconstructed timeline** (ledger data, no prose) — every event with its
   `event_id`, timestamp, and the status of the claim backing it.
3. **Root cause** (LLM prose over the corresponding `CORROBORATED` claim,
   citing its `lineage_id` and the independent sources that corroborate it).
4. **Discarded hypotheses** — each with the specific `CONTRADICTED`
   evidence that refuted it, never "discarded" without a citation.
5. **`UNKNOWN` items** — explicit, not omitted. This is what separates an
   honest postmortem from one that overclaims certainty (see
   `daubert-defensible-writing`: a documented `UNKNOWN` is worth more than a
   forced `CORROBORATED`).
6. **Proposed prevention actions** (not executed) — tied to the corroborated
   root cause, not to the full list of hypotheses.
7. **Audit trail** — hash of the investigation's tool-call chain (adapted
   VIGÍA mechanism), so the postmortem itself is independently verifiable by
   whoever reads it.

Every prose section passes through the same `hallucination_guard` before
rendering: if the LLM cites a fact that doesn't match the sealed ledger,
that section is flagged as failed and rendered with the raw ledger data in
its place — an unverified citation is never let through by default.

## 6. Simulated incident, AI-necessity test, 3-minute demo

Unchanged in substance from the original recon (`INC-2026-DEMO-001`, a
compromised service account escalating to a stolen admin credential, the
adversarial item in `ticket_comment.txt`, the deliberate `UNKNOWN` item
about the intent behind the final pivot). The only adjustment is to the
script: the final stretch of the demo (previously "2:30–2:50 final report")
now shows **postmortem generation** explicitly as a separate step, with the
audit chain visible on screen:

- **2:10–2:30** — the adversarial ticket comment; the system logs it as
  evidence and continues unaffected (unchanged).
- **2:30–2:50** — the **postmortem** is generated: corroborated root cause,
  discarded hypotheses with their evidence, one explicit `UNKNOWN` item, and
  the investigation's audit chain visible as proof of integrity.
- **2:50–3:00** — two proposed prevention actions + close.

## 7. Build plan (updated)

**P0 (previously P1, now required):**
- Audit hash-chain over the investigation's tool calls (adapted VIGÍA
  `tool_log_chain.py`) — no longer "valuable if time allows"; it's what the
  postmortem cites as proof of integrity.
- Postmortem renderer (deterministic template + validated LLM prose,
  `bundle_builder.py`'s seal-before-narrate pattern).

**P0 (unchanged from the original recon):** incident fixture,
normalizer/timeline, fracture detector, read-only tool layer, Ollama
tool-calling loop, predicate/claim gate, hallucination guard, incident
report renderer, the adversarial item.

**P1:** simple CLI or web view for the demo; an explicit "what would
confirm/refute each hypothesis" trace in the UI.

**P2 (do not touch until everything else works):** Docker/sandboxing
beyond path confinement; multi-incident support; CAIE-style cross-artifact
fusion.

## 8. Verdict

The original recon's architecture doesn't change — the postmortem and
VIGÍA's increased weight slot into places where room was already reserved
(the report renderer, the optional hash-chain); they don't require a new
component outside what was already mapped. The main risk is the same one
from the original recon (§K): don't let building a general timeline/fracture
engine (or now, a general postmortem engine) consume time that one incident
with one designed fracture doesn't need.
