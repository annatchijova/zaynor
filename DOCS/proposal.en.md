# Proposal — Zaynor: post-incident DFIR on top of VIGÍA's deterministic engine

*[Leer en español](./propuesta.md)*

> This is the second revision of the proposal (replaces the previous
> version, which still assumed Zaynor would reimplement miniature versions
> of VIGÍA's mechanisms). The substantive change, after judge/mentor
> feedback: **VIGÍA is a pre-existing deterministic forensic engine, and
> Zaynor does not rewrite it — it consumes it behind a narrow boundary.**
> See `DOCS/implementation-plan.en.md` for the layer-by-layer breakdown of
> how this gets built.

## 0. Why the architecture changes (and what doesn't)

What does **not** change: the guiding principle is the same as in the first
proposal —

> The AI decides what to investigate. The AI does not decide what is true.

What changes is *who* implements the deterministic epistemic authority. The
previous proposal had Zaynor rebuilding, at hackathon scale, small versions
of mechanisms VIGÍA already has solved and tested: a corroboration gate, a
fracture detector, an audit chain, a hallucination guard. Rewriting that in
48 hours produces a worse version of something that already exists, and
hands the judges — who already saw and valued VIGÍA — the worst possible
story: "we had 100k lines and rewrote 1,800 of them so we could say we built
them ourselves." The fix is to treat VIGÍA as an **engine/backend** behind
an adapter, not as a design reference to reimplement.

This forces a distinction the previous proposal collapsed into one:

- **Investigative agency** — deciding what evidence to inspect next, given a
  question that discriminates between competing hypotheses. The LLM can
  have this.
- **Epistemic authority** — deciding what state (`OBSERVED`, `CORROBORATED`,
  `CONTRADICTED`, `UNKNOWN`) a claim about the evidence holds. Only the
  deterministic engine (VIGÍA) has this, never the LLM.

`investigative authority ≠ epistemic authority`: the LLM can guide an
adaptive investigation without that implying it decides the truth. That
distinction is what lets Zaynor run in two modes without contradicting
itself:

```
Basic mode (no LLM investigator):
  evidence -> VIGÍA (deterministic engine) -> findings -> LLM narrates

Assisted mode (with LLM investigator):
  evidence -> VIGÍA (initial analysis)
      -> LLM: "I want to check X"
      -> read-only deterministic tool
      -> observation
      -> VIGÍA (re-verifies, updates authoritative state)
      -> finding
```

## 1. Product thesis (updated)

> Zaynor is a post-incident DFIR system built around a deterministic
> forensic authority boundary. Existing VIGÍA mechanisms provide
> reproducible evidence analysis, epistemic state, provenance, fracture
> detection, and auditability — rather than being rewritten for the
> hackathon. Zaynor adds the incident-oriented integration layer, MITRE
> ATT&CK/NIST contextualization, the postmortem workflow, and a local LLM
> interface. The LLM may explain deterministic findings and, optionally,
> guide further read-only investigation, but it can never promote its own
> conclusions into authoritative forensic state.

## 2. Differentiator

Zaynor's contribution isn't "another forensic engine" — it's the
integration layer that turns a general-purpose deterministic engine (VIGÍA)
into a cyberdefense-oriented post-incident investigation application:
declare the incident, freeze the case, invoke VIGÍA through a typed
adapter, enrich the result with MITRE ATT&CK/NIST, and generate an incident
report and a postmortem whose prose can never exceed what VIGÍA's ledger
actually corroborated. The demo proves that boundary live with an
adversarial evidence item that tries and fails to seize authority — and it
also proves that **Zaynor never duplicates logic VIGÍA already solves**: if
something has an equivalent in VIGÍA, it gets called, not reimplemented
"small" just so Zaynor can claim it built it from scratch.

## 3. Architecture

```
                              ZAYNOR
                                │
                         INCIDENT / CASE
                                │
                                ▼
                      FROZEN EVIDENCE
              manifest + hashes + lineage (Zaynor-owned)
                                │
               ┌────────────────┴────────────────┐
               │                                  │
               ▼                                  ▼
     VIGÍA — DETERMINISTIC ENGINE          AI-ASSISTED PATH (optional)
     (existing, via adapter,                       │
      NOT reimplemented)                    LLM decides what to
               │                            investigate
               │                                    │
               │                            read-only tools
               │                                    │
               │                            candidate claims (predicates)
               │                                    │
               └────────────────┬─────────────────┘
                                 ▼
                       AUTHORITY BOUNDARY
                    (inside VIGÍA: provenance/
                     independence verification,
                     fractures, contradictions)
                                 │
                                 ▼
                    AUTHORITATIVE STATE (VIGÍA)
              OBSERVED / CORROBORATED / CONTRADICTED / UNKNOWN
                                 │
                                 ▼
                    ADAPTER: ZaynorAuthoritativeResult
              (Zaynor does NOT know VIGÍA's internals —
               only this stable typed contract)
                                 │
                                 ▼
                    FRAMEWORK ENRICHMENT
            MITRE ATT&CK (which technique) · NIST (how it
            fits into investigation/response) — never raises
            a finding's certainty, only contextualizes it
                                 │
                                 ▼
                          SEALED RESULT
                                 │
                                 ▼
                          LOCAL LLM
              (narrates; hallucination guard validates every
               citation against the sealed result)
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                   ▼
       incident report      postmortem        audience-specific
       (what happened,      (what we learned,  summary/guidance
        with what backing)   what changes)     (analyst/junior/exec)
```

`VigiaAnalysisResult` (provisional name, confirmed against `vigia_agent.py`'s
actual call signature when the adapter is built, per the corresponding
layer in the implementation plan) is treated as a box with a stable
contract: observations, timeline, fractures, competing hypotheses, findings
with state/evidence_refs/provenance/rationale, `UNKNOWN` items, audit/
integrity metadata, and engine version. If VIGÍA has fifteen different
internal objects, Zaynor doesn't need to know — the adapter is exactly the
point where that complexity gets absorbed.

## 4. Repository reconnaissance — reuse decision

The previous category ("ADAPT / design reference") is replaced with one
that explicitly distinguishes calling something live from reimplementing
it:

> **`REUSE/CALL`** — the existing VIGÍA module/engine is invoked through an
> adapter; Zaynor does not reimplement its logic.
> **`ADAPT`** — a narrow contract/signature is copied (not the whole file),
> because VIGÍA embeds it in a component with too much of its own coupling
> to call directly.
> **`NEW ZAYNOR CODE`** — integration-specific logic (incident→case, MITRE/
> NIST enrichment, postmortem) that doesn't exist in VIGÍA because it isn't
> VIGÍA's domain.

Every path below was confirmed against the live VIGÍA repository
(`/home/labestiadevigia/vigia-repo`) before writing this table:

| Mechanism | Confirmed path in VIGÍA | Decision | Note |
|---|---|---|---|
| Analysis engine / entry point | `vigia_agent.py` | **REUSE/CALL** | exact call signature to confirm when building the adapter |
| Read-only evidence sandbox | `vigia/core/path_guard.py` (`PathGuard`) | **ADAPT** | the path-confinement contract is copied, not the full module — VIGÍA couples it to its own MCP bridge |
| Canonicalizer | `vigia/core/canonicalize.py` | **REUSE/CALL** | stdlib-only module, no coupling — imported directly |
| Audit hash-chain | `vigia/core/tool_log_chain.py`, `vigia/core/hash_chain.py` | **REUSE/CALL** | this was what most convinced the judges — no small rewrite of it |
| Deterministic corroboration gate | `vigia/collapse_decision.py` | **REUSE/CALL** | Zaynor does not reimplement its own gate |
| Seal-before-narrate | `vigia/core/bundle_builder.py` (a second variant also exists at `forensics/bundle_builder.py` — which one applies is resolved when building the adapter) | **ADAPT** | the sequencing contract (seal before narrate) is adapted; the sealing implementation itself is called, not copied |
| CAIE (cross-artifact scoring) | `vigia/tools/caie.py` | **out of scope** | still not needed for one incident with one designed fracture; neither called nor reimplemented |
| MITRE ATT&CK mapping | TTP references as comments in `vigia_scorer.py`'s detection rules | **confirmed: no dedicated mapping engine exists** | this is a real gap relative to what the whiteboard assumed — MITRE/NIST enrichment is built as a new Zaynor layer (§5), not "reused," because there's no equivalent module to call |
| OpenHands (agent loop, sandboxing, self-reported risk) | — | **IGNORE** | unchanged from the original recon: a Python ≥3.12 pin, a LiteLLM dependency, and either Docker or an unsandboxed `LocalWorkspace`, for capabilities this project doesn't need |

The MITRE row is the most important correction in this revision relative to
the whiteboard sketch: there's no VIGÍA module to call there, so labeling it
"reused" would be exactly the false reuse this table is otherwise trying to
avoid. It's built as a new layer, explicitly marked as such.

## 5. MITRE ATT&CK / NIST enrichment

A new Zaynor layer (no dedicated engine exists in VIGÍA for this), inserted
between VIGÍA's authoritative state and the final sealing step — never
before it:

- **MITRE ATT&CK** describes which technique/behavior a `CORROBORATED`
  finding corresponds to. It's contextualization, not additional evidence:
  an ATT&CK mapping cannot move a finding from `INSUFFICIENT` to
  `CORROBORATED`.
- **NIST** (incident-response framework) structures how that finding fits
  into the investigation/response/postmortem cycle — it's the taxonomy that
  organizes the final document, not a source of truth about the facts.

Neither framework has epistemic authority. If a MITRE mapping ever ends up
treated as raising a finding's certainty, that's exactly the kind of
authority leak `AGENTS.md` §2 prohibits — it gets treated the same as LLM
prose: it contextualizes, it doesn't decide.

## 6. Postmortem — content contract (corrected)

The structure from the previous proposal stays nearly intact, with one
epistemological correction: the template **cannot assume a corroborated
root cause always exists.**

1. Executive summary (validated LLM prose, 1-3 sentences).
2. Reconstructed timeline (sealed-result data, no prose).
3. **Root cause** — if a `CORROBORATED` claim supports it, it's narrated
   citing its provenance and independent sources. **If none exists, the
   section explicitly says `ROOT CAUSE: UNKNOWN` or lists the supported
   contributing factors without forcing a single root cause.** The template
   never invents a root cause just to fill a section.
4. Discarded hypotheses, each with the specific `CONTRADICTED` evidence
   that refuted it.
5. Explicit `UNKNOWN` items — never omitted.
6. Proposed defensive actions, **tied to corroborated findings and/or
   observed risks, explicitly noting when the root cause remains
   `UNKNOWN`** — not tied to a root cause that may not exist.
7. Audit trail — hash of the investigation's tool-call chain (VIGÍA
   mechanism, called via `REUSE/CALL`, not reimplemented).

A global `MALICE`/`BENIGN`/`SUSPICIOUS` verdict per section is also not
forced: the postmortem's main object can perfectly well end up as a list of
findings with individual state (`CORROBORATED`, `CONTRADICTED`) plus
explicit `UNKNOWN` fields (attribution, initial access vector, intent)
without needing a single verdict label. If VIGÍA exposes an equivalent
state with its own rigorous semantics, that's what gets used; a new one
isn't invented just to fill a box in the diagram.

## 7. Simulated incident, 3-minute demo

Unchanged in substance from the previous proposal (`INC-2026-DEMO-001`, a
compromised service account escalating to a stolen admin credential, the
adversarial item in `ticket_comment.txt`). The demo script now includes
MITRE/NIST enrichment as a visible step between VIGÍA's sealed result and
the LLM's narration, and the final postmortem must show at least one
explicit `UNKNOWN` item — including, potentially, the root cause itself,
without that reading as a demo failure but as proof the system doesn't
overclaim certainty.

## 8. Verdict

The underlying architecture (no epistemic authority for the LLM, a
deterministic gate, a postmortem separate from the incident report, an
audit hash-chain) doesn't change between this revision and the previous
one. What changes is where the implementation of that deterministic
authority lives: inside VIGÍA, invoked via an adapter, not rewritten in
miniature inside Zaynor. The main risk shifts from "running out of time
reimplementing mechanisms that already exist" to "building a
badly-specified adapter that hides too much or too little of VIGÍA's
internals" — see `DOCS/implementation-plan.en.md` for how that risk is
bounded layer by layer.
