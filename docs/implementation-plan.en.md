# ZAYNOR implementation plan: VIGÍA integration

Companion to `proposal.en.md` (the decision) and `AGENTS.md` §2 (the
enforced contract). This document is the sequencing: what gets built, in
what order, what blocks what, and — per phase — what "done" actually has to
demonstrate. The phase count is short on purpose: VIGÍA is an existing
engine, so this is an integration plan, not an engine-building plan (§2.1).
Don't re-fatten it with more implementation phases; if something feels
missing, it belongs as a contract, an invariant, a test, or an observable
output inside one of the seven phases below — see Phase 8 for how the whole
thing gets demonstrated together.

## Phase 0 — Inventory (blocks Phase 3, do this first)

Nothing about the VIGÍA adapter can be written correctly until this exists.

- [ ] Enumerate VIGÍA's actual integration surfaces — importable library,
      CLI, HTTP/RPC service, files it reads/writes — from VIGÍA's own
      source, not assumptions. **Do not infer the preferred integration
      surface merely from what exists.** Inventory every available surface
      first, then deliberately choose the narrowest stable one suitable for
      ZAYNOR. VIGÍA exposing a CLI, a library, and internals doesn't make
      the first one Codex happens to find the right contract.
- [ ] Fill in the capability matrix below completely — this, not just the
      result schema, is what tells Phase 1-4 where to stop so nothing
      reimplements a piece of VIGÍA (§2.1):

  | Required capability | Exists in VIGÍA? | Exact symbol/path | Semantics match? | Adapter needed? | Tests | Decision |
  |---|---|---|---|---|---|---|
  | evidence ingestion | | | | | | |
  | canonicalization | | | | | | |
  | timeline | | | | | | |
  | fractures | | | | | | |
  | hypotheses | | | | | | |
  | corroboration | | | | | | |
  | contradiction | | | | | | |
  | provenance/lineage | | | | | | |
  | UNKNOWN/abstention | | | | | | |
  | exact arithmetic | | | | | | |
  | MITRE mapping | | | | | | |
  | authorized facts | | | | | | |
  | hash/audit | | | | | | |
  | narrative guard | | | | | | |

  A row with no cells filled in is not "done, nothing there" — it's
  unresearched. "Decision" is one of: *use VIGÍA as-is*, *use VIGÍA via a
  thin adapter*, or *implement in ZAYNOR because VIGÍA doesn't cover this
  and the gap is documented* (§2.1's "documented incompatibility").
- [ ] Draft the `ZaynorAuthoritativeResult` contract (full shape in
      Phase 3) from the matrix's "adapter needed" rows — the shape
      everything downstream (Phase 4, 5, 6) codes against. Nobody
      downstream imports a VIGÍA type directly.
- [ ] Write down anything ZAYNOR needs that VIGÍA does not provide (e.g.
      case-freeze manifesting, MITRE/NIST mapping are almost certainly
      ZAYNOR's own responsibility, not VIGÍA's) — these become explicit
      "implement in ZAYNOR" rows in the matrix, not silent gaps.

**Exit condition:** the capability matrix filled in for all rows, and a
written `ZaynorAuthoritativeResult` schema (even a draft
dataclass/TypedDict) derived from it, that Phase 3 through 6 can all code
against independently and in parallel.

## Phase 1 — Deterministic front end (pipeline stages 1-3)

Can start in parallel with Phase 0; doesn't depend on VIGÍA at all.

- [ ] Synthetic telemetry replay generator (a generated/replayed event
      stream — never call this "live telemetry", per the pipeline scope
      note in `AGENTS.md`).
- [ ] Detection: threshold or pattern rule over the replayed stream.
- [ ] Correlation/triage: declarative rule group that groups events into an
      incident and fires `INCIDENT DECLARED`.
- [ ] The three identifiers, computed exactly as specified in `AGENTS.md`
      (`event_id`, `alert_fingerprint`, `incident_key`) — don't collapse
      them into one hash.

**Exit condition:** a declared incident with a reproducible set of
constituent events, ready for freezing.

## Phase 2 — Case freeze

Depends on Phase 1's output shape; otherwise independent.

- [ ] Case freezer with these integrity semantics, not just "hash it":
      - manifest canonicalization
      - artifact SHA-256
      - provenance/lineage metadata where available
      - case root confinement (nothing outside the case directory is
        addressable as evidence)
      - ground truth excluded from evidence (the labels used to build the
        synthetic scenario never enter the frozen bundle VIGÍA/the LLM can
        see)
      - deterministic case identity semantics — the same canonical case
        always yields the same `case_id`
- [ ] Immutable `case_id`.
- [ ] Two cheap tests:
      - changed artifact bytes → different artifact hash
      - same canonical case → same deterministic case identity
- [ ] State the epistemic scope of the hash explicitly, in code comments or
      docs near the freezer: a hash proves artifact identity/integrity
      under this protocol; it does not prove truth, provenance, authorship,
      causality, or completeness. That boundary is load-bearing — don't let
      "it's hashed" get read as "it's verified".

**Exit condition:** a frozen, hashed case bundle satisfying the above —
the input to Phase 3.

## Phase 3 — VIGÍA adapter

Blocked by Phase 0 (needs the matrix and the contract) and Phase 2 (needs a
frozen case to feed in). This is the integration boundary itself (§2.1) —
the single highest-risk phase to get wrong, because it's where "just
reimplement a smaller version" temptation is strongest, and it's the
project's heart, not a four-line translation step.

**Draft `ZaynorAuthoritativeResult` shape** (names are draft — Phase 0's
matrix decides each one explicitly, this is the shape, not the final
naming):

```
ZaynorAuthoritativeResult
├── case_id
├── engine
│   ├── name
│   ├── version/commit
│   └── configuration_hash
├── observations[]
├── timeline[]
├── fractures[]
├── hypotheses[]
├── findings[]
│   ├── finding_id
│   ├── state
│   ├── evidence_refs[]
│   ├── lineage_ids[]
│   └── rationale/mechanical_basis
├── unknowns[]
├── provenance[]
├── integrity
└── audit_refs[]
```

- [ ] Translate a frozen case bundle into whatever input shape VIGÍA
      actually takes (per Phase 0's inventory).
- [ ] Invoke VIGÍA's deterministic analysis.
- [ ] Translate VIGÍA's output into `ZaynorAuthoritativeResult` — no field
      of VIGÍA's internal object graph leaks past this function.
- [ ] Adapter tests: round-trip a known case bundle, assert the resulting
      `ZaynorAuthoritativeResult` matches expectations, assert nothing
      VIGÍA-shaped survives past the adapter.
- [ ] Three acceptance properties, each with its own test:
      - same frozen case + same VIGÍA version + same config ⇒ same
        authoritative result (determinism/reproducibility)
      - LLM unavailable ⇒ the adapter still produces a valid authoritative
        result (the adapter has no LLM dependency at all)
      - an unsupported or missing VIGÍA field ⇒ the corresponding output is
        explicit `UNKNOWN` / "capability absent", never a ZAYNOR-invented
        replacement value. If Codex discovers VIGÍA doesn't expose
        something, that is a matrix gap to document (§2.1), not license to
        silently implement a substitute inside the adapter.

**Exit condition:** `adapter(frozen_case) -> ZaynorAuthoritativeResult`,
tested against all three acceptance properties above, with zero VIGÍA
imports anywhere outside this module.

## Phase 4 — Framework contextualization, then seal

Depends on Phase 3's contract (can be stubbed against Phase 0's draft
schema before Phase 3 is fully done). Framework enrichment and sealing are
one phase but two explicit, ordered steps — don't collapse them:

```
authoritative forensic result
        ↓
MITRE/NIST contextualization
        ↓
completed authoritative package
        ↓
canonicalize
        ↓
seal
```

- [ ] MITRE ATT&CK mapping as structured fields, not a bare string tag:
      ```
      Finding F-003
      state: CORROBORATED

      MITRE ATT&CK:
        technique: Txxxx
        justification: ...
        mapping_status: SUPPORTED

      NIST:
        function/category/IR stage: ...
        justification: ...
      ```
      Finding state, technique/category, justification, and mapping status
      are separate fields, always (§2.4).
- [ ] NIST mapping: same structure, separate field.
- [ ] A framework mapping may fail or remain `UNKNOWN` without invalidating
      the underlying finding — mapping status and finding state vary
      independently.
- [ ] Seal: canonicalize and hash the completed package (findings +
      mappings), mark it immutable.

**Exit condition:** a sealed, hashed authoritative result — findings and
framework mappings both present as structured, separately-stated fields —
ready for the LLM layer.

## Phase 5 — LLM narrator (required path)

Depends on Phase 4's sealed output (can be developed against a stub sealed
result before Phase 4 is fully wired). This is half the product experience
for a hackathon demo, not a one-line "summarize it" step — it needs
explicit, separately-tested outputs:

- [ ] **Analyst view** — findings, evidence references, timeline,
      fractures, hypotheses/alternatives, MITRE/NIST, UNKNOWNs.
- [ ] **Junior explanation** — what was observed, why it matters, what
      evidence supports it, what alternatives existed, what discriminated
      them, what remains unknown.
- [ ] **Incident report** — incident summary, reconstructed timeline,
      supported findings, framework mappings, uncertainty, proposed
      defensive actions (labeled as proposals).
- [ ] **Postmortem** — executive summary, timeline, supported root cause OR
      explicit `ROOT CAUSE: UNKNOWN`, contradicted hypotheses, unresolved
      questions, prevention proposals, audit/integrity references.
- [ ] Narrator consumes only the sealed `ZaynorAuthoritativeResult` +
      authorized facts — no other input channel.
- [ ] Two separate guards, not one — proving immutability alone doesn't
      prove the narration is honest:
      - **State guard:** a mechanical check that narrator output cannot
        write back into the authoritative result.
      - **Factuality/authorization guard:** a mechanical or adversarial
        check that the narrator cannot present an unauthorized factual
        claim as a finding — every fact-shaped statement in its output
        must trace to something in the sealed result. `AGENTS.md` already
        defines the narrator as a consumer of authorized facts that cannot
        add facts (§2.2); this guard is what makes that testable instead of
        aspirational.
- [ ] Test: `run(case, llm=OFF).authoritative_result ==
      run(case, llm=ON).authoritative_result` for the same frozen evidence
      set (the invariant from `proposal.en.md`).

**Exit condition:** all four output types exist and are narrated only from
sealed facts; both the state guard and the factuality/authorization guard
pass.

## Phase 6 — LLM investigation assistant (optional path)

Depends on Phase 3 (needs somewhere to route suggested queries back into)
and the existing allowlisted read-only tool registry (§2.3). Build this
after Phase 5 — it's optional, Phase 5 is not.

Keep these four distinct — a suggested query is not itself a hypothesis:

```
Hypothesis:
    H2 = credential reuse

Investigative question:
    Q7 = Did the same principal authenticate from another source?

Suggested operation:
    timeline_query(...)

Observation:
    ...

Evidence:
    ...

→ back to deterministic engine
```

- [ ] The LLM tracks a hypothesis (`CANDIDATE` / `ACTIVE` / `ABANDONED`,
      per §2.2) separately from the investigative questions it derives from
      that hypothesis, separately again from the concrete read-only
      operation it suggests to answer one.
- [ ] Route the suggested operation through the same hardcoded allowlist as
      every other tool call — no special-casing this path.
- [ ] Any evidence returned goes back through VIGÍA / the deterministic
      adapter before it can change `ZaynorAuthoritativeResult`.

**Exit condition:** enabling/disabling this path never changes the result
for a fixed evidence set — only which evidence gets pulled in — and the
hypothesis/question/operation/evidence chain is inspectable, not collapsed
into one LLM utterance.

## Phase 7 — Definition-of-done wiring

Ongoing, not a single phase — apply `AGENTS.md` §6 to every PR from Phase 1
onward. Specifically worth automating early rather than checking by hand
every time:

- [ ] The `llm=OFF`/`llm=ON` equivalence test from Phase 5.
- [ ] A test asserting no VIGÍA-internal type crosses the adapter boundary
      (Phase 3).
- [ ] A test asserting no float reaches a status/hash computation.
- [ ] A test asserting an unresolvable predicate renders `UNKNOWN`, not a
      guess.

## Phase 8 — End-to-end acceptance and demo

Not an implementation phase — the global exit condition for the whole
project. One frozen incident must demonstrate, end to end:

```
synthetic replay
→ deterministic detection
→ incident declaration
→ case freeze
→ real VIGÍA execution
→ deterministic forensic result
→ at least one supported finding
→ at least one explicit UNKNOWN or contradicted alternative
→ MITRE ATT&CK contextualization
→ NIST contextualization
→ sealed result
→ local LLM explanation
→ postmortem
```

Falsifications — the demo is not accepted if any of these fails:

1. Same evidence → same deterministic result.
2. LLM OFF → same authoritative result.
3. Different LLM narration → same authoritative result.
4. Evidence prompt injection → no authority change.
5. Derived duplicate evidence → no fake independent corroboration.
6. Missing evidence → `UNKNOWN`, not a guessed completion.
7. MITRE mapping → cannot promote finding state.
8. Tampered frozen artifact → integrity failure visible.
9. VIGÍA failure → explicit failure, never a synthetic fallback finding.
10. Ground truth → inaccessible to VIGÍA/LLM during investigation.

**Exit condition:** all ten falsifications pass against one real, recorded
end-to-end run — not against a mocked adapter or a stubbed sealed result.

## Sequencing summary

```
Phase 0 (inventory + matrix + contract)  ──┐
Phase 1 (front end)   ── Phase 2 (freeze) ──┤
                                             ├── Phase 3 (adapter) ── Phase 4 (frameworks → seal) ── Phase 5 (narrator) ── Phase 6 (investigator, optional) ── Phase 8 (E2E demo)
                                             │                                         ↑ can stub against Phase 0's draft contract before Phase 3 lands
                                             └── (Phase 0 also unblocks stubbed Phase 4/5 work in parallel)
Phase 7 (DoD wiring) runs alongside every phase above, starting with Phase 1.
```

Phases 0 and 1 start immediately, in parallel, by different people. Phase 3
is the critical path — nothing downstream is real until it lands, though
Phase 4 and 5 can be built and tested against a stubbed contract in the
meantime so they're not sitting idle. Phase 8 is not "extra time at the
end" — start recording which falsifications already pass as soon as Phase 3
lands, instead of discovering gaps the night of the demo.

## Open questions this plan does not answer

- Who owns which phase among the four of you, and the actual deadline —
  team logistics, not something to guess at here.
