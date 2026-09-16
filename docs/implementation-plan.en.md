# ZAYNOR implementation plan: VIGÍA integration

Companion to `proposal.en.md` (the decision) and `AGENTS.md` §2 (the
enforced contract). This document is the sequencing: what gets built, in
what order, and what blocks what.

## Phase 0 — Inventory (blocks Phase 3, do this first)

Nothing about the VIGÍA adapter can be written correctly until this exists.

- [ ] Enumerate VIGÍA's actual interface: is it an importable library, a
      CLI, an HTTP/RPC service, a set of files it reads/writes? Whoever owns
      this phase needs VIGÍA's own docs/source, not assumptions.
- [ ] Enumerate the deterministic mechanisms VIGÍA already provides
      (parsing, correlation, scoring, whatever it does) so Phase 1-4 stop
      short of reimplementing any of them, per §2.1.
- [ ] Draft the `ZaynorAuthoritativeResult` contract: field names, types,
      which fields are hashes/provenance vs. findings vs. metadata. This is
      the shape everything downstream (Phase 4, 5, 6) codes against —
      nobody downstream should import a VIGÍA type directly.
- [ ] Write down anything ZAYNOR needs that VIGÍA does not provide (e.g.
      case-freeze manifesting, MITRE/NIST mapping are almost certainly
      ZAYNOR's own responsibility, not VIGÍA's).

**Exit condition:** a written `ZaynorAuthoritativeResult` schema (even a
draft dataclass/TypedDict) that Phase 3 through 6 can all code against
independently and in parallel.

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

- [ ] Case freezer: select the incident's records, hash every artifact,
      write the manifest, close the bundle to writes.
- [ ] Immutable `case_id`.

**Exit condition:** a frozen, hashed case bundle — the input to Phase 3.

## Phase 3 — VIGÍA adapter

Blocked by Phase 0 (needs the contract) and Phase 2 (needs a frozen case to
feed in). This is the integration boundary itself (§2.1) — the single
highest-risk phase to get wrong, because it's where "just reimplement a
smaller version" temptation is strongest.

- [ ] Translate a frozen case bundle into whatever input shape VIGÍA
      actually takes (per Phase 0's inventory).
- [ ] Invoke VIGÍA's deterministic analysis.
- [ ] Translate VIGÍA's output into `ZaynorAuthoritativeResult` — no field
      of VIGÍA's internal object graph leaks past this function.
- [ ] Adapter tests: round-trip a known case bundle, assert the resulting
      `ZaynorAuthoritativeResult` matches expectations, assert nothing
      VIGÍA-shaped survives past the adapter.

**Exit condition:** `adapter(frozen_case) -> ZaynorAuthoritativeResult`,
tested, with zero VIGÍA imports anywhere outside this module.

## Phase 4 — Framework contextualization + seal

Depends on Phase 3's contract (can be stubbed against Phase 0's draft
schema before Phase 3 is fully done).

- [ ] MITRE ATT&CK mapping: a separate field from finding state, with its
      own justification field. Never promotes a finding's epistemic state
      (§2.4).
- [ ] NIST mapping: same rule, separate field.
- [ ] Seal: hash the completed `ZaynorAuthoritativeResult` (findings +
      mappings), mark it immutable.

**Exit condition:** a sealed, hashed authoritative result ready for the LLM
layer.

## Phase 5 — LLM narrator (required path)

Depends on Phase 4's sealed output (can be developed against a stub sealed
result before Phase 4 is fully wired).

- [ ] Narrator consumes only the sealed `ZaynorAuthoritativeResult` +
      authorized facts — no other input channel.
- [ ] Generates explanation/summary/report/postmortem, adapted by audience.
- [ ] Proposed actions are labeled as proposals, never as findings.
- [ ] Narrative guard: a mechanical check that narrator output cannot write
      back into the authoritative result.
- [ ] Test: `run(case, llm=OFF).authoritative_result ==
      run(case, llm=ON).authoritative_result` for the same frozen evidence
      set (the invariant from `proposal.en.md`).

**Exit condition:** narration is provably read-only with respect to the
authoritative result.

## Phase 6 — LLM investigation assistant (optional path)

Depends on Phase 3 (needs somewhere to route suggested queries back into)
and the existing allowlisted read-only tool registry (§2.3). Build this
after Phase 5 — it's optional, Phase 5 is not.

- [ ] Suggestion mechanism: LLM proposes a read-only query as a
      `CANDIDATE` hypothesis, not a conclusion (§1, §2.2).
- [ ] Route the suggestion through the same hardcoded allowlist as every
      other tool call — no special-casing this path.
- [ ] Any evidence returned goes back through VIGÍA / the deterministic
      adapter before it can change `ZaynorAuthoritativeResult`.

**Exit condition:** enabling/disabling this path never changes the result
for a fixed evidence set — only which evidence gets pulled in.

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

## Sequencing summary

```
Phase 0 (inventory + contract)  ──┐
Phase 1 (front end)   ── Phase 2 (freeze) ──┤
                                             ├── Phase 3 (adapter) ── Phase 4 (frameworks + seal) ── Phase 5 (narrator) ── Phase 6 (investigator, optional)
                                             │                                         ↑ can stub against Phase 0's draft contract before Phase 3 lands
                                             └── (Phase 0 also unblocks stubbed Phase 4/5 work in parallel)
```

Phases 0 and 1 start immediately, in parallel, by different people. Phase 3
is the critical path — nothing downstream is real until it lands, though
Phase 4 and 5 can be built and tested against a stubbed contract in the
meantime so they're not sitting idle.

## Open questions this plan does not answer

- VIGÍA's actual interface (library/CLI/service) — Phase 0's first task,
  needs whoever has access to VIGÍA to fill in.
- Who owns which phase among the four of you, and the actual deadline —
  team logistics, not something to guess at here.
