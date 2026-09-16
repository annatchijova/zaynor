# AGENTS.md

Operating guide for any AI agent (Claude Code, Codex, or otherwise) with write
access to this repository, and for any human collaborator who wants to know
how agent-assisted work here is expected to look. This file is the contract;
if a PR doesn't follow it, that's a legitimate reason to ask for changes
before reviewing the diff itself.

This file is the *operating* manual — product architecture plus agent
behavior rules. `CLAUDE.md` at the repo root is the separate
*development-discipline* guide (git hygiene, editing discipline, the
abduction/refutation reasoning loop, the Definition of Done checklist). Per
`CLAUDE.md`'s own stated scope, the two are not to be conflated: read
`CLAUDE.md` for how to work in this repo in general, read this file for what
ZAYNOR specifically is and how its architecture constrains a change.
`SYSTEM_PROMPT--ZAYNOR.md` is the single runtime prompt assembled from this
contract and VIGÍA's Peircean reasoning protocol; it cannot override the
repository contracts.

## Hackathon context

ZAYNOR is being built for **Hackathon CyberAr 2026** (I Congreso de
Ciberdefensa, FIE-UNDEF, 16-18 September 2026). The team selected **Eje 2 —
Inteligencia artificial para la defensa de redes e infraestructura**: build
AI-based tooling that detects, prioritizes, and responds to attacks, runs
locally (no external API calls, no data leaves the machine), and
demonstrates resistance to manipulation attempts. Only simulated or public
data is allowed; no testing against real systems. Deliverable is source code
+ README, demoed as a 3-minute pitch + functional demo, then 1 minute of
jury questions — that time budget is why the architecture below is
deliberately small (§ "Scope: the postmortem pipeline").

Source material, in `docs/hackathon/`:

- `reglamento-hackathon-cyberar-2026.md` — general rules (teams, deliverables,
  evaluation rubric, IP, conduct).
- `desafios-cyberar-2026.md` — the three challenge tracks (Ejes) and the
  common conditions; Eje 2 is the one this repo targets.
- `brainstorm/` — the research and architecture-exploration documents that
  produced the design in this file: `deep-research-report.md` and
  `zaynor-informe-arquitectura.md` (the hybrid front/DFIR-core architecture,
  component contracts, VIGÍA/ANNACONDA/OpenHands reuse decisions, the
  `srv-files-01` incident fixture, build plan P0/P1/P2), `dfir-recon-2026-09-15.md`
  (an independent 7-component recon pass with its own `INC-2026-DEMO-001`
  fixture — service-account token leak, not the same story as the informe's
  fixture; the two are alternative fixture proposals, not two parts of one
  story — the team has not yet frozen which fixture ships), and
  `repos-reference.md` (reference platforms: Keep, Coroot, K8sGPT, HolmesGPT,
  plus the team's own VIGÍA/ANNACONDA/SKILLS repos). Treat these as design
  inputs, not as already-decided fact — where they disagree (e.g. the two
  competing incident fixtures), that is an open decision, not an
  inconsistency to silently pick a side on.

ZAYNOR is a postmortem DFIR system built around VIGÍA, an existing
deterministic forensic engine — it does not reimplement VIGÍA's mechanisms
from scratch, and it does not detect, correlate, or replay telemetry
itself. ZAYNOR starts from an incident that is already declared and
evidence that is already collected — both out of scope for this repo (see
"Scope: the postmortem pipeline"). The case is frozen and handed through an
explicit adapter to VIGÍA, which performs the authoritative deterministic
forensic analysis. ZAYNOR then maps supported findings into applicable
frameworks (MITRE ATT&CK, NIST) and seals an authoritative result. A local
LLM consumes that sealed state to explain, summarize, and generate reports
and postmortems for different analyst audiences; it may optionally suggest
further read-only investigative queries, but any resulting evidence has no
effect on the authoritative result until it has crossed back through the
deterministic authority boundary. Keep both boundaries in mind — the
ZAYNOR↔VIGÍA integration boundary and the deterministic↔LLM authority
boundary — they shape almost every rule below. See "Scope: the postmortem
pipeline" for the full picture and §2 for the boundary rules.

## Scope: the postmortem pipeline

ZAYNOR is postmortem, full stop. It does not ingest live or synthetic
telemetry, does not run a detection rule, and does not correlate alerts
into an incident — an incident arriving already declared, with its
evidence already collected, is the input, not something ZAYNOR produces.
Whatever system or process declared the incident and collected the
evidence is out of scope here. ZAYNOR's own pipeline starts at the case
freeze:

```
incident declared (external — a ticket, an alert, an analyst referral;
   out of scope for ZAYNOR) + evidence already collected (out of scope)
   ->  case freeze (manifest + SHA-256, immutable case_id)
   ->  VIGÍA adapter  ->  deterministic forensic analysis (VIGÍA)
   ->  authoritative ZAYNOR result  ->  MITRE ATT&CK / NIST contextualization
   ->  seal  ->  local LLM narration  ->  incident report / postmortem
```

Optional, read-only branch back into the deterministic side (§2.2):

```
authoritative ZAYNOR result
   ->  LLM investigative suggestion  ->  allowlisted read-only query
   ->  evidence  ->  VIGÍA / deterministic re-analysis
   ->  updated authoritative ZAYNOR result
```

- **The case-freeze boundary:** the dedicated step (the case freezer) that
  selects an already-declared incident's already-collected evidence records,
  hashes every artifact, writes a manifest, and closes the bundle to writes
  before handing it to VIGÍA. This is not a metaphor — it's a real, small
  piece of code, and it's what "the evidence is frozen" actually means in
  this repo. It is ZAYNOR's first stage, not the tail end of a detection
  pipeline.
- **Everything after the freeze (VIGÍA adapter → … → postmortem):** the DFIR
  and reporting core. Authoritative forensic analysis is deterministic and
  lives in VIGÍA; ZAYNOR owns the adapter, the MITRE/NIST
  contextualization, the seal, and the local LLM's narration and optional
  investigation-assistant role. §2's authority boundaries apply in full
  here — which, for ZAYNOR, is everything past the freeze.

A task that proposes telemetry replay, a detection rule, or a correlation
step is out of scope by construction, no matter how small — that is a
different system's job, upstream of ZAYNOR's input.

## 0. Language and scope

- **Code, tests, comments, docstrings, commit messages, PR titles/
  descriptions: English, always — no exceptions for a hackathon deadline,
  no exceptions because a teammate is more comfortable writing Spanish
  inline.** If you find a non-English identifier, string constant, or
  comment in application code (not user-facing demo strings), that's a
  defect — flag it or fix it in the same PR.
- The demo output and the incident report itself are user-facing and go in
  Spanish (see `README.md` for the exact split) — don't "fix" that to English.
- No emojis in anything committed to the repo.

## 1. Reasoning discipline

Two skills ship under `.claude/skills/` and load automatically for Claude
Code; any agent working here is expected to apply their method even if its
own tooling doesn't auto-load skills:

- **`abductive-engineering`** — the reasoning loop for every non-trivial
  diagnosis, review, or design decision: observe without interpreting, name
  the baseline, then abduce → deduce → induce before calling anything a root
  cause. §1 below is this loop applied specifically to this repo.
- **`red-team-auditing`** — the adversarial counterpart, for auditing your
  own or anyone else's changes: a finding is PLAUSIBLE until a deduced
  consequence has actually been run against the live code, only then
  CONFIRMED.

**Hard rule: no commit, ever, without having run `red-team-auditing`
against your own diff first.** Not "before merging" — before the commit
exists at all. Adversarially check your own change (does it actually do
what it claims, does it break §2, did it silently drop something) before
`git commit`, not after someone else flags it in review. Same for
`abductive-engineering` on any diagnosis or fix: don't commit a "fix" for a
cause you haven't verified against the live code.

These two exist specifically so that "move fast for the demo" doesn't turn
into a repo full of code nobody actually verified. Don't skip them because
the deadline is close — they're the reason a fast pace stays reviewable.

Before writing a fix or a "the bug is X" comment on a PR:

1. **Say what you actually observed** — the failing assertion, the exact
   tool-call trace, the literal ledger entry — before naming a cause.
2. **Name what "correct" looks like** for that spot. If you can't state the
   baseline, you don't understand the bug yet; go find the contract (a test,
   a docstring, the ledger schema) that defines it.
3. **Treat your first explanation as a hypothesis**, not a conclusion, until
   you've run something that would fail if you were wrong. "I looked and the
   evidence-store already rejects that path" is a complete, useful answer —
   don't turn a non-bug into a diff because a PR needs to exist.
4. Before proposing a change that touches an LLM prompt or an evidence
   ingestion path: ask whether the boring explanation survives first — the
   guard already exists three lines up, the parser already normalizes that
   case, the "gap" is actually intentional because that field is derived
   downstream. Most confident findings against this codebase die right here.

## 2. Authority boundaries: ZAYNOR ↔ VIGÍA ↔ LLM

Two boundaries every contributor needs to internalize before touching
anything past the case freeze:

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
 (required: narrator — §2.2)
 (optional: investigation assistant, read-only, no authority — §2.2)
```

### 2.1 VIGÍA reuse boundary

VIGÍA is an existing engine, not a design document to be reimplemented.

- If a required deterministic capability already exists in VIGÍA with
  suitable semantics, integrate it through an explicit adapter. Do not
  create "VIGÍA-inspired", "minimal", "simplified", or "hackathon-sized"
  replacements merely because a local reimplementation looks easier in the
  moment.
- A reimplementation requires a documented reason in the PR description
  showing why the existing VIGÍA mechanism cannot satisfy the ZAYNOR
  integration contract — "it was faster to write from scratch" is not that
  reason.
- ZAYNOR code must not depend on VIGÍA's internal object graph beyond the
  adapter boundary. Translate VIGÍA's output into a stable
  `ZaynorAuthoritativeResult` contract and code against that, not against
  VIGÍA internals.

### 2.2 The LLM's two roles

- **Narrator (required path).** Once ZAYNOR seals an authoritative result,
  the local LLM consumes the sealed, authorized facts to explain, summarize,
  adapt by audience, and draft reports/postmortems. It can propose actions,
  clearly labeled as proposals. It cannot add facts — nothing it writes
  changes the authoritative result.
- **Investigation assistant (optional path).** The LLM may suggest an
  additional read-only investigative query. That suggestion has no forensic
  authority by itself: any evidence it turns up goes back through VIGÍA /
  the deterministic authority boundary before it can affect an authoritative
  finding. Treat a suggestion the way §1 treats a hypothesis — a candidate,
  not a conclusion.

### 2.3 Claim-state and evidence rules

- **The LLM proposes a claim with typed predicates; it never proposes a
  verdict.** The model doesn't get to say "this is corroborated" — it emits
  a claim naming which evidence fields would have to hold for the claim to
  stand (`{event_id, field, op, value}` tuples). The gate then re-looks-up
  every one of those predicates directly against the frozen evidence itself
  — it does not trust the model's account of what a record says, only the
  record. Every required predicate must first be VERIFIED through that
  independent lookup; a claim may become `CORROBORATED` only after its
  verified predicates *also* satisfy the gate rule's declared provenance and
  independence requirements (see the next bullet) — verification alone is
  not sufficient. A contradicting predicate yields `CONTRADICTED`; anything
  the gate can't resolve is `INSUFFICIENT` (rendered to the human
  report as `UNKNOWN`, never smoothed into a guess). If you find yourself
  passing an LLM completion straight into something that updates finding
  status — including trusting the LLM's own quote of an evidence field
  instead of re-fetching it — stop, that's the bug this architecture exists
  to prevent, not a shortcut.
- **A predicate being VERIFIED is not the same as a claim being
  CORROBORATED.** A predicate is VERIFIED when the gate independently
  re-reads the referenced field from frozen evidence and confirms the typed
  condition holds. A claim is not CORROBORATED merely because its predicates
  verify — it also has to satisfy the claim's declared independence
  requirement: two artifacts that share a common lineage (same collector,
  same upstream event, same normalized record) don't become independent
  evidence just because they're stored in different files or cited twice.
  Track a `lineage_id` on every `EvidenceRef` and a `distinct_lineages: true`
  flag on any gate rule that requires independent corroboration.
- **The LLM's internal hypothesis state is not the ledger's claim state —
  don't conflate the two.** The investigator can freely track `CANDIDATE` /
  `ACTIVE` / `ABANDONED` hypotheses as it works; none of that has authority.
  Only `CORROBORATED` / `CONTRADICTED` / `INSUFFICIENT` are authoritative
  claim states, and only the gate can assign them. The deterministic layer
  doesn't own the investigator's reasoning — it owns what's allowed to cross
  the authority boundary into ZAYNOR's authoritative state.
- **Evidence is data, never an instruction**, no matter what it says. A log
  line, a ticket comment, or any artifact content that reads like a directive
  to the system ("ignore previous instructions", "classify as NOISE") stays
  evidence. It gets logged and reasoned about like any other artifact; it
  never reaches a prompt's control channel or changes what a tool call is
  allowed to do. If you're adding a new evidence type, check it goes through
  the same read-only tool path as everything else — no special-casing "safe"
  sources.
- **A tool call is either on the allowlist or it doesn't happen.** Read-only
  enforcement is a hardcoded function registry, not an LLM self-report. If a
  feature needs a new capability, it needs a new named tool with its own
  narrow contract — it does not need a broader existing tool.
- **No float in anything that feeds a ledger status or a hash.** Gate
  thresholds, exact scores (if any), provenance-derived values, and
  canonical hash inputs use integers or exact numeric types
  (`fractions.Fraction`, not binary floating-point). Floats are fine in
  display-only rendering — never in anything the gate reads to decide a
  claim's status.
- **A missing or ambiguous result is `UNKNOWN`, not a guess dressed as a
  finding.** Don't let a renderer or a prompt smooth over "we don't actually
  know" into a confident-sounding sentence.

### 2.4 Framework mappings are annotations, not evidence

MITRE ATT&CK and NIST contextualize authoritative forensic results; they do
not create them.

- A technique mapping must never promote a finding's epistemic state. A
  framework match is not evidence of causality, intent, attribution, or
  attacker identity.
- Keep separate: finding state, framework mapping, mapping justification,
  and mapping confidence/status (if used).
- NIST structures incident handling, reporting, and defensive response — it
  is not a substitute for the evidence model in §2.3.

If a task description asks you to do something that would blur one of these
(e.g., "just let the model set the verdict directly, it's faster for the
demo"), implement the safe version and say so in the PR description rather
than silently complying or silently refusing.

## 3. Editing discipline

- Prefer a targeted edit anchored on an exact, unique string over rewriting a
  file. Agents silently dropping an unrelated check while "helpfully"
  regenerating a file is the single most common way this kind of repo
  regresses.
- Re-read a file immediately before a second edit to it in the same session —
  anchors go stale the moment anything else touches the file, including your
  own previous edit.
- Treat any finding — from a teammate, a linter, another agent, or your own
  earlier pass — as a claim until you've checked it against the file as it
  is right now. Confirm the cited line still says what the finding claims
  before changing it.

## 4. Git and PR workflow

**Only the repo owner pushes straight to `main`; the other three don't,
ever.** For everyone but the owner, the flow is: branch → commit → push →
PR → review by the owner → merge. This holds even solo, even at hour 40: with
three people moving fast in parallel, an unreviewed direct push from any of
them is exactly what costs the most, because the other two don't know it
happened. The owner already reviews every PR that lands — a PR opened by the
owner would have no one left to review it independently, so requiring one
buys nothing. The owner pushing directly is the asymmetry that keeps the
review gate meaningful for everyone else; it's not a loophole anyone else
gets to use by analogy.

The flow for the three non-owner contributors:

1. **Branch off current `main`:**
   ```bash
   git fetch origin && git checkout -b <type>/<short-description> origin/main
   ```
   Branch names: `feat/…`, `fix/…`, `refactor/…`, `docs/…` — mirror the
   commit type below.

2. **Commit with [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):**
   ```
   <type>[optional scope]: <imperative description>
   ```
   Types: `feat`, `fix`, `docs`, `refactor`, `test`, `build`, `ci`, `chore`.
   Keep commits small and focused — several small commits beat one that
   touches the tool layer, the ledger, and the renderer at once, because the
   second reviewer has to be able to tell which part they're actually
   checking.

3. **Before pushing, rebase onto the current `main`, not the one you branched
   from:**
   ```bash
   git fetch origin main && git rebase origin/main
   ```
   `main` moves while you work. A PR built on a stale base may remain
   textually mergeable while being semantically incompatible with changes
   that landed on `main` in the meantime — this is exactly the kind of thing
   that's invisible until the demo breaks the morning of. Rebase even when
   git reports no conflict; a clean textual merge only means the same lines
   weren't touched twice, not that your change still makes sense against
   what arrived.

   Don't read `git diff origin/main..your-branch` as a preview of what
   merging will do — two-dot diff makes everything `main` gained since you
   branched look like a deletion in your PR. If you need certainty, check it
   for real in a scratch worktree rather than reasoning about it:
   ```bash
   git worktree add -q --detach /tmp/merge-check origin/main
   cd /tmp/merge-check && git merge --no-commit --no-ff origin/<your-branch>
   git diff --cached --stat HEAD
   ```

4. **Push and open the PR:**
   ```bash
   git push -u origin <branch-name>
   gh pr create --base main --head <branch-name> --title "<type>: <summary>" --body "<what changed and why>"
   ```
   The PR description says what changed and why, not just what — and if the
   change touches the ZAYNOR/VIGÍA or deterministic/LLM boundary (§2), say
   explicitly which side of that boundary it's on.

5. **Review and merge.** Address feedback with new commits on the same
   branch — don't rewrite history mid-review unless the reviewer asks for it.
   Prefer squash merge so `main` gets one clean commit per PR. Delete the
   branch after merging.

**Forbidden in any agent session:** `git rebase -i`, history-rewriting
squash outside the merge step above, and `git push --force`
(`--force-with-lease` included) to any shared branch. Only forward-only
operations (`commit`, `merge`, `revert`, and the plain non-interactive
`rebase` in step 3 above, which rewrites only your own unpushed branch).

Before claiming a repo state ("pushed", "merged", "tests pass"), actually run
`git status --short` / `git log --oneline -n 10` / the test command and read
the real output. Don't report from memory of what you intended to do.

## 5. Verification before claims

Run the real command; don't infer results from reading the code.

```bash
# adjust to whatever the chosen stack ends up being — keep this section
# updated as soon as the test/lint commands are decided, this placeholder
# is here so the section isn't silently skipped
pytest -q
ruff check .
```

A green run is reported with what it actually covers — "the tool-layer
allowlist tests pass" is useful, "tests pass" as an unqualified claim about
correctness in general is not. If something couldn't be tested (no access to
the model backend, no time to write the adversarial-evidence test), say so
in the PR instead of letting a green checkmark imply more than it proves.

## 6. Definition of done

- [ ] `red-team-auditing` was run against this diff before committing it,
      not after.
- [ ] The cause of a bug was verified against the live file, not assumed.
- [ ] The edit was a surgical anchored patch, or a deliberate full write for
      a genuinely new file.
- [ ] No existing VIGÍA mechanism was reimplemented without a documented
      incompatibility with the ZAYNOR integration contract (§2.1).
- [ ] VIGÍA internals do not leak past the adapter boundary.
- [ ] Nothing from an LLM completion writes directly to authoritative
      state/finding status (§2).
- [ ] Authoritative ZAYNOR state can be regenerated without an LLM;
      disabling the LLM narrator does not change deterministic findings for
      the same evidence set.
- [ ] No claim became `CORROBORATED` from predicate verification alone when
      its gate rule requires provenance/independence constraints.
- [ ] Evidence references preserve `lineage_id`; duplicated or derived
      artifacts are not counted as independent corroboration.
- [ ] No new evidence path bypasses the read-only tool allowlist.
- [ ] No float entered a ledger-status or hash computation.
- [ ] An ambiguous or missing result renders as `UNKNOWN`, not a confident
      guess.
- [ ] MITRE/NIST mappings do not promote or modify finding state (§2.4).
- [ ] Narrative output cannot modify the sealed authoritative result.
- [ ] The branch is rebased on current `main` and PR review status is
      actually `MERGEABLE` / `CLEAN`, not assumed.
- [ ] Tests/lint were actually run and their real output was read.
- [ ] Commit messages follow Conventional Commits; PR description states
      what changed, why, and which side of the ZAYNOR/VIGÍA/LLM boundary it
      touches.
