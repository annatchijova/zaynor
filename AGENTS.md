# AGENTS.md

Operating guide for any AI agent (Claude Code, Codex, or otherwise) with write
access to this repository, and for any human collaborator who wants to know
how agent-assisted work here is expected to look. This file is the contract;
if a PR doesn't follow it, that's a legitimate reason to ask for changes
before reviewing the diff itself.

ZAYNOR investigates a completed, simulated security incident: a local LLM
picks which read-only evidence to inspect next and narrates a reconstruction,
while a small deterministic layer owns every claim that can actually be
verified (hashes, corroboration counts, hypothesis status). Keep that
boundary in mind — it shapes almost every rule below.

## Scope: the hybrid pipeline

ZAYNOR is a hybrid across the full incident lifecycle, not just the
post-incident half — don't read the deterministic/LLM split in §2 as "we
don't do live telemetry":

```
telemetry (synthetic)  ->  detection  ->  correlation/triage  ->  INCIDENT
   ->  evidence collection  ->  local investigation  ->  hypotheses/RCA
   ->  backed finding  ->  response/prevention  ->  postmortem
```

The two halves run on deliberately different-weight engines, split at
`INCIDENT`:

- **Stages 1-3 (telemetry → detection → correlation/triage):** small,
  deterministic, synthetic. A generated/replayed event stream, a threshold or
  pattern rule, and a declarative correlation rule group it into one
  incident. No eBPF, no per-node agents, no Postgres/Redis stack — that's
  production AIOps infrastructure and explicitly out of scope. This is a
  demo-scale front end, not a monitoring platform.
- **Stages 4-10 (incident → … → postmortem):** the actual DFIR core — this
  is where the LLM investigates and where §2's ledger boundary applies in
  full.

If a task touches stages 1-3, it still needs to be genuinely deterministic
and genuinely small — resist the temptation to make the "live" side richer
than the demo needs just because reference platforms (Keep, Coroot, K8sGPT)
do a lot more there. If a task touches 4-10, §2 is binding.

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
  CONFIRMED. Use it before merging anything that touches §2 below, and
  before trusting any finding — including your own from an earlier pass.

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

## 2. Working with the deterministic/LLM boundary

This is the one invariant every contributor needs to internalize before
touching anything past the evidence-ingestion layer:

- **The LLM proposes; it never writes to the ledger.** Any function that sets
  a finding's status (`OBSERVED` / `INFERRED` / `CORROBORATED` /
  `CONTRADICTED` / `UNKNOWN`) takes structured tool-observation evidence as
  input, never raw model output. If you find yourself passing an LLM
  completion straight into something that updates finding status, stop —
  that's the bug this architecture exists to prevent, not a shortcut.
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
- **No float in anything that feeds a ledger status or a hash.** Corroboration
  counts, gate thresholds, and hash inputs use integers/exact types. Floats
  are fine in display-only rendering.
- **A missing or ambiguous result is `UNKNOWN`, not a guess dressed as a
  finding.** Don't let a renderer or a prompt smooth over "we don't actually
  know" into a confident-sounding sentence.

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

**Nobody commits straight to `main`.** The flow is: branch → commit → push →
PR → review → merge. This holds even solo, even at hour 40 — a two-person
team moving fast is exactly when an unreviewed direct push to `main` costs
the most, because nobody else knows it happened.

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
   `main` moves while you work. A PR built on a stale base can silently
   revert whatever landed in the meantime — this is exactly the kind of
   thing that's invisible until the demo breaks the morning of. Rebase even
   when git reports no conflict; a clean textual merge only means the same
   lines weren't touched twice, not that your change still makes sense
   against what arrived.

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
   change touches the LLM/ledger boundary (§2), say explicitly which side of
   that boundary it's on.

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

- [ ] The cause of a bug was verified against the live file, not assumed.
- [ ] The edit was a surgical anchored patch, or a deliberate full write for
      a genuinely new file.
- [ ] Nothing from an LLM completion writes directly to ledger/finding
      status (§2).
- [ ] No new evidence path bypasses the read-only tool allowlist.
- [ ] No float entered a ledger-status or hash computation.
- [ ] An ambiguous or missing result renders as `UNKNOWN`, not a confident
      guess.
- [ ] The branch is rebased on current `main` and PR review status is
      actually `MERGEABLE` / `CLEAN`, not assumed.
- [ ] Tests/lint were actually run and their real output was read.
- [ ] Commit messages follow Conventional Commits; PR description states
      what changed, why, and which side of the LLM/deterministic boundary
      it touches.
