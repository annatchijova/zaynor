# Security and Quality Audit — `feat/freebsd-evidence-importers`

**Date:** 2026-10-01
**Auditor:** Claude Code (Sonnet 5), adversarial self-review requested by the repository owner
**Method:** Abductive Engineering (A-D-I loop) + Red-Team Auditing discipline
**Base:** `main` @ merge-base with `feat/freebsd-evidence-importers`
**Head:** `41ef62c` ("feat(freebsd): add bounded offline evidence importers")
**Scope:** The single commit on this branch — 16 files, 2248 insertions, 0 deletions:
`tools/offline_evidence.py`, `tools/freebsd_evidence/*`, `tools/rootkit_scanner_reports/*`,
their tests, `docs/adr/0004-*.md`, `CHANGELOG.md`, and an 18-line addition to the existing
`scripts/docs_check.py` doc-sync gate.
**Out of scope:** Unrelated uncommitted changes already present in the working tree at
audit time (`INSTALL.md`, `SECURITY.md`, `SEGURIDAD.md`, `docs/design-references*.md`,
`build/`, `vendor/__init__.py`, `vendor/vigia_engine/__init__.py`, two files under
`visual/`). These predate this session, are not part of the branch's commit, and were left
untouched per this repository's editing discipline (investigate, never overwrite
in-progress work).

## Threat model

- **Attacker CAN:** supply an arbitrary, fully attacker-controlled package JSON and
  arbitrary file contents under the declared `source_root` (the acquisition directory),
  including malformed UTF-8, deeply nested JSON, oversized files, symlinks, path-traversal
  segments, duplicate keys, `NaN`/`Infinity` literals, and crafted chkrootkit/rkhunter
  report text designed to look like control instructions.
- **Attacker CANNOT:** modify the importer code itself, run arbitrary code inside the
  importer process, hold a concurrent write race against the same filesystem path during
  the single-threaded import run (see F-1 for the residual caveat on this), or influence
  the pre-existing `freeze_case()` boundary (`src/zaynor/case_freezer.py`), which this
  branch calls but does not modify.
- **Trust boundary crossed:** untrusted, already-acquired bytes and a JSON manifest
  describing them → staged, hashed, typed observations frozen into the case evidence
  directory.

## Epistemic legend

CODE FACT · PLAUSIBLE HYPOTHESIS · CONFIRMED BY INDUCTION · FALSIFIED

## Executive summary

| ID | Severity | Level | Module | Finding |
|----|----------|-------|--------|---------|
| F-1 | Low | FIXED (was PLAUSIBLE HYPOTHESIS) | `tools/offline_evidence.py` | Residual TOCTOU window between the pre-open symlink-component check and the final `O_NOFOLLOW` open, on intermediate path components of `source_root` — closed with an atomic `dir_fd` component walk |
| F-2 | Informational | CODE FACT | `tools/offline_evidence.py` | `MAX_OBSERVATIONS` is enforced *after* each append rather than before, so the in-memory list can transiently exceed the limit by one entry before the call aborts |
| F-3 | Informational | CODE FACT | ADR 0004 / importers | Scope is deliberately narrow (2 scanner dialects, no BSM parsing, `analysis_unsupported` always) — this is a documented design choice, not a gap |

No finding in this audit reached CONFIRMED severity Medium or above. No finding blocks merge.

## Findings

### F-1 — Residual TOCTOU on intermediate path components — FIXED

**Severity:** Low **Epistemic level:** PLAUSIBLE HYPOTHESIS (not executed) → **CODE FACT (fixed by construction)** **Bucket:** threat-model assumption

> **Update (2026-10-01, same day):** closed in `tools/offline_evidence.py`.
> `read_original()` now opens `source_root` and every path component through
> `_open_regular_no_symlinks()`, which walks the path one component at a time
> with `os.open(part, O_NOFOLLOW, dir_fd=parent_fd)`. Each lookup is relative
> to an already-open parent directory descriptor, so the "is this a
> symlink?" check and the open of that same component are a single syscall —
> there is no longer a separate check-then-open step for an attacker to win a
> race against, on any platform where `os.open` supports `dir_fd` (Linux,
> confirmed in this environment; POSIX generally). A component that is a
> symlink fails with `ELOOP`, mapped back to the same
> `"source path contains a symlink"` error the tests already assert on. A
> resolve-then-check fallback (textually identical to the prior
> implementation, same residual race window) is kept only for a platform
> where `os.open` does not support `dir_fd`.
>
> This is reported as a **CODE FACT**, not as "CONFIRMED BY INDUCTION of a
> fixed race": per this repository's red-team-auditing discipline, a
> genuine race-condition PoC was not built (and is not practical to build
> deterministically for a single-pass CLI invocation). The claim here is
> narrower and verifiable by reading the code: the check-then-open pattern
> that created the race no longer exists on the primary path. Full test
> suite re-run after the change: 39/39 new tests, 434/434 total, 1 skipped —
> identical to the pre-fix run, no regression.
>
> Original finding preserved below for the record.

- **Surprise / expectation violated:** `read_original()` (`tools/offline_evidence.py:262`)
  checks that `source_root` and every intermediate component of the relative path are not
  symlinks (`_reject_symlink_components`), then separately resolves and opens the final
  file with `O_NOFOLLOW`. Between the component check and the open, nothing holds a lock
  on the directory tree.
- **Abduction:** if an attacker (or a concurrent process) can replace a directory
  component with a symlink after the check but before the `os.open()` call, the open could
  follow a path the check believed was clean. `O_NOFOLLOW` only guards the final path
  component, not the directories walked to reach it.
- **Deduction:** this would require the attacker to win a race against the importer's
  own process, on the same host, during the single import invocation — i.e. the attacker
  already has local filesystem write access to the acquisition directory at the moment of
  import.
- **Induction:** not run. A reliable race-condition PoC against a single-pass,
  short-lived CLI invocation is expensive to build and, given the precondition below,
  low-value; this is reported as a hypothesis, not a confirmed bypass.
- **Threat-model precondition:** the importer's own design assumption is that
  `source_root` holds **already-acquired, static** evidence bytes (ADR 0004: "Inputs are
  bounded, digest-verified regular files"). An attacker who can race the filesystem during
  import already has write access to the evidence before it is hashed and frozen, which is
  a stronger position than the import boundary is meant to defend against. This is the
  same residual class of risk present in most POSIX tools that defend against symlink
  attacks without `openat2(RESOLVE_NO_SYMLINKS)` (not portably available from Python's
  stdlib).
- **Recommendation (non-blocking):** acceptable as shipped. If ZAYNOR ever imports
  from a directory under write access by a lower-trust principal than the importer process,
  revisit with `os.open(..., O_NOFOLLOW | O_DIRECTORY)` walks or a platform-specific
  `openat2` binding.

### F-2 — Observation-count bound checked after append

**Severity:** Informational **Epistemic level:** CODE FACT **Bucket:** hygiene

- In `tools/offline_evidence.py:420` (`finish_staging`) and in both importers'
  per-line loops, `MAX_OBSERVATIONS` is enforced with `if len(observations) > MAX_OBSERVATIONS: raise`
  **after** the list already grew by one. The overshoot is bounded (at most one entry per
  check site) and the function raises before any further work, so this is not an
  exploitable resource-exhaustion vector — `MAX_FILES` (256) and `MAX_FILE_BYTES`
  (16 MiB) already bound the total input far below where a one-entry overshoot matters.
  Noted for precision only.

### F-3 — Deliberately narrow scope

**Severity:** Informational **Epistemic level:** CODE FACT **Bucket:** hygiene / design

- Only `chkrootkit 0.59/C` and `rkhunter 1.4.6/C` are parsed into typed observations;
  every other dialect is preserved as raw bytes with an `unsupported_scanner_dialect`
  limitation and `status="unknown"`. BSM audit bytes are inventory-only
  (`bsm_parser_unavailable`). This is stated in ADR 0004 and enforced by the code
  (`_SUPPORTED_DIALECTS`, `_KINDS`/limitation tags) — not a false claim of coverage. No
  finding; recorded so the executive summary accounts for every row in the table above.

## Discarded (non-exploitable) vectors

| Vector | Result | Why it failed |
|---|---|---|
| Path traversal via `..` or absolute `source_path` / `logical_path` | Falsified | `validate_relative_path()` rejects absolute paths, `..` segments, and empty/`.` segments; covered by `test_rejects_digest_mismatch_path_escape_symlink_and_float` and `test_rejects_report_path_escape_and_boolean_exit_status` |
| Symlinked `source_root`, intermediate symlink, or symlinked package JSON | Falsified (for a static filesystem) | `_reject_symlink_components`, `O_NOFOLLOW`, and `is_symlink()` checks on every component; see F-1 for the race-only residual |
| JSON duplicate keys silently overwriting a field | Falsified | `object_pairs_hook=_unique_json_object` raises on any duplicate key |
| `NaN`/`Infinity` entering a frozen record | Falsified | `parse_constant=_reject_json_constant` on load; `_reject_binary_floats` also rejects any Python `float` recursively before any canonical write |
| Digit-string integer DoS (`int("9"*N)` for huge N) | Falsified | CPython's own integer-string conversion limit raises `ValueError`, caught and wrapped; covered by `test_package_loader_rejects_duplicate_keys_and_excessive_depth` |
| Deep JSON nesting exhausting the Python stack or bypassing depth bounds | Falsified | `_reject_binary_floats` walks iteratively (explicit stack, not recursion) and enforces `MAX_VALUE_DEPTH=32`; `json.loads`'s own `RecursionError` is caught too |
| Oversized package/file silently truncated instead of rejected | Falsified | Both `load_package_json` and `read_original` read one byte past the limit and raise if the limit is exceeded, and re-`fstat` after reading to detect concurrent mutation |
| Cross-module path collision in `combine_staged_evidence` | Falsified | duplicate `relative_path` across staged modules raises `OfflineEvidenceError`; covered by the combined-case integration test |
| Non-determinism across two imports of the same input (re-run, re-freeze) | Falsified | `test_combines_both_modules_before_one_case_freeze` asserts `manifest.content_sha256 == manifest_again.content_sha256` across two independent import/freeze runs |
| Scanner-report text treated as an instruction / injected into control flow | Falsified | Report bytes only ever populate bounded string fields inside JSON observations (`raw_line`, `detail`, etc.); nothing in the importer or `make_observation()` interprets content as code or shell input |
| ReDoS via the chkrootkit/rkhunter line regexes | Falsified by inspection | Neither `_CHKROOTKIT_LINE` nor `_RKHUNTER_LINE` contains nested or overlapping quantifiers; both are bounded to `MAX_TEXT_LINE_CHARS` (16 384) per line before matching |

## Verification performed

- Read every new/changed file in full (`tools/offline_evidence.py`,
  `tools/freebsd_evidence/*`, `tools/rootkit_scanner_reports/*`, both tool `README.md`s,
  ADR 0004, the `CHANGELOG.md` entry, and the `scripts/docs_check.py` diff).
- Read the pre-existing `freeze_case()` boundary (`src/zaynor/case_freezer.py`) this
  branch calls into, to confirm the branch does not weaken it — it does not; the file is
  unmodified by this branch.
- Ran the new test files in isolation:
  `tests/test_offline_evidence.py`, `tests/test_freebsd_evidence.py`,
  `tests/test_rootkit_scanner_reports.py`, `tests/test_docs_check.py` — **39 passed**.
- Ran the full repository test suite — **434 passed, 1 skipped**, no regressions
  attributable to this branch.
- Cross-checked ADR 0004's claimed security properties against the actual code line by
  line (bounded JSON, digest verification, symlink/`..` rejection, no-float enforcement,
  `analysis_unsupported` status) — every claim in the ADR's "Security and epistemic
  constraints" section matches the live implementation.

## Decision

**Recommend merge.** This branch adds a narrowly scoped, defensively written, and
honestly documented import boundary. It follows this repository's own architectural
invariants (deterministic core, no float in any sealed/decision path, LLM out of the
decision path, honest degradation via `analysis_unsupported` and typed `limitations`)
without modifying or weakening the existing `case_freezer` / chain-of-custody boundary.
Test coverage specifically targets the adversarial cases that matter for an evidence
importer (path escape, symlinks, digest mismatch, duplicate keys, `NaN`, depth bombs,
digit-string DoS, determinism across re-runs). No finding in this audit rises above Low
severity, and the one Low finding (F-1) is a precondition-gated, industry-standard
residual that the module's own design already assumes away.

**Process note:** this repository's `CLAUDE.md` (§2) prohibits direct pushes to `main`;
every change must land through branch → PR → review → merge. This audit document is
therefore being committed to this same feature branch and submitted as part of its pull
request, rather than pushed to `main` directly.
