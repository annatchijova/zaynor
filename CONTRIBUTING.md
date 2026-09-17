# Contributing to ZAYNOR

*[Leer en español](CONTRIBUYENDO.md)*

Thanks for wanting to work on ZAYNOR. This is a small, focused project —
this guide is intentionally short.

## Before you start

- ZAYNOR integrates VIGÍA's deterministic engine (`vendor/vigia_engine/`)
  rather than reimplementing it — see `AGENTS.md` §2.1. If your change
  touches anything under `vendor/`, it needs a documented reason; the
  default assumption is that VIGÍA's own logic is not yours to rewrite.
- No float in the decision path (`CLAUDE.md` §5.2). Ratios, weights, and
  anything that feeds a sealed result use `fractions.Fraction`.
- The LLM never decides a verdict (`CLAUDE.md` §5.1). If your change lets
  a model influence a finding, a score, or a seal, the architecture is
  wrong, not the implementation.

## Workflow

1. Read the live file before patching it — don't assume what a function
   does from its name or from memory of an earlier version.
2. One focused change per commit. Explain *why*, not just what.
3. Run the full test suite before proposing a change:
   ```bash
   python3 -m pytest tests/ -q
   ```
4. If you touch `src/zaynor/report.py`, `audit_log.py`, or anything
   sealed/hashed, add a test that would fail if your change broke
   determinism or tamper-evidence — not just a happy-path test.
5. No `git rebase`, no `git push --force`, no squashing history. See
   `CLAUDE.md` §2 for the full git discipline this repo follows.

## Adding a case to `casos/`

Cases come from VIGÍA's own corpus (real, publicly documented incidents,
or the canonical intentionality-vector corpus) — see `casos/README.md`
for what's there and why. A new case should be real VIGÍA output, not
invented content; if you're adding a synthetic fixture instead, it goes
in its own clearly-labeled directory (see `casos-samuel/` for the
convention), not mixed into `casos/`.

## Reporting a security issue

See `SECURITY.md` — do not open a public issue for a vulnerability.

## Code of conduct

See `CODE_OF_CONDUCT.md`.
