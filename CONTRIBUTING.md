# Contributing to ZAYNOR

*[Leer en español](CONTRIBUYENDO.md)*

Thanks for wanting to work on ZAYNOR. ZAYNOR grows from VIGÍA into a large,
useful forensic system with a long-term maintenance commitment. Contributions
should help preserve that usefulness as the project evolves.

## Before you start

- ZAYNOR integrates VIGÍA's deterministic engine (`vendor/vigia_engine/`)
  rather than reimplementing it — see `AGENTS.md` §2.1. If your change
  touches anything under `vendor/`, it needs a documented reason; the
  default assumption is that VIGÍA's own logic is not yours to rewrite.
- Do not touch the scorer or its decision contract. Scorer changes require a
  separately documented, explicitly approved architectural decision.
- No float in the decision path (`CLAUDE.md` §5.2). Ratios, weights, and
  anything that feeds a sealed result use `fractions.Fraction`.
- The LLM never decides a verdict (`CLAUDE.md` §5.1). If your change lets
  a model influence a finding, a score, or a seal, the architecture is
  wrong, not the implementation.

## Workflow

1. Read the live file before patching it — don't assume what a function
   does from its name or from memory of an earlier version.
2. One focused change per commit. Explain *why*, not just what.
3. Propose tests with every change. Tests should cover intended behavior,
   boundary conditions, negative cases, and relevant adversarial cases. A
   pull request without a test proposal is incomplete.
4. Run the full test suite before proposing a change:
   ```bash
   python3 -m pytest tests/ -q
   ```
5. If you touch `src/zaynor/report.py`, `audit_log.py`, or anything
   sealed/hashed, add a test that would fail if your change broke
   determinism or tamper-evidence — not just a happy-path test.
6. No `git rebase`, no `git push --force`, no squashing history. See
   `CLAUDE.md` §2 for the full git discipline this repo follows.

## Adding cases and adversarial coverage

Cases must be documented and traceable. The corpus should include adversarial,
break, benign, false-positive (FP), and false-negative (FN) cases, not only
successful detections. Include authorized, documented sources such as NIST,
Digital Corpora, DFRWS, DEF CON DFIR CTF, and other explicitly authorized
repositories or datasets.

A new case should be reproducible VIGÍA/ZAYNOR output, not invented evidence.
Synthetic fixtures are welcome for tests, but must be clearly labeled and
kept separate from real cases. Document the source, authorization, expected
behavior, and case category.

## Reporting a security issue

For security vulnerabilities, email `anna.tchijova@icloud.com`; do not open a
public issue or rely on a public security-advisory workflow.

## Code of conduct

See `CODE_OF_CONDUCT.md`.
