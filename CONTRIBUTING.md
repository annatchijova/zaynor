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
3. Write commits in [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
   format — `<type>[optional scope][!]: <imperative description>` — with one
   of `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `perf`,
   `ci`, `build`, `security`, `revert` (the full list enforced by
   `scripts/commitlint.py` — `ALLOWED_TYPES` is the source of truth). Examples:
   `feat(core): add new evidence profile`,
   `fix(telemetry): correct OTel span naming`,
   `feat(frontend): establish forensic analysis interface`.
   The `commit-msg` hook (`scripts/commitlint.py`, installed via
   `./scripts/install-hooks.sh`) rejects non-conforming headers; the few
   pre-gate headers it grandfathers are listed in `.commitlint-allowlist`.
   `Merge ...` / `Revert ...` headers pass untouched.
4. Propose tests with every change. Tests should cover intended behavior,
   boundary conditions, negative cases, and relevant adversarial cases. A
   pull request without a test proposal is incomplete.
5. Keep the docs in sync with the code. Changing a file that a document
   contracts (the CLI, the API, the agents, the VIGÍA adapter, the seal,
   the MCP tools, the frontend, the SDLC tooling) requires updating that
   document in the same change. Which code parts contract which docs is
   `DOCS_MAP` in `scripts/docs_check.py` — the single source of truth;
   extend it when you add a part that has a doc contract.    Enforcement is mechanical:
   - the `pre-push` hook runs `scripts/docs_check.py` over the range
     being pushed (installed by `./scripts/install-hooks.sh`);
   - CI runs the same gate on every PR and on every direct push to
     `main` (`docs-sync` job).
   A rule can be waived deliberately with a commit trailer in the final
   paragraph of the commit message — `Docs-Waiver: <rule-id> <reason>` —
   per rule, visible in git history, never silent. Only a trailer in
   trailer position counts: an illustrative `Docs-Waiver:` line inside
   body prose or a code fence is not a waiver. Run the gate locally at
   any time:
   ```bash
   python3 scripts/docs_check.py --base origin/main   # branch diff vs main
   python3 scripts/docs_check.py --staged             # what is staged now
   ```
6. Set up the local gates once per clone:
   ```bash
   pip install -e ".[dev]" && pip install pre-commit
   ./scripts/install-hooks.sh   # commit-msg (commitlint) + pre-push (force-push guard + docs-sync)
   pre-commit install           # whitespace/EOF/YAML/TOML/JSON hygiene
   ```
   If you cloned before a hook update landed, re-run
   `./scripts/install-hooks.sh --force` to pick it up (otherwise the old
   hook keeps running and only the CI gate enforces the new check).
   Then run the verification suite before proposing a change:
   ```bash
   python3 -m pytest tests/ -q
   ruff check src tests scripts conftest.py
   ```
   `black --check src tests scripts conftest.py` and `mypy src/zaynor/`
   are advisory (the tree predates formatting; 20 pre-existing mypy notes
   are tracked in `pyproject.toml [tool.mypy]`). Match surrounding style
   in files you touch, fix new mypy notes there, but neither gates a merge.
7. If you touch `src/zaynor/report.py`, `audit_log.py`, or anything
   sealed/hashed, add a test that would fail if your change broke
   determinism or tamper-evidence — not just a happy-path test.
8. No `git rebase`, no `git push --force`, no squashing history. See
   `CLAUDE.md` §2 for the full git discipline this repo follows. (The
   `pre-push` hook enforces the force-push ban mechanically.)

## Releases (SemVer + Keep a Changelog)

- Versioning follows [SemVer](https://semver.org/spec/v2.0.0.html):
  `MAJOR` breaks the public interface or evidence semantics (CLI surface,
  sealed-result contract, manifest/seal format); `MINOR` adds
  backward-compatible functionality (commands, roles, evidence profiles,
  framework annotations); `PATCH` fixes bugs or docs.
- Every user-facing change adds an entry under `CHANGELOG.md`
  `## [Unreleased]`, grouped as `Added` / `Changed` / `Fixed` /
  `Security` / `Removed`, per [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
- The maintainer cuts a release by moving `Unreleased` entries under a
  `## [x.y.z] - YYYY-MM-DD` header, bumping `version` in
  `pyproject.toml`, and tagging `vX.Y.Z`.

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
