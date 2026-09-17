# Changelog

All notable changes to ZAYNOR are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html):

- `MAJOR`: breaks ZAYNOR's public interface or evidence semantics
  (CLI surface, sealed-result contract, manifest or seal format).
- `MINOR`: adds functionality in a backward-compatible manner
  (new commands, roles, evidence profiles, framework annotations).
- `PATCH`: backward-compatible bug fixes and documentation changes.

Entries are grouped per release under `Added` / `Changed` / `Fixed` /
`Security` / `Removed`, newest first. The authoritative history remains
the git log; this file curates it.

## [Unreleased]

### Added

- SDLC gate: `scripts/commitlint.py` (stdlib-only Conventional Commits
  validator, no Node required), installed as the `commit-msg` hook by
  `scripts/install-hooks.sh`, with the pre-gate history it grandfathers
  listed in `.commitlint-allowlist`.
- SDLC config: `[tool.ruff]` / `[tool.black]` / `[tool.mypy]` /
  `[tool.pytest.ini_options]` / `[tool.coverage.*]` sections in
  `pyproject.toml`, plus a `[project.optional-dependencies]` `dev` extra
  (`pip install -e ".[dev]"`), and a network-independent
  `.pre-commit-config.yaml` scoped to files this repo owns.
- SDLC docs: commit, hook, and release workflow in `CONTRIBUTING.md` /
  `CONTRIBUYENDO.md`; verification commands in `AGENTS.md` section 5.
- SDLC gate: `scripts/docs_check.py` (stdlib-only docs-sync gate). A code
  change under a `DOCS_MAP` rule must update the docs that contract it in
  the same branch; enforced by the `pre-push` hook over the pushed range
  and by a `docs-sync` CI job on PRs and on direct pushes to `main`.
  Deliberate per-rule exemptions via a `Docs-Waiver: <rule-id> <reason>`
  trailer in the final paragraph of the commit message (only trailer
  position counts — an illustrative line mid-body is not a waiver);
  gate semantics and trailer parsing tested in `tests/test_docs_check.py`.

## [0.1.0] - 2026-09-17

First tagged release: everything on `main` up to and including the
red-team round 18 audit report. The project has no earlier tags; this
release baselines the post-hackathon tree as `0.1.0` (pre-1.0 API:
`MINOR`/`PATCH` discipline applies, `MAJOR` stays `0` until the sealed
contracts stabilize).

### Added

- Postmortem DFIR pipeline: `freeze` / `analyze` / `audit` over an
  already-declared incident and already-collected evidence, with a
  SHA-256 case manifest, a manifest-bound Mode 1 snapshot, and a sealed
  `ZaynorAuthoritativeResult` (`MALICE | ABSTAIN | UNKNOWN | BENIGN |
  SUSPICION`).
- VIGIA integration: vendored deterministic engine
  (`vendor/vigia_engine/`), subprocess Mode 1 executor, local MCP client
  to VIGIA's bridge, and the `ZaynorMode1Adapter` translation boundary.
- Authority architecture: narrator-only local LLM (Ollama) behind
  `AuthorityGuard` and the hallucination gate; policy-gated agent roles
  (`MENTOR`, `INVESTIGATOR`, `DISPATCHER`, `FLEET_COMMANDER`,
  `DETECTION_ENGINEER`); read-only tool registry; evidence sandbox.
- Tamper-evidence: dual hash chain with optional HMAC anchor
  (`audit_log.py`, `hmac_chain.py`, `investigation_log.py`), Argentina
  timestamps, `CONSULT` sealed-package view.
- Annotations (never authoritative): MITRE ATT&CK / D3FEND enrichment,
  NIST context, candidate Sigma rules (`experimental`), proposed
  response-action matrix (`PROPOSED`, never executed).
- Interfaces: `zaynor` CLI (`replay`, `detect`, `case`, `freeze`,
  `analyze`, `audit`, `chat`, `serve`, `report`, `consult`, `hunts`,
  `models`), optional FastAPI surface, `md`/`html`/`pdf` reports, and
  the Next.js frontend (`frontend/`).
- Corpus and demo: `INC-2026-DEMO-001` scenario, `casos/` case corpus,
  `scenarios/` fixtures, published architecture page.
- OpenTelemetry spans over the postmortem pipeline (optional
  `[telemetry]` extra; hash chain untouched when absent).

### Security

- Arena red-team remediation; rounds of adversarial audits under
  `docs/red-team/` (rounds 2-18, Claude and Codex auditing each other).
- Path traversal, symlink-escape, TOCTOU, and adversarial-evidence
  hardening across the freezer, snapshot, executor, and tool layers.

[Unreleased]: https://github.com/annatchijova/zaynor/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/annatchijova/zaynor/releases/tag/v0.1.0
