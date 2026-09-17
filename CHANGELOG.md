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

- Demo lab: local, fully synthetic DFIR and AIOps demonstration
  environments feeding the existing `freeze` / `analyze` / `audit`
  pipeline (`docs/demo-lab/README.md`). DFIR path: adapted
  Velociraptor evidence collector (`tools/velociraptor/`) with
  `MockTransport`/`RestTransport`, canonical `window_hash` in lockstep
  with `hybrid_integrations`, collection manifest and custody, the
  `INC-2026-DEMO-001` lab under `scenarios/`, and `scripts/demo_dfir.py`
  (offline replay + live transport). AIOps path: docker-compose
  observability stack (OTel Collector, Prometheus, Loki, Tempo, Grafana),
  a synthetic service with fault injection, and an incident aggregator
  (`tools/aiops/`) that correlates alert clusters into evidence bundles
  (`tools/aiops/aggregator/`, `scripts/demo_aiops.py`).
- Demo-lab tests (`tests/test_velociraptor_adapter.py`,
  `tests/test_aiops_aggregator.py`) and `scripts/run_lab_tests.py`, a
  dependency-free runner (pytest when installed, stdlib fallback) shared
  by CI, pre-commit, and contributors.
- CI: ruff scope widened to `tools/`, and a `demo-lab smoke` job running
  both offline demos through the real pipeline with sealed-verdict
  assertions. `.pre-commit-config.yaml` gains local `py-compile` and
  `lab-tests` hooks. `AGENTS.md` section 5 verification commands updated.

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
