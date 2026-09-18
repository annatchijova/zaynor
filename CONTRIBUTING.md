# Contributing to ZAYNOR

*[Leer en español](CONTRIBUYENDO.md)*

ZAYNOR accepts contributions to code, tests, documentation, forensic cases,
integrations, and adversarial validation.

Before changing the system, understand one boundary:

> **AI may investigate and explain. Only the deterministic evidence path may
> change authoritative forensic state.**

A contribution is not complete because it works once. It should preserve
authority boundaries, provenance, reproducibility, and auditability.

## Architectural invariants

Changes must preserve these properties unless an explicit architectural
decision changes the contract.

### VIGÍA owns deterministic decision semantics

ZAYNOR integrates the vendored VIGÍA engine in `vendor/vigia_engine/`; it
does not maintain an independent reimplementation of VIGÍA's scorer.

Do not silently modify vendored scoring behavior. Changes to VIGÍA semantics
belong upstream and require an explicit update to ZAYNOR's integration
contract.

### AI has no verdict authority

An LLM or agent may investigate, derive, acquire within policy, or explain a
verified result. It must not create or modify an authoritative finding, score,
verdict, seal, or decision threshold.

No registered AI-agent role has `MUTATE` or `AUTHORIZE`.

See [`AGENTS.md`](AGENTS.md) and
[`src/zaynor/agents/README.md`](src/zaynor/agents/README.md).

### Authoritative arithmetic is reproducible

Do not introduce binary floating-point into authoritative scoring, hashing,
canonicalization, or sealed state. Exact/canonical numeric representations
such as `Fraction`, `Decimal`, and integers are used according to the
relevant contract.

### Evidence is untrusted data

Evidence content must never become instructions or capabilities.

Collectors produce observations and provenance. MCP/tool outputs are
untrusted inputs. New evidence must return through the deterministic analysis
path before it can affect an authoritative conclusion.

### Provenance survives transformation

Do not silently discard source identity, custody information, hashes,
dependency relationships, uncertainty, or distinctions between real and
synthetic evidence.

## Making a change

1. **Read the current implementation first.** Do not infer behavior from a
   filename, old documentation, or an earlier version.
2. **Keep the change focused.** Prefer one coherent concern per commit and
   explain why the change is necessary.
3. **Use Conventional Commits.**

   ```text
   feat(core): add evidence profile
   fix(telemetry): correct OTel span naming
   security(mcp): reject unauthorized capability
   docs(install): document local Ollama setup
   ```

   Allowed types and enforcement live in
   [`scripts/commitlint.py`](scripts/commitlint.py).
4. **Test behavioral changes.** Cover the intended behavior and relevant
   negative, boundary, and adversarial cases. Security- or authority-sensitive
   fixes should include a regression test demonstrating the previous failure.
5. **Update contracted documentation with the code.** Documentation/code
   relationships are enforced by `scripts/docs_check.py`. If a new component
   establishes a documentation contract, update `DOCS_MAP`.
6. **Do not rewrite shared history.** Force pushes, rebases of shared project
   history, and silent squashing are not part of this repository's workflow.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate

pip install -e ".[dev]"
pip install pre-commit

./scripts/install-hooks.sh
pre-commit install
```

Before proposing a code change:

```bash
python3 -m pytest tests/ -q
ruff check src tools tests scripts conftest.py
git diff --check
```

`black --check` and `mypy` are currently advisory rather than merge gates.
Match the surrounding style and do not introduce new type errors in code you
touch.

The installed hooks enforce commit-message, documentation-sync, and
history-safety rules. CI repeats the repository gates independently. See
[`scripts/`](scripts/) and the CI workflows for the exact current
implementation of those gates.

## Security- and authority-sensitive changes

Changes involving any of the following require additional scrutiny:

- VIGÍA integration or scoring;
- `result.json` / `result.seal.json`;
- canonicalization, hashes, HMACs, or audit chains;
- evidence freeze or custody;
- filesystem/path boundaries;
- MCP capabilities or agent permissions;
- Ollama/model boundaries;
- hallucination or authority guards.

For these changes, include a regression test that fails when the relevant
security property is violated. A successful happy path alone is insufficient.

See [`SECURITY.md`](SECURITY.md) and [`docs/red-team/`](docs/red-team/).

## Adding forensic cases

Cases are evaluation units, not examples invented to make the engine look
successful.

Every added case must identify:

- whether the evidence is real or synthetic;
- source and provenance;
- authorization or licensing where applicable;
- expected behavior;
- case category;
- enough information to reproduce the ZAYNOR/VIGÍA result.

Real evidence must come from documented, authorized sources. Existing sources
include public forensic datasets and challenges such as Digital Corpora and
DFRWS.

Synthetic fixtures are welcome for regression, adversarial, BREAK,
false-positive, and false-negative coverage, but must be clearly labeled and
kept distinguishable from real forensic evidence.

See [`casos/README.md`](casos/README.md).

## Documentation

If you are changing behavior, start with the document closest to that
contract:

- [`README.md`](README.md) — product model and authority boundary;
- [`INSTALL.md`](INSTALL.md) — installation and operation;
- [`GUIA_PERITOS.md`](GUIA_PERITOS.md) — reproducible forensic workflow;
- [`AGENTS.md`](AGENTS.md) — integration and agent contracts;
- [`src/zaynor/agents/README.md`](src/zaynor/agents/README.md) — agent roles and capabilities;
- [`docs/mcp-locales.md`](docs/mcp-locales.md) — MCP surface;
- [`docs/demo-lab/README.md`](docs/demo-lab/README.md) — DFIR/AIOps laboratory;
- [`docs/technical-details.md`](docs/technical-details.md) — implementation details;
- [`SECURITY.md`](SECURITY.md) — security boundaries and reporting.

## Releases

ZAYNOR follows [Semantic Versioning](https://semver.org/) and maintains
[`CHANGELOG.md`](CHANGELOG.md) using the Keep a Changelog structure.

Breaking changes to public interfaces, evidence semantics, seal formats, or
other persisted authoritative contracts require particular care: compatibility
is forensic behavior, not merely API ergonomics.

Release preparation and versioning are maintainer responsibilities.

## Reporting vulnerabilities

Do not report vulnerabilities containing exploit details in a public issue.

Follow [`SECURITY.md`](SECURITY.md) for private reporting and disclosure.

## Code of Conduct

Participation in the project is governed by
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
