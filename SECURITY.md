# Security Policy

*[Leer en español](SEGURIDAD.md)*

## Reporting a vulnerability

**Do not open a public issue for a security bug.** Email
`anna.tchijova@icloud.com`. Do not put exploit details, sensitive evidence,
credentials, or private case data in a public issue or pull request.

| Severity | What it means here | Response time |
|---|---|---|
| Critical | A sealed result can be forged, tampered with undetected, or a verdict can be influenced by evidence content or a narrator | 48 hours |
| High | A path/symlink/allowlist guard can be bypassed, or a non-local AI backend can be reached | 7 days |
| Medium/Low | Everything else | best effort |

Include a description, affected component or version, reproduction steps or a
minimal proof of concept, and the expected security or forensic impact. The
maintainer will acknowledge reports as soon as practical and coordinate a fix
or mitigation. Do not expect that a report is safe to publish until the
maintainer confirms it.

## What ZAYNOR actually protects, and how

This lists real, implemented controls — not aspirational ones. Each row
names the module a reader can go verify directly.

| Control | Where | What it actually does |
|---|---|---|
| LLM never in the decision path | `authority_seal.py`, `agents/mentor.py` | The deterministic engine seals a result before any model runs; `Mentor` narrates a copy, never the sealed object itself. Swapping the narrator (Ollama model, or removing it) changes wording, never the verdict. |
| No float in any sealed value | `case_freezer.py`, `hash_utils.py`, throughout | Ratios and scores that reach a seal use `fractions.Fraction` or integers. Floats are cosmetic-layer only. |
| Every claim checked against the seal | `hallucination_guard.py`, `agents/authority_guard.py` | A narration's claims are extracted and compared against the sealed result's own facts, regardless of what the model actually said. An unsupported claim is stripped before the user sees it. |
| Local-only narrator, enforced structurally | `agents/ollama_client.py` | `OllamaClient` refuses any host other than `127.0.0.1`/`localhost`/`::1` at construction time — not a config default, a hard check. |
| Semantic tripwire against prompt injection | `agents/tripwire.py` | A deterministic, per-case identifier is folded into the narrator's system prompt; if evidence content tries to reference or impersonate it, the narration is replaced with a flagged notice instead of reaching the user. |
| Tamper-evident, per-case audit chain | `audit_log.py` | Each case's `freeze`/`analyze` lifecycle is hash-chained (SHA-256, optional HMAC), genesis bound to `case_id` so one case's chain cannot be grafted onto another's, with a tail anchor against truncation. |
| Path and symlink confinement | `cli.py` (`_fixture_path`, `_directory_path`), `path_guard.py` | Every file/directory argument is resolved and checked against symlink traversal at every path component, not just the final target. |
| Read-only evidence tools, closed vocabulary | `tools.py` | `ReadOnlyToolRegistry` exposes no write/execute method at all; every call is audited with a closed, non-extensible action vocabulary. |
| Deterministic seal, independently reproducible | `authority_seal.py`, `zaynor audit` | The same frozen case, analyzed twice, produces byte-identical seals — verified as part of the test suite, not assumed. |

## Known, documented limitations

Real gaps that exist today are tracked in `LIMITACIONES_CONOCIDAS.md`, not
hidden. A system that cannot name its own failure modes cannot be
trusted with forensic evidence.

## Security architecture

These are implemented boundaries, not promises about every deployment:

### Authority and verdict integrity

- `result.json` and `result.seal.json` are authoritative only after
  cryptographic verification through `verify_authoritative_result()`.
- The shared stored-case loader binds the requested `case_id`, loads both
  artifacts, verifies the seal, and fails closed on malformed or mismatched
  data.
- `answer_question()` and the HTTP API verify authority before invoking the
  narrator. Chat never runs VIGÍA analysis and never recalculates a verdict.
- The LLM narrates a verified result; it cannot create, modify, or replace a
  result, seal, finding, or verdict.
- The hallucination and authority guards compare claims with sealed facts and
  remove or reject unsupported claims before user-facing narration.

### Evidence and filesystem boundaries

- Case IDs and paths are validated at the boundary.
- Path traversal and symlink traversal are rejected by the CLI and evidence
  access layers.
- Evidence access is read-only unless an explicitly documented operation says
  otherwise.
- Missing, malformed, tampered, or case-mismatched artifacts fail closed.

### Local model boundary

- ZAYNOR's Ollama client accepts only local loopback hosts: `127.0.0.1`,
  `localhost`, or `::1`.
- Host, model, and timeout are configurable; requests use Ollama's local
  `/api/generate` endpoint and explicitly disable streaming.
- There is no cloud fallback or external provider in the supported runtime.
- The API rejects unsupported model IDs and does not pretend that an unknown
  token usage is a measured zero.

### API and transport boundary

- Malformed requests, invalid case IDs, unavailable cases, invalid authority,
  unavailable Ollama, and internal failures use structured HTTP errors.
- Streaming is rejected explicitly when it is not implemented.
- Completion IDs are generated with UUIDs rather than second-resolution time.
- CORS is restricted to configured localhost OpenWebUI origins by default;
  wildcard origins are not enabled.
- Public error messages do not expose internal paths or exception details.

### Hashes, seals, and audit records

Authority seals are deterministic SHA-256 digests over the canonical typed
result representation. Case and audit metadata must not be treated as a
replacement for the result seal. Where hash-chain or audit-chain records are
enabled, verify the chain and its anchors before treating the log as intact.
Multiple hashes are evidence of distinct binding checks, not permission to
skip any one of them.

### Dependency and deployment hygiene

- Keep dependencies pinned or reviewed through the project manifest and lock
  process when available.
- Do not commit credentials, API keys, private evidence, generated secrets, or
  downloaded model files without documented provenance.
- Run the test suite and `git diff --check` for security-relevant changes.
- Prefer a restricted, local runtime with Ollama bound to loopback and case
  output directories protected from unrelated users.

## Deployment checklist

- [ ] Case output and evidence roots are dedicated and access-restricted.
- [ ] `result.json` and `result.seal.json` are retained together.
- [ ] Authority verification is run before sharing a result or narration.
- [ ] Ollama is bound to loopback and uses an approved local model.
- [ ] API host exposure and CORS are intentionally configured.
- [ ] Audit/hash-chain verification is performed when those records are part
      of the deployment.
- [ ] Logs and reports do not contain credentials or unnecessary sensitive
      evidence.
- [ ] Backups of results, seals, and audit records are tested for integrity.

## Reporting issues in VIGÍA

`vendor/vigia_engine/` is an upstream dependency boundary. Report issues that
belong to VIGÍA to its maintainers as well as notifying ZAYNOR when the issue
affects ZAYNOR's integration. Do not silently patch upstream behavior in a
ZAYNOR security fix without documenting the contract impact.

## Scope

This policy covers `github.com/annatchijova/zaynor`. It does not cover
VIGÍA's own upstream repository (`vendor/vigia_engine/` is a vendored,
unmodified copy — see `vendor/vigia_engine/NOTICE.md`); report issues
found there to VIGÍA's own security policy instead.
