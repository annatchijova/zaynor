# Security Policy

*[Leer en español](SEGURIDAD.md)*

## Reporting a vulnerability

**Do not open a public issue for a security bug.** Use GitHub's private
security advisory feature on this repository, or contact the maintainer
directly.

| Severity | What it means here | Response time |
|---|---|---|
| Critical | A sealed result can be forged, tampered with undetected, or a verdict can be influenced by evidence content or a narrator | 48 hours |
| High | A path/symlink/allowlist guard can be bypassed, or a non-local AI backend can be reached | 7 days |
| Medium/Low | Everything else | best effort |

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

## Scope

This policy covers `github.com/annatchijova/zaynor`. It does not cover
VIGÍA's own upstream repository (`vendor/vigia_engine/` is a vendored,
unmodified copy — see `vendor/vigia_engine/NOTICE.md`); report issues
found there to VIGÍA's own security policy instead.
