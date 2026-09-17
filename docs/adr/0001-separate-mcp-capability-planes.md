# ADR-0001 — Keep MCP capability planes separate

Date: 2026-09-17
Status: accepted
Reversibility: one-way-ish (changing the exposed tools requires coordinated
agent configuration and permission review)

## Forces at the time

ZAYNOR needs three backend concerns with different trust and lifecycle
contracts:

- forensic evidence access and investigation;
- agent memory and memory custody;
- reasoning-trace and audit persistence.

The repositories already contain working MCP servers for MNEME and CRONOS,
and VIGÍA has both a curated vendored bridge and a larger upstream bridge.
The number of functions available across repositories is not itself a safe
permission boundary. A single MCP containing every function would combine
read-only evidence access, memory mutation, trace mutation, live-system
access, mounts, and honeytokens.

ZAYNOR's authoritative boundary is also distinct: `result.json` and
`result.seal.json` are produced by analysis and must not be changed by an
agent, memory system, trace system, or LLM.

## Decision

Expose separate MCP capability planes and integrate them through explicit
adapters only when a concrete caller needs them:

| MCP | Current surface | Responsibility | Authority |
|---|---:|---|---|
| ZAYNOR curated bridge | 9 tools | Read-only evidence inspection and bounded forensic analysis | No verdict authority; observations remain untrusted |
| MNEME | 9 tools | Persistent memory, custody, recall, quarantine, and bundle verification | No authority over ZAYNOR results |
| CRONOS | 10 tools | Reasoning traces, hypotheses, evidence records, and trace-chain verification | No authority over ZAYNOR verdicts |
| VIGÍA upstream bridge | 22 tools | Broader VIGÍA capabilities for explicitly authorized agents | Outside the default ZAYNOR MCP surface |

The ZAYNOR curated bridge keeps these nine tools:

`list_files`, `read_evidence`, `search_pattern`, `generate_forensic_hash`,
`calculate_shannon_entropy`, `infer_intent`, `audit_grice_maxims`,
`detect_eco_overinterpretation`, and `validate_and_correct_analysis`.

MNEME and CRONOS remain separate MCP servers. ZAYNOR may add typed adapters
for them, but the adapters must preserve their boundaries:

- MNEME outputs are memory/custody data, never authoritative findings.
- CRONOS outputs are reasoning-trace data, never authoritative findings.
- Neither server may write, replace, or recalculate ZAYNOR result or seal
  artifacts.
- The LLM may propose questions, hypotheses, or narration, but it does not
  decide the verdict.

The full VIGÍA bridge is not exposed by default. Its additional tools include
live process and network inspection, mounts, image handling, honeytokens,
dictionary reloads, and LLM-backed operations. A future second VIGÍA MCP may
be configured for a specifically authorized agent, with its own resource,
effect, and operational review.

## Alternatives rejected

- **Merge all tools into one ZAYNOR MCP** — rejected because it collapses
  distinct permissions and makes memory, trace, evidence, and live-system
  actions look equivalent. Best argument for it: one configuration is easier
  for an agent to discover.
- **Expose all 22 VIGÍA tools in the default ZAYNOR bridge** — rejected
  because several tools have effects or dependencies outside the current
  frozen-evidence/read-only contract. Best argument for it: maximum VIGÍA
  coverage without another server configuration.
- **Replace ZAYNOR's audit trail with CRONOS** — rejected because CRONOS
  seals reasoning traces while ZAYNOR's audit log binds the case lifecycle,
  result sealing, case identity, tail anchor, and optional HMAC. Best argument
  for it: CRONOS already persists a detailed trace and verifies its chain.
- **Use MNEME as the authority store** — rejected because memory custody and
  recall are not the deterministic ZAYNOR result/seal contract. Best argument
  for it: MNEME provides strong per-memory custody and quarantine semantics.
- **Treat the aggregate count as a target tool count** — rejected because no
  single contract requires 32 tools; the observed surfaces are 9, 9, 10, and
  22 in separate systems. Best argument for it: a larger catalog can appear
  more complete in a demo.

## Assumption this rests on

Agents can be configured with more than one MCP server and can distinguish
evidence observations, memory records, and reasoning traces. If a target
runtime can only load one server, we will use a narrow typed multiplexer with
the same capability and authority boundaries rather than flattening all tools
into one unrestricted catalog.

## Consequences

Accepted now:

- Permission review stays local to each capability plane.
- ZAYNOR's forensic MCP remains small and read-only.
- MNEME and CRONOS can evolve independently without changing ZAYNOR's
  authoritative schema.
- A failed or unavailable memory/trace server does not silently change a
  forensic verdict.

Deferred:

- Typed MNEME and CRONOS adapters for ZAYNOR agents.
- A separately authorized full VIGÍA MCP configuration.
- A reliable MCP stdio handshake for ZAYNOR's vendored bridge; the current
  bridge starts but has not yet completed `initialize` in the local test
  environment.

Accepted limitation:

- Some audit and reasoning functionality is intentionally represented by
  separate systems. Cross-system correlation must be explicit and must not
  promote an observation into authority without the ZAYNOR verification path.

## Revisit trigger

Reopen this ADR if any of the following occurs:

- a supported agent runtime cannot configure separate MCP servers;
- an agent needs a capability currently excluded from the curated ZAYNOR
  bridge and its resource/effect contract has been reviewed;
- ZAYNOR's authoritative audit requirements change to require a durable
  reasoning-trace backend;
- MNEME or CRONOS changes its serialized or verification contract;
- the VIGÍA upstream bridge changes its tool set or transport model.

## Anchored at

- `src/zaynor/zaynor_mcp_client.py`
- `vendor/vigia_engine/vigia/vigia_sift_bridge_min.py`
- `src/zaynor/audit_log.py`
- `src/zaynor/investigation_log.py`
- MNEME repository: `mcp_server.py`
- CRONOS repository: `mcp_server.py`
- VIGÍA repository: `vigia/vigia_sift_bridge.py`
