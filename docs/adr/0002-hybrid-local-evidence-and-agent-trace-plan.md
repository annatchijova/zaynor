# ADR-0002 — Use a hybrid local evidence and agent-trace architecture

Date: 2026-09-17
Status: accepted
Supersedes: ADR-0001 — Keep MCP capability planes separate
Reversibility: one-way-ish (the selected adapters affect persisted evidence
windows, agent integrations, and future postmortem inputs)

## Forces at the time

ZAYNOR is expanding from a deterministic forensic pipeline into a larger
backend for investigation and postmortem work. The surrounding projects offer
useful capabilities, but they have different contracts:

- ANNACONDA has a strong evidence-window and Velociraptor adapter pattern.
- CRONOS records reasoning traces and verifies their hash chain.
- MNEME provides persistent memory, custody, recall, and quarantine.
- VIGÍA remains the deterministic analysis boundary and upstream forensic
  capability source.
- A live endpoint-collection deployment is not part of this workstream.
- Claude is implementing the postmortem, audit-trail, independent-verifier,
  hash-chain, and timestamp work in its own scope.

The system must remain local, reproducible, and explicit about the difference
between collected evidence, agent reasoning, memory, and authoritative
verdicts.

## Decision

Adopt a hybrid architecture, but implement only the following workstreams in
this phase:

1. **Record this architecture decision.**
2. **Integrate a reproducible evidence-window boundary.** Adapt the useful
   ANNACONDA/Velociraptor normalization and window-sealing pattern for local
   fixtures and mock transports. This phase does not connect to a live
   Velociraptor server, endpoint, or remote collector.
3. **Use CRONOS for agent reasoning traces.** CRONOS records hypotheses,
   recalls, tool calls, evidence notes, discards, decisions, and trace-chain
   verification. Its reasoning trace is supplementary and cannot alter a
   ZAYNOR result or seal.
4. **Use MNEME as optional agent memory and custody support.** MNEME may store,
   recall, quarantine, verify, and export memory records. Its memory state is
   never authoritative over ZAYNOR's `result.json` or `result.seal.json`.

The resulting local flow is:

```text
fixture/mock evidence
        |
        v
reproducible evidence window
        |
        v
ZAYNOR frozen case -> VIGÍA deterministic analysis -> result + seal
        |
        +--> CRONOS reasoning trace
        +--> MNEME optional memory/custody
        +--> safe narration and later postmortem
```

All integrations are adapters. They must preserve the following boundary:

- evidence windows contain observations and custody metadata, not a verdict;
- CRONOS contains agent reasoning, not authoritative findings;
- MNEME contains memory/custody records, not authoritative findings;
- only the verified ZAYNOR result/seal path can establish the authoritative
  result;
- Ollama may narrate or propose, but never decides or rewrites authority.

## Explicitly out of scope for this phase

- Live Velociraptor collection or endpoint acquisition.
- Remote or cloud collectors.
- OpenTelemetry implementation. It remains a future observability layer and
  must be local/OTLP-compatible when revisited, without making cloud export a
  runtime requirement.
- Replacing ZAYNOR's audit trail with CRONOS or MNEME.
- Importing ANNACONDA's agent fleet, cloud services, Firestore, Google ADK,
  active remediation, or broad autonomous execution.
- The postmortem implementation assigned to Claude. Its outputs will be
  consumed only through documented, verified contracts.

## Alternatives rejected

- **Start with live Velociraptor** — rejected because this phase requires
  reproducible local tests and no live acquisition. Best argument for it:
  it would demonstrate operational collection sooner.
- **Port ANNACONDA's adapter unchanged** — rejected because its canonicalizer,
  CAIE taxonomy, schemas, and bundle contracts are not ZAYNOR contracts. Best
  argument for it: the adapter already handles normalization, custody, and
  deterministic window hashes.
- **Make CRONOS the sole audit authority** — rejected because CRONOS seals
  reasoning traces, while ZAYNOR's audit and authority layers bind case
  lifecycle and result/seal verification. Best argument for it: one trace
  chain would simplify the visible story.
- **Make MNEME the result store** — rejected because memory recall and custody
  are not deterministic verdict authority. Best argument for it: MNEME has
  mature quarantine and bundle-verification semantics.
- **Implement OpenTelemetry before the local contracts** — rejected because
  telemetry must describe verified transitions, not become a substitute for
  them. Best argument for it: it would provide early distributed visibility.

## Assumption this rests on

Local fixtures and mock transports can characterize the evidence-window,
reasoning-trace, and memory contracts before any live collector is introduced.
If a later live integration is approved, it must enter through the same
window adapter and pass the same custody, normalization, and authority tests.

## Consequences

Accepted now:

- The first hybrid implementation is reproducible and safe to test offline.
- Agents gain separate reasoning and memory planes without gaining verdict
  authority.
- The evidence-window contract becomes the seam for a future collector.
- CRONOS and MNEME remain independently verifiable services.

Deferred:

- Live Velociraptor transport and endpoint deployment.
- OpenTelemetry spans and exporters.
- Cross-system postmortem correlation beyond the contracts Claude provides.

## Initial implementation

The first offline boundary is implemented in
`src/zaynor/hybrid_integrations.py`. It accepts only an ANNACONDA window whose
canonical hash verifies, materializes normalized artifacts as ordinary JSON,
and returns a profile for the existing `case_freezer.freeze_case()` path. It
does not assign scores or verdicts.

CRONOS and MNEME are represented by narrow injected sink protocols. They may
receive verified collection context and bounded summaries, respectively, but
they cannot receive or mutate `result.json`, `result.seal.json`, or the
authoritative verdict. This keeps the integration compatible with their MCP
servers without importing their server instructions or optional side effects
(for example Slack posting or agent-directed filesystem writes).

## Revisit trigger

Reopen this ADR if:

- live collection is explicitly authorized and a controlled test environment
  exists;
- the evidence-window schema or custody model changes;
- CRONOS or MNEME changes its persisted verification contract;
- Claude's postmortem output requires a new authoritative field;
- OpenTelemetry is needed for a demonstrated operational question rather than
  general observability;
- a supported agent runtime cannot configure the separate capability planes.

## Anchored at

- `docs/adr/0001-separate-mcp-capability-planes.md`
- `src/zaynor/authority_seal.py`
- `src/zaynor/case_freezer.py`
- `src/zaynor/audit_log.py`
- `src/zaynor/investigation_log.py`
- ANNACONDA: `tools/velociraptor/adapter.py`
- CRONOS: `mcp_server.py` and `cronos/chain.py`
- MNEME: `mcp_server.py` and its custody/bundle modules
