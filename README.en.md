# Zaynor — local, traceable DFIR investigation

*[Leer en español](./README.md)*

> Status: active prototype for Hackathon CyberAr 2026. Zaynor is being
> assembled by migrating capabilities from three existing repositories; the
> product integration is still advancing in this checkout.

## The real problem

After an incident, an investigator must reconstruct what happened from
authentication, process, network, filesystem, ticket, and operator-note
records. The sources may be incomplete, contradictory, or contain text
controlled by an attacker. Manual correlation is slow. A generic LLM assistant
may be fast, but it can also invent facts, overstate causality, or treat a
sentence inside a log as an instruction.

Zaynor addresses one concrete question:

> What does the evidence support, which alternative explanations were
> considered, what should be investigated next, and what remains unknown?

Zaynor is not a SIEM, an EDR, or a real-time monitoring system. It is a local,
post-incident DFIR investigation tool.

## What it does

Zaynor receives an already-declared incident and already-collected evidence. It
freezes the case, preserves artifact identity, and passes the evidence to a
deterministic mathematical engine. That engine produces and seals the
authoritative result using one of these public labels:

```text
MALICE | ABSTAIN | UNKNOWN | BENIGN | SUSPICION
```

AI does not detect the incident or decide the verdict. After the result is
sealed, a local LLM may decide what to investigate next, propose a bounded
read-only operation, and explain the result for different audiences. If a
query produces new evidence, that evidence passes through the mathematical
engine again before it can change an authoritative result.

The architectural principle is:

> **AI decides what to investigate. The deterministic mathematical engine
decides what the evidence supports.**

The quadripartite engine in the VIGÍA lineage exists as a technical capability.
Its detailed mechanics, score, and internal semantics are a later technical
deep dive; this README prioritizes the authority boundary that the jury can
observe in the demo.

## Authority flow

```text
DECLARED INCIDENT + COLLECTED EVIDENCE
        (simulated fixture or authorized public data)
    -> case freeze: manifest, hashes, immutable case_id
    -> deterministic mathematical engine
    -> sealed authoritative verdict
    -> comprehensive MITRE ATT&CK / NIST context
    -> local AI proposes what to investigate next
    -> typed, bounded, read-only operation
    -> new evidence -> deterministic re-analysis -> re-sealing
    -> local chat, technical view, and human-facing report
```

The AI can never:

- write directly to the verdict or sealed result;
- create evidence references that no real tool returned;
- execute a shell, arbitrary network request, or filesystem write;
- turn ambiguity into a confident conclusion;
- execute a defensive recommendation.

An instruction written inside a log, ticket, or artifact remains **untrusted
evidence**, never a system command.

## Audiences

### Junior forensic examiner (perito junior)

The perito junior has a full local-LLM chat for asking questions about the case
in natural language. The chat explains:

1. what was observed;
2. why it matters;
3. which evidence supports each explanation;
4. which alternatives were considered;
5. what should be queried next;
6. what remains unknown.

The chat helps investigate and understand the case. It is not a second verdict
engine and cannot execute remediation.

### Senior analyst

The technical view preserves frozen artifacts, provenance, timeline, fractures,
hypotheses, evidence references, verdict state, MITRE/NIST context, audit data,
and open questions.

### Incident owner

The executive view summarizes the sealed result, supported sequence, material
uncertainty, framework context, and proposed defensive actions. Actions are
shown as `PROPOSED` and `NOT EXECUTED`.

## Demonstration case

The demo uses `INC-2026-DEMO-001`, a simulated Linux incident:

```text
privileged login from an unknown device
    -> SSH session on srv-files-01
    -> process creates collection.zip
    -> timestamp metadata is changed
    -> related outbound connection is observed
    -> operator note attempts to manipulate the investigator
```

The system must show both what it can establish and what it cannot. The
identity of the person at the keyboard, the credential origin, and the
complete transfer of the file remain unknown unless the frozen evidence
supports them.

A synthetic fixture or replay may put an already-formed case on screen. It is
a demonstration harness, not a claim that Zaynor is live monitoring or a
production SIEM.

## Three-minute demonstration

The recommended jury explanation is:

1. **Problem:** evidence is scattered, contradictory, and potentially
   manipulative.
2. **Sealed verdict:** the deterministic engine produces a public label before
   the LLM is called.
3. **Investigation:** the local LLM selects a discriminating question and can
   use only read-only tools.
4. **Manipulation:** an artifact contains an instruction; it is recorded as
   untrusted data and cannot change permissions, tools, or the verdict.
5. **Explanation:** the perito junior asks the local chat about the result and
   what remains to be investigated.
6. **Close:** supported facts, uncertainty, MITRE/NIST context, and proposed
   actions are shown separately.

> **AI investigates. Evidence and the deterministic engine decide.**

## Requirements and sovereignty

- All processing runs locally.
- Inference uses Ollama or an equivalent local backend.
- Case data is never sent to an external service.
- Only simulated or authorized public data is used.
- The model operates through explicit read-only operations with step, time,
  byte, and result limits.
- No testing is performed against real systems.

## Status and scope

The repository is integrating existing capabilities rather than building a
platform from scratch. The current tree includes, among other pieces, case
freezing, hashing and custody, bounded read-only evidence tools, a VIGÍA
adapter contract, a local MCP client, an investigation log, and the synthetic
demonstration scenario.

The final integration must preserve these properties:

- the same frozen case and configuration produce the same authoritative result;
- enabling or disabling the LLM does not change the sealed result;
- every finding has traceable references;
- invented references are rejected;
- path traversal, unauthorized tools, and writes are rejected;
- an adversarial artifact cannot modify authority state;
- missing or ambiguous evidence remains `UNKNOWN`;
- comprehensive MITRE and NIST context does not promote a finding;
- the perito junior chat explains authorized facts only.

## Out of current scope

The current demonstration does not include:

- real-time monitoring or collection;
- acquisition from real systems;
- autonomous remediation;
- shell, arbitrary network, or write access for the LLM;
- PDF or HTML rendering;
- a SIEM, EDR, or operational-scale product.

Real-time monitoring, new report formats, and operational connectors are later
improvements. The full local chat and comprehensive MITRE/NIST context are part
of the product being integrated now.

## Documentation

- [`docs/extra_arenaai.md`](./docs/extra_arenaai.md) — formal product
  position, users, demo, scope, and acceptance criteria.
- [`AGENTS.md`](./AGENTS.md) — VIGÍA integration contracts and authority limits
  between evidence, deterministic engine, and LLM.
- [`docs/proposal.en.md`](./docs/proposal.en.md) — architecture proposal.
- [`docs/implementation-plan.en.md`](./docs/implementation-plan.en.md) —
  integration plan and capability matrix.
- [`docs/hackathon/`](./docs/hackathon/) — Hackathon CyberAr rules, challenge
  material, and research notes.
- [`docs/SANDBOX.md`](./docs/SANDBOX.md) — evidence-worker boundaries.

## Design lineage

Zaynor is being assembled from three existing repositories and takes concrete
patterns from related projects. These references do not grant authority to the
LLM and do not replace the project's local contracts:

- **VIGÍA:** deterministic mathematical engine, verdicts, sealing, and the
  read-only evidence model.
- **ANNACONDA:** separation between authorized facts and narrative, plus the
  bounded investigation loop.
- **Forge:** report structure and separation between junior explanation and
  technical analysis.
- **K8sGPT:** separation between structured findings and generated explanation.
- **HolmesGPT:** iterative tool-based investigation with a step budget.
- **Keep:** separation between event identity, alert fingerprint, and incident
  identity.

Third-party components and adaptations remain subject to their licenses and
will be documented before final submission.

## License

Apache License 2.0 — see [`LICENSE`](./LICENSE).
