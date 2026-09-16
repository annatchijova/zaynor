# Zaynor — product position and hackathon proof

**Status:** current product framing for Hackathon CyberAr 2026. This document
records the intended product boundary, the demonstration argument, and the
claims that the README must make consistently. It is not a replacement for
`AGENTS.md`, `docs/proposal.en.md`, or the implementation plan.

## Executive position

Zaynor is a local DFIR investigation system for an incident that has already
been declared and whose evidence has already been collected. It is being
assembled by migrating the relevant capabilities from three existing
codebases; it is not a greenfield mock or a claim that a generic language model
can replace a forensic engine.

The product claim is deliberately narrow:

> A deterministic mathematical engine produces and seals the authoritative
> verdict. A local LLM then decides what to investigate next, explains the
> sealed result, and proposes defensive actions without changing that result.

The public verdict labels are:

```text
MALICE | ABSTAIN | UNKNOWN | BENIGN | SUSPICION
```

The quadripartite mathematical engine is an existing technical capability in
the VIGÍA lineage. Its internal mechanics and detailed score semantics belong
to the later technical explanation; the hackathon README should first make the
product boundary and the evidence/AI separation understandable.

## The real problem

After an incident, a junior or senior investigator must reconstruct what
happened from heterogeneous records: authentication, processes, network
activity, filesystem metadata, tickets, and operator notes. These sources may
be incomplete, contradictory, or contain text controlled by an attacker.
Manual correlation is slow. A generic LLM assistant is fast but can invent
facts, overstate causality, or treat a sentence inside a log as an instruction
for the investigation.

Zaynor addresses the operational question:

> What does the evidence support, which alternatives were considered, what
> should be investigated next, and what must remain unknown?

The value is not "AI detects everything". Detection and the authoritative
verdict belong to the deterministic mathematical engine. The value of AI is
bounded investigative agency and understandable communication after the
verdict has been sealed.

## Users and audiences

### Senior forensic analyst

The senior view exposes the technical basis: frozen artifacts, provenance,
timeline, fractures, hypotheses, evidence references, verdict state,
comprehensive MITRE ATT&CK and NIST context, audit history, and unresolved questions.

### Perito junior

The perito junior can use the complete local-LLM chat being migrated into
Zaynor to ask questions about the sealed case in accessible language. This is a
first-class product capability, not a future convenience. The chat explains:

1. what was observed;
2. why it matters;
3. which evidence supports the explanation;
4. which alternatives were considered;
5. what the local investigator should inspect next;
6. what remains unknown.

The chat is an explanation and investigation aid. It is not a second verdict
engine and it cannot execute remediation.

### Incident owner or decision-maker

The executive view presents the sealed verdict, the supported sequence, the
material uncertainty, the framework context, and defensive actions marked as
proposals rather than executed operations.

## Authority model

The authoritative path is deterministic:

```text
incident declared + evidence collected
    -> case freeze: manifest, hashes, immutable case_id
    -> deterministic mathematical engine
    -> sealed verdict
    -> comprehensive MITRE ATT&CK / NIST contextualization
    -> authoritative facts for human-facing views
```

The AI path begins only after the authoritative result exists:

```text
sealed verdict and authorized facts
    -> local LLM proposes a discriminating question
    -> typed, allowlisted, read-only operation
    -> new observation
    -> deterministic re-analysis and re-sealing
    -> updated authoritative result, if the evidence warrants it
```

The LLM can choose what to investigate, but it cannot:

- set or edit `MALICE`, `ABSTAIN`, `UNKNOWN`, `BENIGN`, or `SUSPICION`;
- write directly to the authoritative result or ledger;
- add evidence references that were not returned by a real tool call;
- execute shell commands, arbitrary network requests, or filesystem writes;
- convert an ambiguous result into a confident conclusion;
- execute a defensive recommendation.

Evidence is data, not instruction. A ticket comment or log line that says
"ignore the rules" remains an untrusted artifact and has no instruction
authority.

## Concrete demonstration case

The demonstration uses `INC-2026-DEMO-001`, a simulated Linux incident:

```text
privileged login from an unknown device
    -> SSH session on srv-files-01
    -> process creates collection.zip
    -> timestamp metadata is changed
    -> related outbound connection is observed
    -> an operator note attempts to manipulate the investigator
```

The system must show both what it can establish and what it cannot. The
identity of the human at the keyboard, the origin of the credential, and the
complete transfer of the file remain unknown unless the frozen evidence
supports them. The adversarial note is displayed as evidence without gaining
permission to change the investigation.

A synthetic replay or fixture loader may be used to put this already-declared
case on screen. It is a demonstration harness, not a claim that Zaynor is a
live network monitor or a production SIEM.

## Three-minute demonstration argument

The demonstration should make the trust boundary visible rather than explain
it only with architecture diagrams.

1. **Problem:** an analyst receives heterogeneous and contradictory evidence.
2. **Sealed result:** the deterministic engine produces one of the five public
   labels and seals the result before the LLM is called.
3. **Investigation:** the local model selects a read-only question that can
   discriminate between competing explanations.
4. **Manipulation attempt:** an evidence artifact contains an instruction for
   the agent; it is recorded as untrusted content and cannot change the tool
   set or verdict.
5. **Human explanation:** the perito junior can ask the local chat why the
   result was reached and what remains unresolved.
6. **Close:** supported facts, unknowns, framework context, and proposed
   defensive actions are shown separately.

The closing sentence is:

> The AI investigates. The evidence and deterministic engine decide.

## Scope for the current product

In scope:

- local inference through Ollama or an equivalent local backend;
- full local chat for the perito junior and explanation for senior analysts;
- deterministic verdicts and sealed authoritative results;
- read-only, bounded investigation suggestions;
- comprehensive MITRE ATT&CK and NIST contextualization that never changes verdict state;
- simulated or public evidence only;
- a Markdown-oriented incident brief and traceable evidence references;
- explicit unknowns and defensive recommendations that are not executed.

Not in the current demonstration:

- real-time monitoring or continuous collection;
- acquisition from real systems;
- testing against third-party infrastructure;
- autonomous remediation;
- arbitrary shell, network, or filesystem access for the model;
- PDF or HTML report rendering;
- a general-purpose SIEM, EDR, or production-scale platform.

Real-time monitoring, additional report formats, and broader operational
integrations are future improvements, not current product claims.

## Proof and acceptance criteria

The migration is convincing when the repository can demonstrate these
properties with one reproducible case:

- the same frozen evidence and deterministic configuration produce the same
  authoritative result;
- turning the LLM on or off does not change the already-sealed result;
- every displayed finding points to evidence that exists in the frozen case;
- an invented evidence reference is rejected;
- path traversal, arbitrary tools, and writes are rejected;
- the adversarial artifact cannot change permissions, tools, or verdict state;
- a missing or ambiguous fact remains `UNKNOWN`;
- MITRE or NIST annotations do not promote a finding;
- the perito junior chat explains authorized facts instead of manufacturing
  new ones;
- proposed defensive actions are visibly marked `PROPOSED` and `NOT EXECUTED`.

These checks demonstrate a real security property more effectively than a
claim of perfect attack detection on a small synthetic dataset.

## Adoption path

The hackathon fixture can later be replaced by authorized exports from an EDR,
SIEM, journald, ticketing system, or other approved collection process. The
case-freeze boundary, deterministic authority model, local chat, and report
contract remain the same. New connectors add evidence formats; they do not
hand verdict authority to the model.

This gives Zaynor a credible adoption story without claiming that the
prototype already performs live collection or production response.

## Documentation decision

The repository's technical plans remain useful implementation material. This
file is the product-facing decision record that resolves their presentation:

- the incident is already declared at the DFIR boundary;
- the mathematical engine, not the LLM, detects/classifies and seals the
  verdict;
- the LLM investigates after the seal and explains it to different audiences;
- the perito junior chat is a first-class capability;
- real-time operation and PDF/HTML outputs are later improvements;
- the public README uses the five labels requested by the team.

The README should be read together with `AGENTS.md` for the non-negotiable
VIGÍA and deterministic/LLM boundaries, and with the hackathon source
material under `docs/hackathon/` for the event's constraints.
