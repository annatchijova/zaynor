# ZAYNOR architecture proposal: VIGÍA authority with bounded AI investigation

**Status:** decided.

This proposal supersedes earlier plans to build local “VIGÍA-mini”
mechanisms inside ZAYNOR. AGENTS.md §2 is the enforced version of this
decision for humans and agents writing code.

## Context

ZAYNOR needs reproducible, auditable forensic conclusions independent of
LLM completions, while AI should help humans investigate incomplete and
contradictory evidence.

VIGÍA already provides the deterministic forensic authority: evidence
reasoning, provenance, uncertainty, auditability, and related semantics.
Reimplementing smaller versions inside ZAYNOR would duplicate work and
create a second epistemic authority.

The architecture therefore separates:

- **forensic authority**, owned by VIGÍA and deterministic ZAYNOR components;
- **investigative agency**, which may be exercised by a bounded local LLM;
- **explanation**, performed by a local LLM over sealed authorized facts.

> **AI may decide what to investigate. AI never decides what is true.**

## Decision

ZAYNOR is a hybrid DFIR system built around VIGÍA as its deterministic
forensic engine.

### Authoritative path

1. A deterministic front end replays synthetic telemetry and applies
   detection and correlation until an incident is declared.
2. The case is frozen into an immutable evidence bundle with a canonical
   manifest, artifact hashes, provenance metadata, and stable case_id.
3. An explicit adapter passes the frozen case to the existing VIGÍA engine.
4. VIGÍA performs the authoritative deterministic forensic analysis.
5. The adapter translates the result into a stable
   ZaynorAuthoritativeResult; downstream ZAYNOR code does not depend on
   VIGÍA internal types.
6. MITRE ATT&CK and NIST context is added as structured annotation without
   changing the epistemic state of findings.
7. The completed authoritative package is canonicalized and sealed.
8. A local LLM explains the sealed authorized state for different audiences.

~~~text
synthetic telemetry replay
    ↓
deterministic detection + correlation
    ↓
incident declared
    ↓
case freeze: manifest + SHA-256 + provenance + immutable case_id
    ↓
VIGÍA adapter → VIGÍA deterministic forensic analysis
    ↓
ZaynorAuthoritativeResult
    ↓
MITRE ATT&CK / NIST contextualization
    ↓
seal → local LLM narration
    ↓
analyst view / junior explanation / incident report / postmortem
~~~

### Optional investigative path

AI-assisted investigation is a bounded extension of the authoritative path,
not an alternative authority system. The LLM may maintain candidate
explanations, identify unresolved questions, propose discriminating
evidence, and suggest an allowlisted read-only operation.

It may not create or promote findings, change evidence state, declare
corroboration, turn UNKNOWN into a conclusion, execute arbitrary tools,
write evidence, or modify the sealed result.

~~~text
authoritative result
    ↓
candidate hypothesis / investigative question
    ↓
LLM suggests read-only operation
    ↓
typed schema + hardcoded allowlist + case confinement
    ↓
deterministic execution → new observation/evidence
    ↓
VIGÍA deterministic re-analysis → updated authoritative result
~~~

A different evidence set is a different investigation. The LLM can affect
which evidence is requested, but not the semantics by which it becomes an
authoritative finding.

## Three boundaries

### ZAYNOR ↔ VIGÍA: integration boundary

VIGÍA is an existing engine, not a design document to be reimplemented.
Existing deterministic capabilities are reused through an explicit adapter.
A local equivalent requires a documented incompatibility or capability gap;
“it was easier to rewrite” is not sufficient.

All downstream ZAYNOR code depends on ZaynorAuthoritativeResult, not
VIGÍA-internal types.

### Evidence ↔ authority: epistemic boundary

Evidence is data, not instruction. Verification, corroboration,
contradiction, provenance/lineage, uncertainty, abstention, and exact
computation remain deterministic.

Multiple artifacts are not automatically independent corroboration.
Independence is a provenance/lineage property, not a citation count.
Missing evidence remains missing unless a deterministic protocol gives its
absence specific evidentiary meaning.

### Deterministic state ↔ LLM: AI authority boundary

LLM output has no direct write path to authoritative forensic state.
Evidence-controlled content—including logs, filenames, documents, and tool
results containing evidence bytes—has instruction_authority = false.
That property survives transformations and tool-return boundaries.

The LLM is treated as a potentially confused deputy: useful reasoning is
preserved while authority is structurally restricted.

## Analytical model: competing hypotheses without a second forensic engine

ZAYNOR may expose an Analysis of Competing Hypotheses (ACH)-style view:

~~~text
research question
    ↓
competing hypotheses
    ↓
supporting / contradictory / neutral evidence
    ↓
discriminating evidence still needed
    ↓
remaining / contradicted alternatives
    ↓
authoritative findings + explicit uncertainty
~~~

ACH does **not** replace VIGÍA’s evidence model, inference engine, ledger,
corroboration semantics, or provenance model. It is an investigative and
explanatory projection over verified evidence and authoritative state.

An LLM may propose a relationship between evidence and a hypothesis, but
that proposal remains unverified until checked against the frozen evidence
and processed through the deterministic authority boundary.

## Evidence independence and sensitivity are separate properties

ZAYNOR distinguishes lineage independence—whether evidence originates from
genuinely independent provenance chains—from result sensitivity—whether
removing one item changes an analytical result.

A leave-one-out analysis may be used as a deterministic sensitivity test
where compatible with the authoritative result contract. It is not a
substitute for provenance analysis.

~~~text
independent evidence ≠ insensitive result
insensitive result ≠ independent evidence
~~~

## Framework mappings are annotations, not evidence

MITRE ATT&CK and NIST contextualize authoritative forensic results; they do
not create them. A technique mapping never promotes a finding’s epistemic
state and is not evidence of causality, intent, or attribution.

Finding state, mapping status, mapping justification, and framework
identifier remain separate fields. NIST structures incident handling,
response, and reporting; it does not replace the forensic evidence model.

## Human-facing explanation

The system preserves full technical rigor internally while presenting
different projections to different audiences.

### Advanced analyst

May inspect observations, evidence references, provenance and lineage,
reconstructed timeline, fractures and contradictions, competing
explanations, uncertainty, framework mappings, integrity metadata, and the
audit trail.

### Junior analyst

Receives an explanation structured around:

1. what was observed;
2. why it matters;
3. what evidence supports it;
4. what alternative explanations existed;
5. what evidence discriminated between them;
6. what remains unknown.

### Executive / incident owner

Receives the incident summary, supported findings, material uncertainty,
defensive recommendations, unresolved questions, and relevant
integrity/audit references.

## Load-bearing invariants

For the same frozen evidence set, VIGÍA version, and deterministic
configuration:

~~~text
run(case, llm=OFF).authoritative_result
==
run(case, llm=ON).authoritative_result
~~~

Different narration must not produce different forensic state.

Additional invariants:

- no undocumented VIGÍA reimplementation;
- no VIGÍA-internal type crosses the adapter;
- no LLM completion writes authoritative state;
- evidence-derived text never acquires instruction authority;
- derived duplicates do not create independent corroboration;
- framework mappings never promote finding state;
- unresolved questions remain UNKNOWN;
- narrative output cannot modify the sealed result;
- VIGÍA failure is explicit and cannot trigger a synthetic fallback finding.

## Demonstration thesis

ZAYNOR detects a suspicious situation, freezes the evidence, and performs a
reproducible deterministic forensic analysis. A local AI explains what the
evidence supports, what alternatives were considered, and what remains
unknown. If enabled, the AI can suggest what to investigate next, but new
evidence must pass back through the deterministic forensic engine before it
can change the result.

> **rigorous underneath, understandable on top.**

## Consequences

- AGENTS.md §2 enforces the VIGÍA reuse boundary and AI authority model.
- The implementation plan begins with an inventory of real VIGÍA source.
- ACH, sensitivity analysis, forensic fixture improvements, and AI threat
  controls do not duplicate VIGÍA semantics.
- The narrator is required; the investigation assistant remains optional.
- MITRE ATT&CK and NIST remain visible in the authoritative package and
  reports.
- UNKNOWN is a valid and expected result.

## Out of scope here

This document does not define the final ZaynorAuthoritativeResult schema,
the exact VIGÍA integration surface, ownership, implementation deadlines,
or UI technology. Those are implementation decisions constrained by this
architecture.
