# Zaynor

*[Leer en español](./README.md)*

> Status: active development for a 48-hour hackathon. This README is
> provisional and will be updated as the project takes shape.

A hybrid defense system for already-declared incidents: it takes frozen
evidence, builds and tests hypotheses with a deterministic mathematical
engine, and uses local AI to choose further investigation steps and produce
reports for different audiences, built for the "AI for network and
infrastructure defense" challenge.

## What it is

Zaynor starts when an incident has occurred and evidence has already been
collected; incident declaration and acquisition are external to this repo.
From the frozen evidence, the investigator maintains hypotheses and questions
using Peirce's triad: abduction proposes explanations, deduction derives what
would discriminate them, and induction tests them against evidence.
Discriminating evidence and fractures feed VIGÍA's deterministic mathematical
engine, which calculates score and confidence and assigns one of its
verdicts: `MALICE`, `ABSTAIN`, `UNKNOWN`, `BENIGN`, or `SUSPICION`. The LLM
does not decide the verdict.

After that authoritative step, AI may decide what to investigate next — in a
bounded loop similar to ANNACONDA — using only allowlisted read-only
operations. New evidence must cross the deterministic engine again before it
can change the result. The LLM also narrates the sealed result: it copies
Forge's report format as-is — Markdown, PDF, and HTML — and provides an LLM
chat for junior analysts; the senior view preserves hypotheses, fractures, score, confidence,
alternatives, and traceability.

The core architectural principle:

> AI may decide what to investigate. The deterministic mathematical engine
> decides what the evidence supports.

## Why it's a hybrid

The project covers the post-incident flow:

```
INCIDENT DECLARED + COLLECTED EVIDENCE (external to Zaynor)
   -> frozen evidence (manifest + SHA-256, immutable case ID)
   -> Peircean hypotheses: abduction -> deduction -> induction
   -> discriminating evidence / fractures
   -> VIGÍA deterministic mathematical engine
   -> MALICE | ABSTAIN | UNKNOWN | BENIGN | SUSPICION + score/confidence
   -> hash chain + sealed authoritative result
   -> AI chooses bounded additional investigation (optional, read-only)
   -> new evidence -> VIGÍA / deterministic re-analysis
   -> Forge reports (.md/.pdf/.html) + local analyst chat
```

The separation is intentional: the deterministic engine owns verdicts, scores,
confidence, fractures, traceability, and the hash chain; AI proposes next
investigation steps and translates already-sealed results for humans. An LLM
proposal never changes the verdict by itself.

## Requirements

- Everything runs locally. No data leaves the machine.
- Inference via a local model (Ollama or an equivalent backend), running on
  ordinary developer hardware — no server-class infrastructure assumed.
- Simulated or public data only.
- Planned interfaces: local CLI, frontend, API, and Ollama chat; MCP may
  expose read-only investigation tools.

## Design lineage

No external project is reused as a dependency — Zaynor is a small, original
prototype. These are the concrete ideas actually taken from other projects,
so the lineage is on record:

- **VIGÍA** — the deterministic mathematical forensic engine, score,
  confidence, quadripartite verdicts, and sealing before any LLM sees the
  result; it also contributes the read-only sandbox model.
- **ANNACONDA** — the hallucination-guard pattern: the LLM's narrative can
  only cite facts already authorized by the deterministic engine, never
  invent a new one, plus the bounded loop for choosing what to investigate.
- **Forge** — the analyst reporting shape copied as-is: Markdown, PDF, and
  HTML, with a junior explanation flow separated from the deeper senior
  analysis.
- **K8sGPT** — separating a deterministic finding from its AI explanation
  into distinct fields, so the LLM can never write to the verdict, only to
  the text alongside it.
- **HolmesGPT** — the bounded investigation loop (a step limit, not
  unlimited autonomy) and a declarative tool registry.
- **Keep** — separating event identity, alert fingerprint, and incident
  identity instead of one generic "hash" notion.

## Repository structure

The working contracts are in `AGENTS.md`, `docs/SANDBOX.md`, and
`SYSTEM_PROMPT--ZAYNOR.md`. The worker boundary in `src/zaynor/sandbox.py`
keeps evidence inspection bounded; it does not parse or execute artifact
content inside the API process.

The engineering skill catalog lives in `docs/skills/` and is intentionally
scoped to this project's local DFIR and detection pipeline.

## License

Apache License 2.0 — see [`LICENSE`](./LICENSE).
