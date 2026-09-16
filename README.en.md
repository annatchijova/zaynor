# Zaynor

*[Leer en español](./README.md)*

> Status: active development for a 48-hour hackathon. This README is
> provisional and will be updated as the project takes shape.

A hybrid defense system: detection and correlation over a deterministic
replay of synthetic telemetry, feeding a local-LLM-assisted post-incident
forensic investigation, built for the "AI for network and infrastructure
defense" challenge.

## What it is

Zaynor covers the incident end-to-end, not just the post-mortem half: a
small, deterministic front end detects and correlates signals over a replay
of synthetic telemetry (not real live telemetry) until something becomes an
incident — at that point the evidence gets frozen (manifest + SHA-256,
immutable case ID) and the deep part starts: a local LLM that decides which
evidence to inspect, proposes hypotheses, and narrates the reconstruction.
The LLM never proposes a verdict directly — it proposes a *claim* with
verifiable predicates ("event X has field Y = Z"), and a deterministic layer
re-checks every predicate directly against the frozen evidence and verifies
the rule's declared provenance and independence requirements before
promoting the claim to `CORROBORATED`. The model can investigate and
propose; authority over findings stays outside the LLM and is derived from
explicit rules applied to frozen evidence (see "Design lineage" below for
what was taken from which project).

The core architectural principle:

> AI decides what to investigate. AI does not decide what is true.

## Why it's a hybrid

The project covers the full incident lifecycle, not just the post-incident
half:

```
deterministic replay of synthetic telemetry -> detection -> correlation/triage
   -> INCIDENT DECLARED (evidence frozen: manifest + SHA-256)
   -> frozen evidence access (pre-collected; acquisition out of scope)
   -> local investigation -> hypotheses/RCA
   -> backed finding -> proposed response (not executed) -> postmortem
```

The first three stages are handled by a small, deterministic engine
(a synthetic event stream, a detection rule, a correlation rule) — no eBPF,
no per-node agents, no production monitoring stack. The real weight of the
project, and where the substantive AI lives, starts at the incident: that's
where the local LLM investigates, the deterministic gate controls which
claims can acquire authoritative status, and the ledger keeps the resulting
findings in an auditable record.

## Requirements

- Everything runs locally. No data leaves the machine.
- Inference via a local model (Ollama or an equivalent backend), running on
  ordinary developer hardware — no server-class infrastructure assumed.
- Simulated or public data only.

## Design lineage

No external project is reused as a dependency — Zaynor is a small, original
prototype. These are the concrete ideas actually taken from other projects,
so the lineage is on record:

- **VIGÍA** — the read-only evidence sandbox (hash before reading, path
  confinement), and the principle of sealing a deterministic result before
  any LLM ever sees it.
- **ANNACONDA** — the hallucination-guard pattern: the LLM's narrative can
  only cite facts already authorized by the deterministic engine, never
  invent a new one.
- **K8sGPT** — separating a deterministic finding from its AI explanation
  into distinct fields, so the LLM can never write to the verdict, only to
  the text alongside it.
- **HolmesGPT** — the bounded investigation loop (a step limit, not
  unlimited autonomy) and a declarative tool registry.
- **Keep** — separating event identity, alert fingerprint, and incident
  identity instead of one generic "hash" notion.

## Repository structure

The working contracts are in `AGENTS.md`, `docs/SANDBOX.md`, and
`SYSTEM_PROMPT--ZAYNOR.md`. The first implementation slice is the worker-side
boundary in `zaynor/sandbox.py`; it does not parse or execute artifact content.

The engineering skill catalog lives in `docs/skills/` and is intentionally
scoped to this project's local DFIR and detection pipeline.

## License

Apache License 2.0 — see [`LICENSE`](./LICENSE).
