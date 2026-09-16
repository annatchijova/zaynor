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
re-checks every predicate directly against the frozen evidence before
anything is sealed as `CORROBORATED`. It's the same philosophy as ANNACONDA
(deterministic collection/correlation first, LLM narrates after, never the
other way around) applied to a post-incident case instead of only a live
one.

The core architectural principle:

> AI decides what to investigate. AI does not decide what is true.

## Why it's a hybrid

The project covers the full incident lifecycle, not just the post-incident
half:

```
deterministic replay of synthetic telemetry -> detection -> correlation/triage
   -> INCIDENT DECLARED (evidence frozen: manifest + SHA-256)
   -> evidence collection -> local investigation -> hypotheses/RCA
   -> backed finding -> proposed response (not executed) -> postmortem
```

The first three stages are handled by a small, deterministic engine
(a synthetic event stream, a detection rule, a correlation rule) — no eBPF,
no per-node agents, no production monitoring stack. The real weight of the
project, and where the substantive AI lives, starts at the incident: that's
where the local LLM investigates and where the deterministic ledger has the
final say.

## Requirements

- Everything runs locally. No data leaves the machine.
- Inference via a local model (Ollama or an equivalent backend), running on
  ordinary developer hardware — no server-class infrastructure assumed.
- Simulated or public data only.

## Repository structure

Under construction — see `AGENTS.md` for the working contract (git/PR
workflow, the deterministic/LLM boundary, editing discipline) while the code
doesn't exist yet.

## License

Apache License 2.0 — see [`LICENSE`](./LICENSE).
