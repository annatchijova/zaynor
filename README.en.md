# Zaynor

*[Leer en español](./README.md)*

> Status: active development for a 48-hour hackathon. This README is
> provisional and will be updated as the project takes shape.

A local-LLM-assisted post-incident forensic investigator, built for the
"AI for network and infrastructure defense" challenge.

## What it is

Zaynor reconstructs a simulated security incident from heterogeneous
evidence (logs, authentication events, process records, network events,
filesystem metadata). A locally-running LLM decides which evidence to
inspect, proposes and discriminates between hypotheses, and narrates the
reconstruction — but **it never decides on its own what counts as a
confirmed finding**. That authority belongs to a deterministic layer that
requires corroboration from at least two independent sources before
anything is sealed as `CORROBORATED`.

The core architectural principle:

> AI decides what to investigate. AI does not decide what is true.

## Why it's a hybrid

The project covers the full incident lifecycle, not just the post-incident
half:

```
telemetry (synthetic) -> detection -> correlation/triage -> INCIDENT
   -> evidence collection -> local investigation -> hypotheses/RCA
   -> backed finding -> response/prevention -> postmortem
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
