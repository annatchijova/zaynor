# ZAYNOR Forensic Report — NITROBA

*Generated 2026-09-17T10:02:57-03:00 (Argentina time)*

## Overview — what kind of incident this is

- **Case:** NITROBA
- **Classification:** SUSPICION — no ATT&CK technique corroborated
- **Confidence:** UNKNOWN
- **Result SHA-256:** `434cf0a51eaa0649e7a78a8941dfe4d3d6c9ce16c99b403c706e03889cb9089b`
- **Engine:** ZAYNOR deterministic engine (Mode 1) 1.0.0-SANS-2026
- **Findings / Unknowns:** 1 / 0

## Agents in this pipeline

| Role | Status | What it actually does |
|---|---|---|
| MENTOR | conectado | The only role a normal zaynor chat/serve run actually invokes; explains an already-sealed result, never re-invokes the engine. |
| INVESTIGATOR | implementado, sin invocación automática | Collects a bounded evidence window and re-verifies custody hashes; real and tested, no CLI/API command calls it yet. |
| FLEET_COMMANDER | implementado, sin invocación automática | Writes to the investigation log; real and tested, no caller wired yet. |
| DETECTION_ENGINEER | implementado, sin invocación automática | Drafts a candidate detection rule anchored to a real sealed finding; real and tested, not wired to a command yet. |
| DISPATCHER | implementado, sin invocación automática | Catalog of evidence types the engine can actually analyze; real and tested, not wired to a command yet. |
| ENDPOINT_HUNTER / PERSISTENCE_HUNTER | out of scope | Would need a live EDR collection backend this project does not have. |
| THREAT_INTEL | out of scope, for now | A portable VirusTotal/GTI enrichment exists but is not wired in — external network dependency, pending decision. |

Findings themselves come from ZAYNOR's own deterministic Mode 1 engine, not from a named agent above -- no per-finding agent attribution exists in the sealed contract (`AuthoritativeFinding` has no agent field). This table names what ZAYNOR's own local, Ollama-driven agent layer does around that sealed result.

## Findings

| Finding | State | MITRE | Detected by | Rationale |
|---|---|---|---|---|
| F-NITROBA | SUSPICION | - | ZAYNOR deterministic engine (Mode 1) | [MOTOR] Label-blind selection: SUSPICION_DETECTED. Significant signal with structural support (score=0.3135) |

- **F-NITROBA evidence:** `NITROBA-ART-001` → `NITROBA-ART-001`, `NITROBA-ART-002` → `NITROBA-ART-002`, `NITROBA-ART-003` → `NITROBA-ART-003`, `NITROBA-ART-004` → `NITROBA-ART-004`, `NITROBA-ART-005` → `NITROBA-ART-005`

## Unknowns

None declared.

## Chain of custody

```
result_sha256 (deterministic): 434cf0a51eaa0649e7a78a8941dfe4d3d6c9ce16c99b403c706e03889cb9089b
report_hash (timestamped)   : 03c210c74182fc4056322ed0bf76ca919ddb8965620b5f9cbb77f9fe2aa1fc5e
```

## Methodology

The deterministic engine produces and seals the result before any language model is invoked. The model receives a compressed, read-only summary and narrates it; it cannot alter a verdict, a finding, or the seal. Every claim in a narration is checked against this sealed result before being shown (zaynor chat/serve). result_sha256 is the canonical SHA-256 seal of the authoritative result: recompute it independently with `zaynor audit` to confirm this report was not altered after the fact.
