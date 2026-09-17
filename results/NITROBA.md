# ZAYNOR Forensic Report — NITROBA

*Generated 2026-09-17T09:45:08-03:00 (Argentina time)*

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
| INVESTIGATOR | implementado, sin invocación automática | collect_window/verify_custody are real and tested (agents/investigator_tools.py) but no CLI/API command calls them yet. |
| FLEET_COMMANDER | implementado, sin invocación automática | Writes to the investigation log; real code (agents/fleet_commander_tools.py), no caller in cli.py/api.py yet. |
| DETECTION_ENGINEER | implementado, sin invocación automática | draft_sigma_rule anchors candidates to a real sealed finding (agents/detection_engineer_tools.py), not wired to a command yet. |
| DISPATCHER | implementado, sin invocación automática | Catalog of evidence types Mode 1 can actually analyze (agents/dispatcher_tools.py), not wired to a command yet. |
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
report_hash (timestamped)   : 2b867f817d15c557850ed37aa881cfd44cb644811b3f2d7c8e283f32947fa7a5
```

## Methodology

The deterministic engine produces and seals the result before any language model is invoked. The model receives a compressed, read-only summary and narrates it; it cannot alter a verdict, a finding, or the seal. Every claim in a narration is checked against this sealed result before being shown (zaynor chat/serve). result_sha256 is the canonical SHA-256 seal of the authoritative result: recompute it independently with `zaynor audit` to confirm this report was not altered after the fact.
