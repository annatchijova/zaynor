# ZAYNOR Forensic Report — NITROBA

## Overview — what kind of incident this is

- **Case:** NITROBA
- **Classification:** SUSPICION — no ATT&CK technique corroborated
- **Confidence:** UNKNOWN
- **Result SHA-256:** `8dd2e47d3cfd9a4c407376018fa07fa8aff0c4018e956003432f9b007fefdbbc`
- **Engine:** vigia_agent 1.0.0-SANS-2026
- **Findings / Unknowns:** 1 / 0

## Agents in this pipeline

| Role | Status | What it actually does |
|---|---|---|
| MENTOR | conectado | Explains an already-sealed result; never re-invokes VIGIA. |
| INVESTIGATOR | conectado | collect_window/verify_custody call VIGIA's MCP bridge for real. |
| FLEET_COMMANDER | conectado | Writes to the investigation log; never produces a verdict. |
| DETECTION_ENGINEER | conectado | draft_sigma_rule anchors candidates to a real sealed finding. |
| DISPATCHER | conectado | Catalog of evidence types Mode 1 can actually analyze. |
| ENDPOINT_HUNTER / PERSISTENCE_HUNTER | out of scope | Would need a live EDR collection backend this project does not have. |
| THREAT_INTEL | out of scope, for now | A portable VirusTotal/GTI enrichment exists but is not wired in — external network dependency, pending decision. |

Findings themselves come from VIGIA's deterministic Mode 1 engine, not from a named agent above -- no per-finding agent attribution exists in the sealed contract (`AuthoritativeFinding` has no agent field). This table names what ZAYNOR's own local, Ollama-driven agent layer does around that sealed result.

## Findings

| Finding | State | MITRE | Detected by | Rationale |
|---|---|---|---|---|
| F-NITROBA | SUSPICION | - | VIGIA deterministic engine (Mode 1) | [MOTOR] Label-blind selection: SUSPICION_DETECTED. Significant signal with structural support (score=0.3135) |

- **F-NITROBA evidence:** `NITROBA-ART-001` → `NITROBA-ART-001`, `NITROBA-ART-002` → `NITROBA-ART-002`, `NITROBA-ART-003` → `NITROBA-ART-003`, `NITROBA-ART-004` → `NITROBA-ART-004`, `NITROBA-ART-005` → `NITROBA-ART-005`

## Unknowns

None declared.

## Chain of custody

```
manifest_sha256           : 1768243e3d02cfdc9fa7226140bd628de7a639137ba48998d7e1985e60fdbe0b
snapshot_sha256           : bbbfc9973c67fd76b2b39b28c783672812bc9f5a66c30e62a230b513a28194cb
engine_configuration_hash : 8473accae535bdc076e0ad222bdfab0ba8b12c93cc4e865e3cf01f88a4126e32
result_sha256             : 8dd2e47d3cfd9a4c407376018fa07fa8aff0c4018e956003432f9b007fefdbbc
```

## Methodology

The deterministic engine produces and seals the result before any language model is invoked. The model receives a compressed, read-only summary and narrates it; it cannot alter a verdict, a finding, or the seal. Every claim in a narration is checked against this sealed result before being shown (zaynor chat/serve). result_sha256 is the canonical SHA-256 seal of the authoritative result: recompute it independently with `zaynor audit` to confirm this report was not altered after the fact.
