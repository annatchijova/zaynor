> Source: `repos` (external brainstorming input listing reference repositories
> and platforms for the Zaynor architecture). Kept verbatim as source material
> for the team's brainstorming process, not repository-authored documentation.

# Reference repos and pipeline sketch

```text
LIVE
telemetría sintética
      ↓
regla de detección
      ↓
correlación + triage
      ↓
════════ INCIDENT BOUNDARY ════════
      ↓
evidence fija/read-only
      ↓
LLM local investiga
      ↓
hipótesis + RCA
      ↓
gate determinista
      ↓
ledger/findings
      ↓
respuesta propuesta
      ↓
postmortem
```

## AIOps / incident-investigation platforms referenced

- https://github.com/keephq/keep
- https://github.com/coroot/coroot
- https://github.com/k8sgpt-ai/k8sgpt (solo k8s)
- https://github.com/holmesgpt/holmesgpt

| Platform | Stars / Traction | Main Focus | Evidence Collection Mechanism | Local / Air-Gapped LLM |
| :---- | :---- | :---- | :---- | :---- |
| **Keep** | ~11,900+ ★ | Alert Hub & Workflow Automation | Workflows-as-Code via APIs/Webhooks | Yes (Custom LLM endpoints) |
| **Coroot** | ~7,900+ ★ | Automated eBPF APM & RCA | Kernel-level eBPF tracing & log clustering | Yes (On-prem inspection engine) |
| **K8sGPT** | ~5,800+ ★ | K8s Cluster Diagnostic Triage | Native K8s API analyzers & Prometheus metrics | Yes (Ollama / Local vLLM) |
| **HolmesGPT** | CNCF Sandbox | Multi-Cloud/K8s Incident Investigation | Interactive CLI/API queries & log sampling | Yes (BYO local model) |

## Team's own sibling repos

- https://github.com/annatchijova/annaconda — se conoce end to end
- https://github.com/annatchijova/vigia-intent-analysis — se conoce end to end, 102 LOC de python
- https://github.com/annatchijova/SKILLS
