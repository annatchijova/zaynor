# Design lineage

Zaynor is being assembled from three existing repositories and takes concrete
patterns from related projects. These references do not grant authority to the
LLM and do not replace the project's local contracts:

- **VIGÍA:** deterministic mathematical engine, verdicts, sealing, and the
  read-only evidence model.
- **ANNACONDA:** separation between authorized facts and narrative, plus the
  bounded investigation loop.
- **Forge:** report structure and separation between junior explanation and
  technical analysis.
- **K8sGPT:** separation between structured findings and generated explanation.
- **HolmesGPT:** iterative tool-based investigation with a step budget.
- **Keep:** separation between event identity, alert fingerprint, and incident
  identity.

Third-party components and adaptations remain subject to their licenses and
will be documented before final submission.
