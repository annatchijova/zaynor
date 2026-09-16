# Zaynor

*[Leer en español](./README.md)*

> Status: active development for Hackathon CyberAr 2026 (48 hours). The
> post-incident pipeline is partly implemented; the authoritative forensic
> engine still runs through an injected executor, not against real VIGÍA.
> See "Implementation status" for the honest account of what exists and what
> does not.

Zaynor is a post-incident DFIR system built around VIGÍA, an existing
deterministic forensic engine. It starts from an incident that is **already
declared**, whose evidence has **already been collected**: it freezes the
case, hands it to VIGÍA through an explicit adapter, contextualizes the
supported findings against MITRE ATT&CK and NIST, seals the result, and only
then does a local LLM narrate it. Built for the "AI for network and
infrastructure defense" challenge.

The core architectural principle:

> AI decides what to investigate. AI does not decide what is true.

## Scope: the post-incident pipeline

Zaynor is postmortem, full stop. It does not ingest telemetry, does not run
a detection rule, and does not correlate alerts into an incident: a declared
incident with already-collected evidence is its *input*, not something Zaynor
produces. Whatever system or process declared the incident and collected the
evidence is out of scope here.

```
incident declared (external: a ticket, an alert, an analyst referral;
   out of scope) + evidence already collected (out of scope)
   ->  case freeze (manifest + SHA-256, immutable case_id)
   ->  VIGIA adapter  ->  deterministic forensic analysis (VIGIA)
   ->  authoritative Zaynor result  ->  MITRE ATT&CK / NIST contextualization
   ->  seal  ->  local LLM narration  ->  incident report / postmortem
```

Optional, read-only branch back into the deterministic side:

```
authoritative Zaynor result
   ->  LLM investigative suggestion  ->  allowlisted read-only query
   ->  evidence  ->  deterministic re-analysis (VIGIA)
   ->  updated authoritative Zaynor result
```

The case freeze is not a metaphor: it is a real, small stage of code that
selects the case's evidence records, hashes every artifact, writes a
manifest, and closes the bundle to writes before handing it downstream.
Everything after that point reads only from the frozen copy.

## The two authority boundaries

- **Zaynor ↔ VIGÍA integration boundary.** VIGÍA is an existing engine, not
  a design document to be reimplemented. It is integrated through an
  explicit adapter (`src/zaynor/adapter.py`), and no VIGÍA internal type
  crosses that boundary: the stable contract is `ZaynorAuthoritativeResult`.
  A capability absent from the executor's result is represented as an
  explicit `UNKNOWN`, never filled in with a Zaynor-generated forensic
  value.
- **Deterministic ↔ LLM authority boundary.** The LLM narrates an
  already-sealed result and may suggest read-only queries. It cannot add,
  modify, or promote a finding: disabling the narrator does not change any
  deterministic finding for the same evidence set.

### Claims, predicates, and evidence

The LLM never proposes a verdict. It proposes a *claim* with typed
predicates (`{event_id, field, op, value}`), and the deterministic gate
re-reads every predicate directly against the frozen evidence — never
against the model's own quote of the record. A VERIFIED predicate is not
enough: a claim becomes `CORROBORATED` only if those verified predicates
also satisfy the rule's declared provenance and independence requirements
(two artifacts sharing a `lineage_id` are not independent evidence just
because they sit in different files). A contradicting predicate yields
`CONTRADICTED`; anything the gate cannot resolve stays `INSUFFICIENT` and
renders as `UNKNOWN` in the report, never smoothed into a guess.

Three further rules run through the whole codebase:

- **Evidence is data, never an instruction.** A log line reading "ignore
  previous instructions" is still evidence: it gets logged and reasoned
  about like any other artifact and never reaches a prompt's control
  channel.
- **A tool call is either on the allowlist or it does not happen.**
  Read-only enforcement is a hardcoded function registry, not an LLM
  self-report.
- **No float in anything feeding a claim state or a hash.** Integers,
  `fractions.Fraction`, or `decimal`. Floats are for display rendering only.

## Implementation status

Three states, not two: what is in and running, what is partial, and what
does not exist yet. A placeholder is not reported as green.

| Stage | Where | Status |
|---|---|---|
| Case freeze: manifest, SHA-256, chain of custody | `case_freezer.py`, `custody.py`, `hash_utils.py` | Implemented |
| Read-only confinement of frozen evidence | `path_guard.py` | Implemented |
| Bounded evidence worker | `sandbox.py` | Partial — first slice of the `docs/SANDBOX.md` contract; not a container launcher and not a proof of isolation |
| Allowlisted read-only tool registry | `tools.py` | Implemented — `list_files`, `read_evidence`, `grep_pattern`, audited before execution |
| Hash-chained audit log (plus tail anchor) | `audit_log.py` | Implemented |
| Zaynor ↔ VIGÍA adapter and authoritative contract | `adapter.py`, `schemas.py` | Partial — contract and fail-closed translation are in; the executor is injected and does not yet run against real VIGÍA |
| Investigation log (hypotheses, no authority) | `investigation_log.py` | Implemented |
| Narrative hallucination guard | `hallucination_guard.py` | Partial — mechanism ported, with tests; still carries ANNACONDA's closed vocabulary instead of this project's own schema |
| Claim and predicate gate | — | Not yet |
| MITRE ATT&CK / NIST contextualization | fields in `schemas.py` only | Not yet — no mapping logic |
| Seal of the authoritative result | — | Not yet |
| Local LLM narrator | — | Not yet — no Ollama or other backend binding |

## Open scope note: the deterministic front end

The tree still contains `src/zaynor/replay.py`, `detection.py`,
`correlation.py`, and `tests/test_front_end.py`: stages 1-3 of the earlier
hybrid scope, from before the correction to postmortem-only. Their
docstrings still cite an `AGENTS.md` section ("Scope: the hybrid pipeline")
that no longer exists, and `docs/implementation-plan.en.md` still describes
a "Phase 1 — Deterministic front end". `AGENTS.md` is the governing contract
and says the opposite: replay, detection, and correlation are out of scope
by construction.

The divergence is open and this README does not resolve it: either the front
end is withdrawn from the tree, or it is documented explicitly as a fixture
generator outside the authoritative pipeline. Until the team decides, this
README describes `AGENTS.md`'s scope, and that code is not part of the
post-incident pipeline described above.

## Demonstration case

`scenarios/inc-2026-demo-001/` holds the synthetic INC-2026-DEMO-001
fixture: a privileged credential (`admin.rojas`) used from a
non-inventoried device (`DEV-UNKNOWN-17`), an SSH session against
`srv-files-01`, the creation of `collection.zip`, an alteration of its
declared `modified_time` so it appears to predate the login, and an outbound
connection.

`docs/ground-truth-inc-2026-demo-001.md` keeps the expected reconstruction,
deliberately outside `scenarios/` and outside anything a case freezer, a
tool, or an investigator ever reads. That file also states what the fixture
does **not** establish — how the credential was obtained, who was at the
keyboard, whether the whole file was transferred, who controls the
destination. Any reconstruction claiming certainty on those points is wrong
by construction of the fixture.

## Requirements and how to run it

- Everything runs locally. No data leaves the machine.
- Inference via a local model (Ollama or an equivalent backend), running on
  ordinary developer hardware — no server-class infrastructure assumed.
- Simulated or public data only.
- Python 3.11 on a POSIX system: path confinement and the bounded worker
  use `os.O_NOFOLLOW`, `flock`, `resource`, and `selectors`. There is no
  package manifest pinning a minimum, and nothing below 3.11 was verified.
- **No third-party runtime dependencies.** The whole package is stdlib.
  `pytest` is the only development dependency and there is no package
  manifest yet.

```bash
pip install pytest
pytest -q
```

`conftest.py` puts `src/` on the path, so the package does not need to be
installed. The tests cover the adapter, the case freezer, the hallucination
guard, the investigation log, the sandbox, the read-only registry, and the
legacy front end.

## Repository structure

```
src/zaynor/        pipeline: case freeze, confinement, tools, adapter, logs
tests/             seven test modules, one per area
scenarios/         synthetic INC-2026-DEMO-001 fixture (telemetry + collected evidence)
docs/              architecture proposal, implementation plan, sandbox contract
docs/skills/       catalog of 58 engineering-discipline and forensic skills
docs/hackathon/    rules, challenge tracks, and the design brainstorm documents
.claude/skills/    the two reasoning skills that load automatically
```

The working contracts, in order of precedence for an architectural
decision:

- `AGENTS.md` — the operating manual: what Zaynor is, the authority
  boundaries, the git and PR workflow, the definition of done.
- `CLAUDE.md` — the development-discipline guide (abductive reasoning, git
  hygiene, surgical patching). Not to be conflated with `AGENTS.md`.
- `SYSTEM_PROMPT--ZAYNOR.md` — the runtime prompt assembled from that
  contract; it cannot override it.
- `docs/proposal.en.md` and `docs/implementation-plan.en.md` — the
  architecture proposal and the phased plan.
- `docs/SANDBOX.md` — the evidence sandbox contract and which part of it is
  actually implemented.

## Design lineage

No external project is used as a dependency — the package is pure stdlib.
These are the things actually taken from other projects, so the lineage is
on record:

- **VIGÍA** — not a design reference but the forensic authority Zaynor
  integrates with: the authoritative deterministic analysis lives there,
  behind the adapter. Mechanisms of its own were also adapted where direct
  integration did not apply: the read-only tool registry (`tools.py`, from
  its MCP bridge) and the audit log's hash-chaining pattern. Every adapted
  module documents in its docstring what was taken, what was dropped, and
  why.
- **ANNACONDA** — the hallucination guard (`hallucination_guard.py`), path
  confinement (`path_guard.py`), the chain of custody (`custody.py`), and
  the mission memory ported as the investigation log
  (`investigation_log.py`), all adapted with attribution in the file itself.
- **K8sGPT** — separating a deterministic finding from its AI explanation
  into distinct fields, so the LLM can never write to the verdict, only to
  the text alongside it.
- **HolmesGPT** — the bounded investigation loop (a step limit, not
  unlimited autonomy) and a declarative tool registry.
- **Keep** — separating event identity, alert fingerprint, and incident
  identity instead of one generic "hash" notion.

## Epistemic scope of SHA-256

The hashes in this repository record **byte identity under a manifest**.
They do not prove origin, truth, authorship, completeness, admissibility, or
malicious intent, and no claim of a complete legal chain of custody is made
anywhere.

## License

Apache License 2.0 — see [`LICENSE`](./LICENSE). Code adapted from VIGÍA and
ANNACONDA is under the same license.
