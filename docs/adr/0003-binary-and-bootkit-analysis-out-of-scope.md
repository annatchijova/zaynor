# ADR-0003 — Binary/bootkit malware analysis stays out of ZAYNOR's core

Date: 2026-09-17
Status: accepted
Reversibility: one-way-ish (a later sandboxed-detonation service is a
different codebase and integration boundary, not a toggle on this one)

## Forces at the time

A teammate proposed adding binary analysis and bootkit detection to
ZAYNOR — disassembling or executing suspicious binaries found in
evidence to classify them as malware.

ZAYNOR's whole identity, established and re-verified repeatedly this
session, is: frozen evidence in, a deterministic engine (VIGÍA) scores
it, a local LLM narrates the sealed result and never decides. Every
read-only tool in this codebase — `PathGuard`, `tools.py`'s
`ReadOnlyToolRegistry`, the curated VIGÍA MCP bridge (ADR-0001) — is
deliberately read-only. Nothing in this project has ever executed
untrusted bytes, and nothing here has a sandbox, a VM, or any isolation
boundary for content that might need to run to be understood.

Bootkit detection and general binary malware analysis are exactly the
class of work that usually needs one of:

- **Dynamic analysis**: actually executing the suspicious binary in an
  isolated, disposable environment (a detonation sandbox) and observing
  what it does. ZAYNOR has never had this capability, has no code that
  even gestures at it, and building a real one — isolation, snapshot/
  revert, network containment, safe cleanup — is a multi-week
  infrastructure project on its own, not a feature added to an existing
  read-only forensic tool under a hackathon deadline.
- **Deep static analysis / reverse engineering**: disassembly, control-
  flow analysis, unpacking. This is a different engineering domain from
  VIGÍA's Peircean/CAIE evidence-scoring model (which reasons over
  already-structured artifacts, not raw machine code) and would need a
  real design pass — a new scoring model, not a quick integration into
  the existing one.

## Decision

Binary disassembly and bootkit dynamic/behavioral analysis do **not**
go into ZAYNOR for this hackathon. This is a joint call (Anna + Claude),
made explicitly rather than left as an unspoken "no."

What *is* welcome, and fits the existing shape without inventing a new
architecture: a **static, read-only, deterministic** binary triage —
hashing, PE/ELF header parsing, and YARA signature matching against
bytes already sitting in frozen evidence (never executing them) — added
as one more entry in `DEFAULT_HUNT_CATALOG`
(`agents/dispatcher_tools.py`), the same pattern `registry`/`prefetch`/
`browser`/`event_log`/`memory`/`mft`/`ebs_json` already use. This is a
real, scoped, buildable piece of work if there is time and someone
signs up to build it — it is deferred, not rejected outright.

## Alternatives rejected

- **Build a sandboxed detonation environment inside ZAYNOR** — rejected:
  no isolation infrastructure exists, the security risk of running that
  half-built under time pressure is real, and it contradicts the
  read-only invariant every other tool in this codebase holds. Best
  argument for it: dynamic analysis is genuinely the most reliable way
  to classify a bootkit. That argument is correct and is exactly why
  this belongs in a dedicated, properly-isolated service, not bolted
  onto a forensic-narration tool overnight.
- **Add a disassembly/RE pipeline to the scoring engine** — rejected:
  VIGÍA's scoring model reasons over structured artifacts (SIFT/EBS
  records), not raw binaries; fitting disassembly output into that model
  needs a real design decision, not a quick call to `angr`/`radare2` from
  inside `vigia_scorer.py`. Best argument for it: static analysis output
  could in principle become just another evidence artifact. True in
  principle — worth a real ADR of its own if someone wants to pursue it,
  not decided here.
- **Flat "no" with nothing offered back** — rejected: the underlying
  instinct (binaries and bootkits are real DFIR evidence) is correct,
  and there is a genuinely low-risk, deterministic slice of it (static
  hash/header/YARA triage) that fits the project's own invariants. Saying
  only "no" would waste that energy instead of redirecting it.

## Consequences

Accepted now:

- ZAYNOR's read-only, no-execution invariant holds without exception.
- The teammate's proposal has a real, scoped, shippable alternative to
  aim at instead of either a rejected full RE pipeline or nothing.
- `DEFAULT_HUNT_CATALOG` gains a documented candidate 8th entry
  (`binary_static` or similar) if someone picks it up — not built by
  this ADR, just cleared to exist.

Deferred:

- Any form of binary execution or disassembly, dynamic or static.
- A real sandboxed detonation service, as a separate project/codebase
  that could later feed ZAYNOR frozen evidence about what it observed
  (same shape as any other evidence source) — a legitimate future
  architecture, not this one.

## Revisit trigger

Reopen this ADR if:

- someone builds a real, isolated detonation sandbox as its own service
  and wants to integrate its *output* (frozen behavioral evidence, not
  live execution) as a new evidence source — that is a different,
  acceptable integration shape;
- someone wants to build the static hash/header/YARA hunt type described
  above — that does not need this ADR reopened, it needs a PR.

## Anchored at

- `src/zaynor/path_guard.py`, `src/zaynor/tools.py` — the read-only
  invariant this decision preserves.
- `docs/adr/0001-separate-mcp-capability-planes.md` — the curated,
  read-only MCP surface this stays consistent with.
- `src/zaynor/agents/dispatcher_tools.py::DEFAULT_HUNT_CATALOG` — where
  a future static-triage hunt type would live.
- `src/zaynor/report.py::_AGENTS` — same "out of scope, here's why"
  pattern already used for `ENDPOINT_HUNTER`/`PERSISTENCE_HUNTER`
  (needs a live EDR backend this project does not have) and
  `THREAT_INTEL` (external network dependency, pending decision).
