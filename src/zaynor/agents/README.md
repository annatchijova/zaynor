# `agents/` — real wiring status, read this before adding a role

This directory has more real, tested code than the CLI currently exposes.
Before building a new agent, a new runtime, or a new tool registry: check
this table first. Verified by grepping `cli.py`/`api.py` for every tool
function in this directory (2026-09-17) — not assumed from file names.

| Module | Role | Status | Real caller today |
|---|---|---|---|
| `mentor.py` | MENTOR | **wired** | `zaynor chat`, `zaynor serve` (via `chat_service.py`) |
| `investigator_tools.py` | INVESTIGATOR | implemented, tested, no caller | none |
| `fleet_commander_tools.py` | FLEET_COMMANDER | implemented, tested, no caller | none |
| `detection_engineer_tools.py` | DETECTION_ENGINEER | implemented, tested, no caller | none |
| `dispatcher_tools.py` | DISPATCHER | implemented, tested, **wired** | `zaynor hunts` |
| `consult_tools.py` | CONSULT | implemented, tested, **wired** | `zaynor consult` (via `framework_context.build_consult_package`) |

Do not re-derive this table from scratch — update it here the moment a
role gets a real caller, so the next person (human or agent) does not
repeat the same investigation.

## The pieces underneath, and how they actually fit

- **`contracts.py`** — the shared typed vocabulary (`AgentRole`, `Audience`,
  `CapabilityEffect`, `Capability`, `AgentSpec`, `UntrustedContext`,
  `ToolRequest`). Everything else imports from here; nothing here imports
  from a role-specific module.
- **`registry.py`** — the approved manifest per role (which tools, which
  capabilities, `can_write`/`can_adjudicate`). `AgentRuntime` refuses to
  bind a tool a role's manifest does not list.
- **`policy.py`** — deterministic tool authorization
  (`authorize_tool(role, request, human_approved=...)`), independent of
  what the model asked for or said about itself.
- **`runtime.py::AgentRuntime`** — a real, generic, bounded Ollama
  tool-calling loop (`run(role, system=, prompt=, tools=)`), with its own
  `max_steps` (default 8) and JSON-shaped turn parsing. **This is real and
  tested (`tests/test_agents.py`) but has zero production callers** —
  same gap as the four unwired role modules above. If you wire a new role
  to a CLI/API command, this is very likely the runtime to call — do not
  build a second, competing tool-loop.
- **`investigation_contracts.py` / `investigation_runner.py`** — a
  *different*, narrower bounded interaction: one audited proposal → policy
  check → observation, anchored to a sealed result
  (`InvestigationSession`, `BoundedInvestigator`). This is not the same
  thing as `AgentRuntime` — do not conflate the two step budgets
  (`InvestigationSession.max_steps`, adapted from HolmesGPT, vs.
  `AgentRuntime`'s own `max_steps`). Also unwired to any CLI/API command
  today.
- **`chat_service.py`** — the one path that actually ships: shared between
  `zaynor chat` and `zaynor serve`, calls `mentor.py` directly (not
  `AgentRuntime` — MENTOR's job is narrate-and-check, not a multi-step
  tool loop).
- **`tripwire.py`** — not a role; a cross-cutting defense (semantic
  tripwire against prompt injection) folded into `Mentor.chat_checked`.
- **`model_catalog.py`, `ollama_client.py`** — infrastructure, not agents.

## The package-seal mismatch — resolved, not by changing what `analyze` seals

`consult_tools.py::ConsultTools` requires a seal computed over an
`AuthoritativePackage` wrapper (`framework_context.py`), but `zaynor
analyze` seals the bare `ZaynorAuthoritativeResult` directly. These are
two different sealed objects with different canonical bytes. Rather than
extending `_run_analyze`'s seal shape (a change to the sealed decision
path, which needs a documented decision per `CLAUDE.md` §1.3, not a quiet
fix), `framework_context.build_consult_package(result, seal)` bridges the
two: it verifies the already-sealed result first, then wraps and reseals
it as a package, entirely downstream of `analyze`. `zaynor consult`
(read-only, no LLM, no engine re-invocation) is the real caller.

`FrameworkContext` defaults to empty when built this way: no MITRE/NIST/
OWASP mapper exists yet — `Finding.mitre`/`Finding.nist` are passed
through verbatim from whatever the engine emitted (`adapter.py:73-74`),
unpopulated by every case in the current corpus (`casos/*.json`). This is
the honest state, not a placeholder pretending to be a mapping. Building
that mapper is a real, separate, not-yet-scoped piece of work — do not
infer one exists because `OwaspAnnotation` now has a dataclass shape.

## Before wiring a new role

1. Update the table above first — claim the "wired" status before writing
   the code, so two people don't wire the same role at once.
2. Reuse `AgentRuntime` unless you have a documented reason not to.
3. A tool handler that only reads/returns a deterministic catalog (like
   DISPATCHER's `list_hunts`) does not need an LLM round-trip at all —
   see `zaynor hunts` for the pattern: call the tool function directly
   from the CLI when there's no actual reasoning step, and reserve
   `AgentRuntime` for roles that genuinely need the model to choose
   between tools or synthesize a narrative from multiple tool calls.
