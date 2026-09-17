# Security Audit — ZAYNOR auxiliary MCP integration

## Red Team Round 19

**Date:** 2026-09-17  **Method:** source review plus reproducible local MCP
experiments  **Scope:** ZAYNOR's `auxiliary_mcp_client.py`, CRONOS and MNEME
stdio entrypoints, their declared dependencies, and the auxiliary MCP
allowlists. VIGÍA authority, scorer, and the evidence-window adapter were not
changed or re-audited here.

**Base:** `b82fb9b`  **Reproducible evidence:**
`tests/test_auxiliary_mcp_client.py` plus the local stdio probes recorded in
the session log.

## Threat model

- Attacker CAN cause a configured auxiliary subprocess to hang, return an
  unexpected tool catalog, or provide hostile tool arguments.
- Attacker MAY control an externally loaded auxiliary configuration in the
  stronger configuration-injection scenario.
- Attacker CANNOT modify ZAYNOR code, the MCP SDK, or the authoritative
  `result.json`/`result.seal.json` path.

## Epistemic legend

CODE FACT · PLAUSIBLE HYPOTHESIS · CONFIRMED BY INDUCTION · FALSIFIED

## Executive summary

| ID | Severity | Level | Bucket | Finding |
|----|----------|-------|--------|---------|
| RT19-01 | Medium | CONFIRMED BY INDUCTION | vulnerability | MCP calls have no client-side deadline |
| RT19-02 | Medium | CODE FACT / threat-model dependent | vulnerability | untrusted `extra_env` can alter interpreter import context |
| RT19-03 | High | CODE FACT | architectural gap | MNEME memory tools are not case-bound |

## Findings

### RT19-01 — Auxiliary MCP operations can hang ZAYNOR

**Severity:** Medium  **Epistemic level:** CONFIRMED BY INDUCTION
**Bucket:** vulnerability (availability)

- **Surprise / expectation violated:** a local auxiliary failure should fail
  closed and return control to ZAYNOR.
- **Abduction:** the client delegates `initialize`, `list_tools`, and
  `call_tool` directly to the SDK without a deadline. A non-responsive server
  can therefore hold the caller indefinitely.
- **Deduction:** a FastMCP server running on the asyncio stdio path, or a
  process that never responds, will leave `session.initialize()` pending.
- **Induction:** the pre-fix integration against CRONOS remained blocked at
  `initialize` for 30 seconds; a minimal empty FastMCP server reproduced the
  same behavior. The Trio entrypoint fixed the server-side trigger, but the
  client still has no deadline for a future hang.
- **Causal chain:** unresponsive subprocess → SDK await remains pending →
  ZAYNOR request/task remains pending.
- **Threat-model precondition:** the configured local MCP process is wedged or
  the SDK transport regresses.

### RT19-02 — `extra_env` is an import-context injection surface

**Severity:** Medium  **Epistemic level:** CODE FACT; exploitability is
configuration-threat-model dependent  **Bucket:** vulnerability

- **Surprise / expectation violated:** auxiliary server configuration should
  not silently replace the code imported by the configured server.
- **Abduction:** `extra_env` is copied into the child environment without a
  protected-key check. A caller controlling it can set `PYTHONPATH` (or other
  interpreter-affecting variables) before the server starts.
- **Deduction:** a hostile directory on `PYTHONPATH` could shadow imports used
  by a server, if the attacker also controls that directory.
- **Induction:** not run as arbitrary-code execution; the source path and
  threat-model precondition are directly observable. This finding is therefore
  not labeled exploit-confirmed.
- **Causal chain:** attacker-controlled config → child environment → altered
  module resolution → auxiliary process behavior changes.
- **Threat-model precondition:** attacker controls `extra_env` and a directory
  visible to the child interpreter. If configuration is trusted and immutable,
  this is hardening rather than a reachable exploit.

### RT19-03 — MNEME memory access is not case-scoped

**Severity:** High  **Epistemic level:** CODE FACT  **Bucket:** architectural
  trust-boundary gap

- **Surprise / expectation violated:** the ADR and integration plan require
  memory to be scoped to the current case.
- **Abduction:** `mneme_store` accepts a topic but `mneme_recall` accepts only a
  free query. The ZAYNOR client has no `case_id` parameter or enforcement in
  either operation.
- **Deduction:** a caller using the allowlisted client can query the MNEME DB
  without proving a case binding; memory from another case may be returned.
- **Induction:** no data-crossing experiment was run against a shared DB; the
  missing binding is directly visible in both the client and server contracts.
- **Causal chain:** case-unbound recall → shared MNEME corpus → cross-case
  memory exposure or poisoning → contaminated agent context.
- **Threat-model precondition:** more than one case uses the same MNEME DB and
  the caller can invoke the memory tools. This is not a verdict-authority
  bypass, but it violates investigation isolation.

## Discarded vectors

| Vector | Result | Why it failed |
|---|---|---|
| MNEME authority/claim tools reachable through ZAYNOR allowlist | FALSIFIED | They are not in `MNEME_TOOLS`; `call_tool` rejects them before connection. |
| CRONOS Slack side effect enabled by ZAYNOR | FALSIFIED | The CRONOS child environment removes `SLACK_BOT_TOKEN`. |
| MCP server path symlink accepted | FALSIFIED | `server_params()` rejects a symlink before launch. |
| Auxiliary MCP can alter ZAYNOR authoritative result | FALSIFIED | The client returns tool content only; no result/seal write path exists. |

## Recommendations

1. Add configurable bounded deadlines around all three SDK operations and
   close the subprocess on timeout.
2. Reject protected child-environment keys, including `PYTHONPATH`, from
   `extra_env`.
3. Keep `mneme_store` and `mneme_recall` disabled in ZAYNOR until MNEME offers
   an explicit case-bound contract. Continue exposing only verification,
   custody-chain, and informational tools in the interim.
