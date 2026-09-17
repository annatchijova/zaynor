# Full-suite blocker diagnosis — 2026-09-17

## Scope

This is a diagnostic record for the full ZAYNOR test suite. No production
behavior was changed as part of this step.

## Reproduction

The suite collects 315 tests. Running the complete suite with a 120-second
hard limit reached 46% and then made no further progress:

```text
env PYTHONPATH=src timeout 120 pytest -q
exit=124
```

Running test modules sequentially with a 15-second per-module limit showed
that every module before `tests/test_investigator_tools.py` completed. The
first blocking module was:

```text
tests/test_investigator_tools.py exit=124
```

The three real-bridge tests also block when run independently with a
12-second limit:

```text
TestAgainstRealVigiaBridge::test_collect_window_reads_real_evidence_through_vigia exit=124
TestAgainstRealVigiaBridge::test_verify_custody_computes_a_real_sha256_through_vigia exit=124
TestAgainstRealVigiaBridge::test_collect_window_rejects_paths_outside_evidence_dir exit=124
```

The first three tests in that module pass. The first blocked test is the
real-bridge `collect_window` test.

## Current boundary

`collect_window()` calls `_run_mcp_call()`, which creates a fresh
`VigiaMCPClient`. That client starts the vendored
`vigia/vigia_sift_bridge_min.py` over stdio and waits for MCP initialization.
The bridge entrypoint currently uses the SDK default `mcp.run()` path. The
ZAYNOR-owned MCP server uses the explicitly selected Trio stdio backend due
to the same MCP SDK startup behavior observed during its handshake testing.

## Diagnosis

The full-suite timeout is isolated to the VIGÍA MCP bridge startup/handshake
path used by `investigator_tools`; it is not caused by the ZAYNOR MCP server,
the authority tests, or the ordinary API tests. The next step is to add a
bounded client/bridge startup test and make the smallest ZAYNOR-side change
needed to select a working local stdio runtime, without changing VIGÍA
scoring or analysis behavior.

## Not changed

- No scorer or authoritative schema changes.
- No VIGÍA re-analysis changes.
- No test was skipped or weakened.
- No frontend or external repository changes.
