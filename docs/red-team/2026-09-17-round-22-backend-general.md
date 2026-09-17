# Red team round 22 — backend general audit

## Status

**Date:** 2026-09-17
**Status:** DRAFT — findings only, no fix applied, nothing committed
**Base:** worktree at `a58fd9a` + uncommitted changes (`AGENTS.md`, `CLAUDE.md`,
`src/zaynor/agents/consult_tools.py`, `src/zaynor/agents/contracts.py`,
`tests/test_consult_tools.py`, `tests/test_mentor_checked.py`,
`tests/test_report.py` modified; `build/`, `results/*.json`, `vendor/__init__.py`,
`vendor/vigia_engine/__init__.py` untracked)
**Method:** Abductive Engineering (A-D-I) + Red-Team Auditing
**Scope:** audit-trail exposure (audit_log.py / cli.py / api.py), the
investigation pipeline (agents/investigation_contracts.py,
investigation_runner.py, investigator_tools.py, policy.py, registry.py), the
MCP transport layer (zaynor_mcp_client.py, auxiliary_mcp_client.py,
agents/ollama_client.py), and the general API surface (api.py in full)
**Reproducible evidence:** ad-hoc scripts run against the live source tree
during this session (paths and exact commands are given inline under each
finding's Induction section); none were kept as permanent files in the repo

## Baseline

```
PYTHONPATH=src python3 -m pytest -q --ignore=tests/test_real_forensic_image_evidence.py
349 passed, 1 skipped in 17.86s
```

Green, consistent with round 21's resolution note (344 passed, 1 skipped —
the delta is the audit-trail feature's own new tests plus whatever the
currently-uncommitted `consult_tools.py`/`contracts.py` changes added).
`tests/test_real_forensic_image_evidence.py` was excluded per the task's own
instruction (documented pre-existing hang, under separate investigation) and
was not otherwise touched.

## Threat model

- The attacker can send requests to the API if the operator binds it off
  `127.0.0.1` (R21-01, still true, re-verified below).
- The attacker can control the `question` field of an investigation proposal
  and the content of a chat message.
- The attacker can run two (or more) HTTP requests concurrently against the
  same case.
- A separate, weaker precondition is named explicitly wherever a finding
  needs it: the attacker already has local filesystem write access to a
  case directory under `cases_root` (not the same as controlling the API —
  this is a stronger capability, and every finding that needs it says so).
- The attacker cannot modify ZAYNOR's own source code, the local kernel, or
  a result after `AuthoritySeal` has covered it. A hash/HMAC chain in this
  system proves integrity of what it covers, never that the underlying tool
  call or narration is "correct" — noted where relevant, not sold as a break.

## Epistemic legend

`CODE FACT` = directly observable in the live source, no inference needed.
`PLAUSIBLE HYPOTHESIS` = architecturally plausible, not executed.
`CONFIRMED BY INDUCTION` = a prediction was deduced and then actually
executed against live code (real threads, real subprocess calls, real
files), and the predicted effect was observed.
`FALSIFIED` = the prediction was executed and did not hold.

## Executive summary

| ID | Severity | Level | Module | Finding |
| --- | --- | --- | --- | --- |
| R22-01 | High | CONFIRMED BY INDUCTION | `api.py` investigation ledger | Concurrent proposals for the same case_id race; the loser's real, already-executed observation is silently dropped |
| R22-02 | Medium (precondition-dependent) | CONFIRMED BY INDUCTION | `audit_log.py` | `AuditLog` follows a pre-placed symlink at the audit-log path instead of rejecting it, unlike the rest of the codebase's symlink-rejection convention |
| R22-03 | Low/Medium | CONFIRMED BY INDUCTION | `api.py` `get_case_evidence` | A tampered/drifted evidence directory causes an absolute server filesystem path to leak into the HTTP error message |
| R22-04 | Low (today) | CODE FACT | `audit_log.py` | `load_entries`/`verify_with_report` have no byte/entry cap, unlike the `_read_bounded` convention R21-05 established; not currently remotely triggerable because no API-reachable path writes `TOOL_INVOKED` entries |
| R21-01 | Alta condicional (unchanged) | CODE FACT | `api.py`/`cli.py` | Re-verified: `--host 0.0.0.0` still has no authentication |
| R21-06 | Baja/Media (unchanged) | CODE FACT | `pyproject.toml` | Re-verified: still no Python lockfile in the tree |
| R21-07 | Media condicional (unchanged) | CODE FACT | `zaynor_mcp_client.py` | Re-verified: `VigiaMCPClient.call_tool()` still has no allowlist of its own |

## Findings

### R22-01 — Lost update between concurrent investigation proposals for the same case

**Level:** CONFIRMED BY INDUCTION
**Bucket:** vulnerability (availability of the audit trail / correctness of
the investigation record), under the threat model where the attacker can
issue two overlapping HTTP requests
**Severity:** High — this is exactly the kind of "observation executed but
not recoverable" gap round 21 flagged as R21-04 and left open; this
confirms a second, distinct mechanism that reaches the same broken outcome
without needing any crash or injected fault at all — ordinary concurrency
is enough.

**Surprise / expectation violated:** the house docstring for
`_save_investigation_state` explicitly frames R21-03's fix as closing "the
atomicity gap," and both new R21-03 regression tests exercise a single
request. Nothing in `propose_investigation` documents or enforces that two
requests for the same case cannot run at once.

**Abduction:** `propose_investigation` (`src/zaynor/api.py:668-719`) is a
plain read -> compute -> write cycle with no lock:
1. `state = _load_investigation_state_or_error(case_id, output_root, seal.sha256)` reads `investigation.json` (or the empty default) at the *start* of the request.
2. `investigator.propose_and_execute(question=req.question)` calls the (mocked in tests, real in production) LLM, then runs the real, deterministic MCP tool call.
3. `_save_investigation_state(case_id, output_root, state)` performs a full-file atomic replace (`tempfile.NamedTemporaryFile` + `fsync` + `os.replace`), but replaces the *entire ledger*, not a merge of it.

If two requests for the same `case_id` both pass step 1 before either
reaches step 3, both compute their own new session built from the *same*
stale base, and the second `os.replace` in program order wins — the first
request's proposal and observation (an observation that really executed a
tool call) vanish from the persisted ledger, even though nothing crashed
and no file was corrupted (`_save_investigation_state`'s own atomicity
guarantee holds perfectly; it just atomically replaces with the wrong,
stale-based content).

**Deduction (prediction, stated before running anything):** launching two
threads that both call `propose_investigation("CASE-X", ...)` for the same
case, synchronized so both load state before either saves, will result in
`investigation.json` containing only **one** of the two proposals/
observations, even though both HTTP calls return `200`/success with a real,
distinct `requested_tool` result each.

**Induction:** ran a real script (`/tmp/.../scratchpad/repro_race.py`,
Python 3.12, this repo's actual `pytest`-free code path, `mcp` library as
installed in this environment) against a real frozen+analyzed case
(`freeze` + `analyze` via the actual vendored engine harness used by
`tests/test_api.py`'s own `_analyzed_case` fixture). `OllamaClient.generate`
was monkeypatched only to avoid depending on a running Ollama daemon; the
MCP tool call itself was real (`verify_custody` -> the vendored VIGÍA
bridge subprocess, the same path `test_propose_investigation_runs_a_real_deterministic_tool_call`
exercises). A `threading.Barrier(2)` inside the monkeypatched `generate()`
forces both threads to have already loaded `investigation.json` before
either proceeds to execute its tool call and save.

Observed:
```
results: {'B': 'verify_custody', 'A': 'verify_custody'}
errors: {}
persisted proposals: ['P-001']
persisted observations: 1
both threads completed successfully: True
```
Both threads' HTTP-equivalent calls succeeded (`errors == {}`), both really
executed `verify_custody` against the real MCP bridge, but only one
proposal/observation survives on disk. The prediction held.

**Causal chain:**
```
request A: load investigation.json (0 proposals)
request B: load investigation.json (0 proposals)   <- same stale base
request A: LLM proposes P-A -> policy ok -> real MCP call executes
request B: LLM proposes P-B -> policy ok -> real MCP call executes
request B: save (1 proposal: P-B)  -- os.replace, atomic, correct write
request A: save (1 proposal: P-A)  -- os.replace, atomic, overwrites B's write
=> investigation.json now shows only P-A; P-B's real, executed
   observation is unrecoverable from the ledger, indistinguishable from
   "never asked"
```

**Threat-model precondition:** the attacker needs the ability to fire two
requests against the same case_id close enough in time — any client of the
API (including two legitimate operator tabs, or two automated retries) can
do this; no elevated capability is required. This is not a
threat-model-assumption finding wearing a costume; it is a real defect
reachable by the API's own advertised contract.

**Note on precision:** this does not corrupt `investigation.json` (the file
is always well-formed JSON — `_save_investigation_state`'s atomicity
guarantee from R21-03 is intact) and it does not touch the sealed
authoritative result at all (`authoritative_result_unchanged` stays `True`
throughout). The break is narrower and still real: **the persisted
investigation record can silently lose a real, already-executed
observation to a second, unserialized writer** — a chain-of-custody gap for
the investigation ledger specifically, not for the sealed verdict.

### R22-02 — `AuditLog` follows a pre-placed symlink instead of rejecting it

**Level:** CONFIRMED BY INDUCTION
**Bucket:** vulnerability, conditional on a threat-model precondition
(attacker already has local filesystem write access to the case directory
*before* `AuditLog` is constructed there)
**Severity:** Medium — real write-through-symlink primitive, but gated by a
strong precondition; downgraded from High for that reason

**Surprise / expectation violated:** the rest of this codebase treats
symlink rejection as a load-bearing, repeated invariant —
`PathGuard.validate` walks every path component with `lstat`,
`cli.py::_atomic_json_write` explicitly checks `path.is_symlink()` before
writing, `cli.py::_fixture_path`/`_directory_path` reject any symlink
component, and `api.py::_save_investigation_state` checks
`path.exists() and path.is_symlink()` before its own atomic write. Nothing
in `audit_log.py` — the module whose whole purpose is tamper-evidence —
performs the equivalent check on `self._path` or `self._tail_path`.

**Abduction:** `AuditLog.__init__` -> `_resume()` opens `self._path` for
reading without checking whether it is a symlink; `AuditLog.append()` opens
it in append mode (`"a"`) and writes the tail sidecar via
`Path.write_text()`, again with no symlink check; the static
`load_entries`/`verify_with_report` do the same on read. If an attacker can
place a symlink named `audit.jsonl` at the expected path inside a case
directory *before* the trusted `freeze`/`analyze` CLI pipeline constructs
an `AuditLog` there, every one of those operations will silently follow the
symlink instead of failing closed.

**Deduction:** constructing `AuditLog(symlink_path, case_id=...)` where
`symlink_path` is a symlink pointing at an empty file outside the case
directory, then calling `.append(...)`, should write the (bounded,
non-attacker-chosen-content, but real) audit entry into the symlink's
*target* file, not raise `SYMLINK_DETECTED_IN_PATH` or any equivalent
rejection the rest of the codebase uses.

**Induction:** ran two real scripts directly against the live
`zaynor.audit_log` module (no mocking):
1. Pre-created `audit_path` as a symlink to a non-empty, non-JSON file. `AuditLog(audit_path, case_id=...)` followed the symlink on construction (`_resume()`), read the target's real content, and crashed with an *uncaught* `json.decoder.JSONDecodeError` trying to parse it as an audit record — confirming the symlink is followed, not detected, even on the read side.
2. Pre-created `audit_path` as a symlink to an *empty* file so `_resume()` succeeds cleanly, then called `.append("CASE_FROZEN", {"x": 1}, reason=...)`. Observed: the target file (outside the case directory) now contains the real, well-formed JSON audit entry; `audit_path.is_symlink()` was still `True` throughout — nothing detected or rejected it.

```
audit_path is_symlink before: True
target content after append:
{"action":"CASE_FROZEN","case_id":"INC-SYMLINK", ... "seq":1}
```

**Causal chain:**
```
attacker (local fs write access to the case dir) pre-places
  cases_root/<case_id>/audit.jsonl -> /some/writable/target
operator runs `zaynor freeze`/`zaynor analyze` on <case_id> (trusted action)
  -> AuditLog(cases_root/<case_id>/audit.jsonl, case_id=...)
  -> _resume() opens the symlink target, not the nominal path
  -> append() opens the symlink target in "a" mode and writes a real entry
=> a bounded but real audit-shaped JSON line gets appended to whatever
   file the attacker's symlink pointed at, and the case's own audit.jsonl
   silently never exists as a real file at all
```

**Threat-model precondition, stated honestly:** this requires the attacker
to already have write access to (or the ability to create) the case
directory's contents before the trusted pipeline runs — a stronger
capability than "can call the API." It is not equivalent to remote code
execution, though: an attacker who can write into `cases_root/<case_id>/`
but who does *not* otherwise control the ZAYNOR process (e.g. a
lower-privileged local account sharing a `cases_root` mount, or a step
earlier in an automated pipeline that stages case directories before
`zaynor freeze` runs) gains a genuine "the trusted process will append
bounded, non-attacker-chosen content into a file of the attacker's
choosing" primitive that the rest of the codebase's symlink-rejection
pattern was specifically built to close everywhere else it applies. The
finding is that `audit_log.py` is inconsistent with its own neighbors, not
that this is a remotely-triggerable API bug — the API's own `get_case_audit_trail`
and `cli.py`'s `_run_audit_trail` both only check `case_dir.is_symlink()`,
never `audit.jsonl` itself, so the same gap is reachable from both
call sites identically (no CLI/API divergence here — see the falsified
vector below).

### R22-03 — Absolute server filesystem path leaks into an HTTP error message on evidence drift

**Level:** CONFIRMED BY INDUCTION
**Bucket:** vulnerability (information disclosure), threat-model dependent
on the evidence directory having drifted from its sealed manifest (which
itself implies either tampering or a real integrity fault worth surfacing)
**Severity:** Low/Medium — real disclosure of `cases_root`'s absolute path
on the server, but only triggered in a state (evidence-vs-manifest
mismatch) that already requires local write access to the evidence
directory to produce, and it only discloses a path, not evidence content or
credentials

**Surprise / expectation violated:** task item 4 explicitly asks whether
any route leaks internal file paths or stack traces. `api.py`'s general
pattern for surfacing `FrozenSnapshotError` is `f"evidence could not be
re-verified: {exc}"` (`api.py:660`) — but `frozen_snapshot.py`'s own error
messages (`_inventory`, lines 55/59/90) interpolate a `Path` object
(`path`) built from `root.rglob("*")`, where `root` is the server's
absolute `evidence_dir` — not the case-relative path `_validated_entries`
uses elsewhere in the same module (`entry.relative_path`, lines 76/78).
That inconsistency inside `frozen_snapshot.py` itself (some error paths
relative, others absolute) is what actually leaks.

**Abduction:** if the evidence on disk diverges from the manifest after
freezing — most directly, a symlink appearing inside the evidence tree,
which `_inventory` checks before anything else — the raised
`FrozenSnapshotError` message will contain the full absolute path
(`cases_root/<case_id>/evidence/...`), and `api.py`'s
`get_case_evidence` route forwards that string verbatim into the client-
facing `ApiError.message`.

**Deduction:** freezing and analyzing a real case, then placing a symlink
inside its evidence directory (simulating post-freeze tampering or a local
integrity fault), then calling the `/cases/{case_id}/evidence` route
handler directly should raise an `ApiError` whose `.message` contains the
server's absolute `cases_root` path.

**Induction:** ran a real script: froze + analyzed `INC-LEAK` via the
actual CLI (`zaynor.cli.main`), then created
`cases_root/INC-LEAK/evidence/collected/evil_link -> /etc/passwd` after
sealing, then called `get_case_evidence`'s route function directly (no
mocking of `_evidence_payload`/`FrozenSnapshotError`). Observed:
```
status: 422 code: invalid_authority
message: evidence could not be re-verified: frozen evidence contains
symlink: /tmp/zaynor-leak-i_mv8zza/cases/INC-LEAK/evidence/collected/evil_link
contains absolute cases_root path: True
```
The prediction held exactly.

**Causal chain:**
```
evidence directory drifts from its sealed manifest (symlink added,
  a local integrity fault, or post-freeze tampering)
  -> _validated_entries -> _inventory(evidence_dir) raises
     FrozenSnapshotError(f"... symlink: {path}")   <- absolute path here
  -> api.py's get_case_evidence catches it and wraps it verbatim
     into ApiError(422, ..., f"evidence could not be re-verified: {exc}")
  -> the flat REST error shape (_rest_error_response) ships that string
     straight to the HTTP client
```

**Threat-model precondition:** reaching this state already requires local
write access to the case's evidence directory (the same precondition class
as R22-02) — a client that can only call the HTTP API cannot manufacture
this condition on demand. What the finding adds is that *once* that
precondition holds (whether from an actual attacker or an operational
fault), the resulting error response discloses the server's install layout
to any caller who can reach `/cases/{case_id}/evidence`, including a caller
under R21-01's no-auth threat model — the two findings compound.

### R22-04 — No byte/entry cap on `AuditLog.load_entries`/`verify_with_report`

**Level:** CODE FACT (the missing cap); PLAUSIBLE HYPOTHESIS capped for
"remotely exploitable resource exhaustion" — deliberately not claimed
higher, see below
**Bucket:** hygiene / resource-exhaustion-review, explicitly not sold as an
active remote DoS today
**Severity:** Low today; worth closing before it becomes a real hole

**Surprise / expectation violated:** round 21 (R21-05) established a
concrete convention for exactly this class of gap — `ollama_client.py`'s
`_read_bounded()` caps every response read before it is parsed. `audit_log.py`
was written this session, after that convention existed, and does not
follow it: `load_entries` and `verify_with_report` both iterate
`path.open("r")` line-by-line with no maximum file size, line count, or
entry count, and `api.py::get_case_audit_trail` returns every entry
`load_entries` produces in one JSON response with no pagination.

**Abduction and the refutation attempt (Eco's razor):** the boring/benign
explanation is "this doesn't matter because nothing attacker-reachable
writes enough entries to make it matter." Checked directly: `grep` for
every call site of `tools.py::audited_tool` (the only code that appends
`TOOL_INVOKED`/`TOOL_SUCCEEDED`/`TOOL_FAILED`) shows it is applied inside
`ReadOnlyToolRegistry` in `tools.py` itself, and `ReadOnlyToolRegistry` has
**zero** consumers anywhere else in `src/zaynor/` — it is not wired into
`api.py`'s `propose_investigation` route (`agents/investigator_tools.py`'s
real handlers call `_run_mcp_call` directly, with no `AuditLog` involved at
all). The only code that ever calls `AuditLog.append()` today is
`cli.py::_run_freeze` and `cli.py::_run_analyze` — both local,
trusted-operator CLI commands, each contributing a small, fixed number of
entries per invocation (1 and 2 respectively). **The benign explanation
survives**: as wired today, nothing reachable from the API can grow
`audit.jsonl` at all, so this is not currently a remote resource-exhaustion
vector. It remains a real code fact and a real inconsistency with the
established convention, worth fixing before `ReadOnlyToolRegistry` (or any
future TOOL_INVOKED wiring on the investigation path) gets connected to
anything the API exposes — at that point this becomes exactly the kind of
gap R21-05 closed for Ollama.

**Induction (measuring the actual cost, to make the hygiene claim concrete
rather than hand-wavy):** appended 20,000 synthetic entries directly via
`AuditLog.append()` (not through any API path — this required calling the
class directly, consistent with "nothing reachable does this today") to
produce a real 6.7 MB `audit.jsonl`, then called the real
`get_case_audit_trail` route function against it:
```
audit.jsonl size bytes: 6738260  entries: 20000  write time s: 1.74
route returned total_entries: 20001  chain_valid: True  read time s: 0.19
```
The route re-verifies the whole HMAC/hash chain and returns every entry
with no truncation in ~0.2s at this size — cheap today, but unbounded, and
the response payload grows linearly with whatever ends up in the file.

**Recommendation (recorded, not applied — this task is investigate-only):**
apply the same `_read_bounded`-style cap (max file size before parsing, or
a max entry count) to `load_entries`/`verify_with_report`, and consider
pagination on `get_case_audit_trail`/`_run_audit_trail` before wiring any
attacker-influenceable path to `AuditLog.append()`.

## Re-verification of round 21's still-open items

Per the task's explicit instruction, these are not re-reported as new
findings — each was re-read against the current live code in this session.

- **R21-01 (no auth off-loopback):** unchanged. `grep` for
  `api_key`/`Authorization`/`Bearer`/`X-API-Key` across `api.py`/`cli.py`
  returns nothing; `serve_parser.add_argument("--host", default="127.0.0.1", ...)`
  still allows an explicit non-loopback bind with no authentication layer
  added anywhere in `create_app`. No regression, no silent fix.
- **R21-06 (no Python lockfile):** unchanged. No `uv.lock`, `poetry.lock`,
  or hashed `requirements*.txt` present in the repository root.
- **R21-07 (`VigiaMCPClient` has no allowlist of its own):**
  unchanged. `VigiaMCPClient.call_tool()` (`zaynor_mcp_client.py:238-255`)
  still forwards any `name`/`arguments` pair straight to
  `session.call_tool(name, arguments)` with no allowlist check; the
  restriction still lives entirely in `InvestigatorToolAdapter` +
  `agents.policy.authorize_tool()`, one layer up, exactly as the round 21
  resolution described.

R21-02, R21-03, and R21-05 were confirmed resolved by round 21's own
resolution document and were spot-checked again in this session (the
`asyncio.wait_for` wrapping in `zaynor_mcp_client.py`'s `__aenter__`/
`list_tools`/`call_tool`, the atomic-write + `InvestigationLedgerCorrupted`
pair in `api.py`, and `_read_bounded` in `ollama_client.py` are all present
and unchanged in the live file) — no regression found in any of the three.

## Discarded (non-exploitable) vectors

| Vector | Result | Why it failed |
| --- | --- | --- |
| Trailing slash on `/v1/chat/completions/` bypasses the OpenAI-vs-REST error-shape dispatch | FALSIFIED | Starlette issues a real `307` redirect to the canonical path first (confirmed with `follow_redirects=False`); the handler always sees the canonical `request.url.path`, so the dispatch in `api_error_handler` never sees the trailing slash |
| Query string on `/v1/chat/completions?x=1` changes `request.url.path` | FALSIFIED | `Request.url.path` excludes the query string by construction; the dispatch check is unaffected |
| Case difference (`/V1/Chat/Completions`) reaches the handler with the wrong shape | FALSIFIED | FastAPI routes are case-sensitive; an unmatched path returns Starlette's generic `404 {"detail":"Not Found"}` before any `ApiError`/`api_error_handler` logic runs at all |
| CORS origin reflection / bypass (arbitrary `Origin`, `null`, or a subdomain-suffix trick against `http://localhost:8080`) | FALSIFIED | `Access-Control-Allow-Origin` is only echoed for the two configured origins in every case tested (`http://evil.example`, `null`, `http://localhost:8080.evil.com` all got no ACAO header); confirms CORS is correctly configured, but also confirms (as R21-01 already implies) that CORS is a browser-only control — a non-browser client gets the full `200` response regardless of `Origin`, so this was never a meaningful boundary by itself |
| CLI's `_run_audit_trail` and the API's `get_case_audit_trail` apply different case-path checks (task's specific hint to check for CLI/API drift) | FALSIFIED | Both check `_SAFE_CASE_ID.fullmatch(case_id)` first, then `case_dir.is_symlink() or not case_dir.is_dir()`, in the same order, with the same effect; neither checks `audit.jsonl` itself for a symlink (that is R22-02, and it affects both identically, not one more than the other) |
| Malformed/adversarial LLM JSON escapes `InvestigationProposal`'s strict field/type validation | FALSIFIED | `parse_proposal` enforces exact field-set equality (`_PROPOSAL_FIELDS`), rejects any `_FORBIDDEN_AUTHORITY_FIELDS` key, and `InvestigationProposal.__post_init__` requires `arguments` to be a `Mapping`, rejects floats recursively, and bounds the canonical JSON to 64 KiB; every deviation raises `InvestigationContractError`/`InvestigationRunnerError`, caught in `api.py` as `policy_rejected` (422) |
| `VigiaMCPClient.__aexit__` lacks a timeout on `stack.aclose()` while `AuxiliaryMCPClient` looked like it had one, suggesting new drift | FALSIFIED | `AuxiliaryMCPClient` only wraps `aclose()` in `asyncio.wait_for(..., 1.0)` on its `__aenter__` *failure* cleanup path; its own `__aexit__` (the normal close path) is just as unguarded as `VigiaMCPClient`'s. Both clients share the same pre-existing gap symmetrically — not new drift introduced by either |
| Investigation ledger file path (`output_root/case_id/investigation.json`) is attacker-influenced beyond the case_id itself | FALSIFIED | `case_id` reaches `_investigation_state_path` only after `_load_case_for_overview` has already enforced `_SAFE_CASE_ID.fullmatch(case_id)`; no additional user-controlled path component exists |

## Commands and scripts run

```
PYTHONPATH=src python3 -m pytest -q --ignore=tests/test_real_forensic_image_evidence.py
# 349 passed, 1 skipped

# R22-01 (race): scratchpad/repro_race.py -- real threads, real freeze+analyze
# via zaynor.cli.main, real vendored-engine subprocess, real MCP call
# (verify_custody against the vendored VIGIA bridge), OllamaClient.generate
# monkeypatched only to avoid depending on a running Ollama daemon.

# R22-02 (symlink): two inline scripts constructing AuditLog directly
# against a pre-placed symlink at the audit.jsonl path.

# R22-03 (path leak): inline script -- real freeze+analyze via zaynor.cli.main,
# a symlink added to the evidence directory after sealing, then
# api.get_case_evidence's route function called directly.

# R22-04 (unbounded read): inline script -- 20,000 real AuditLog.append()
# calls, then api.get_case_audit_trail's route function called directly
# against the resulting 6.7 MB audit.jsonl.

# CORS / error-shape dispatch probes: inline scripts using
# fastapi.testclient.TestClient against a real create_app() instance.
```

None of these scripts were added to the repository; they were run from a
scratch directory outside the tree and discarded after use, per the task's
instruction to investigate only.

## Suggested next order of work (recorded only, not actioned this session)

1. Serialize (or optimistically version-check) writes to
   `investigation.json` per case_id — R22-01 is the highest-severity finding
   in this round and is reachable by ordinary concurrent API use, no
   special privilege required.
2. Bring `audit_log.py`'s path handling up to the same symlink-rejection
   standard already used by `PathGuard`, `_atomic_json_write`, and
   `_fixture_path`/`_directory_path` — R22-02.
3. Make `frozen_snapshot.py`'s `_inventory` report case-relative paths (the
   way `_validated_entries` already does for its own error messages)
   instead of the absolute `Path` it currently interpolates — R22-03.
4. Add a byte/entry cap to `AuditLog.load_entries`/`verify_with_report`
   before any future change wires `ReadOnlyToolRegistry`'s
   `TOOL_INVOKED`/`TOOL_SUCCEEDED`/`TOOL_FAILED` auditing into an
   API-reachable path — R22-04.
5. R21-01/R21-06/R21-07 remain open, unchanged, and are still the
   maintainer's decisions to make, not code defects to patch reactively.
