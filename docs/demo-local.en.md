# ZAYNOR local demo — terminal-first guide

This is the complete procedure to run and record a local ZAYNOR demo with
VIGÍA, Ollama, the OpenAI-compatible API, OpenWebUI, the frontend, and MCP.
The procedure never analyzes a case from chat.

Selected case: `case_026_ventrilocuo_process_hollowing`.

The case combines a legitimate binary with an anomalous path, RWX memory
containing a PE not backed by disk, an incorrect parent process, persistence,
and exfiltration.

## Variables

```bash
export ZAYNOR=/home/labestiadevigia/zaynor
export DEMO_CASE=case_026_ventrilocuo_process_hollowing
export DEMO_CASES=/tmp/zaynor-demo-cases
export DEMO_OUTPUT=/tmp/zaynor-demo-output
export OLLAMA_HOST=http://127.0.0.1:11434
export OLLAMA_MODEL=hermes3:8b
```

## Prepare and analyze

```bash
cd "$ZAYNOR"
python3 --version
ollama list
python3 -m pip install -e '.[api]'

python3 - <<'PY'
import json
from pathlib import Path
Path('/tmp/zaynor-case-026-profile.json').write_text(
    json.dumps({'process-hollowing-demo': ['case_026_ventrilocuo_process_hollowing.json']}, indent=2) + '\n',
    encoding='utf-8',
)
PY

rm -rf "$DEMO_CASES" "$DEMO_OUTPUT"

PYTHONPATH=src python3 -m zaynor.cli freeze \
  --case-id "$DEMO_CASE" \
  --evidence-profile process-hollowing-demo \
  --profile-map /tmp/zaynor-case-026-profile.json \
  --source-root casos \
  --cases-root "$DEMO_CASES" --json

PYTHONPATH=src python3 -m zaynor.cli analyze \
  --case-id "$DEMO_CASE" \
  --cases-root "$DEMO_CASES" \
  --output-root "$DEMO_OUTPUT" --json
```

`analyze` is the only stage that invokes VIGÍA and produces the decision.
Chat never re-runs the engine.

## Verify the result and audit trail

```bash
PYTHONPATH=src python3 -m zaynor.cli audit \
  --case-id "$DEMO_CASE" --cases-root "$DEMO_CASES" \
  --output-root "$DEMO_OUTPUT" --json

PYTHONPATH=src python3 -m zaynor.cli audit-trail \
  --case-id "$DEMO_CASE" --cases-root "$DEMO_CASES" --json

sha256sum "$DEMO_OUTPUT/$DEMO_CASE/result.json" \
  "$DEMO_OUTPUT/$DEMO_CASE/result.seal.json"
```

The expected chain is `CASE_FROZEN → ENGINE_INVOKED → RESULT_SEALED`, with
`chain_valid=true`. The expected case result is `MALICE`. Audit timestamps are
inside hashed entries; this demo does not use external trusted timestamping.

## CLI chat

```bash
PYTHONPATH=src python3 -m zaynor.cli chat \
  --case-id "$DEMO_CASE" --output-root "$DEMO_OUTPUT" \
  --model "$OLLAMA_MODEL" --host "$OLLAMA_HOST" --timeout 120 \
  --audience senior \
  --question 'Explain process hollowing, RWX memory, the incorrect parent, and the discrepancy between the disk hash and memory. Do not change or infer another verdict.' \
  --json
```

The guard may remove unverifiable claims or reject the narration. That is
fail-closed behavior and does not change `result.json` or `result.seal.json`.

## Start and test the local API

If `8420` is already occupied, use `8421`:

```bash
cd "$ZAYNOR"
PYTHONPATH=src python3 -m zaynor.cli serve \
  --output-root "$DEMO_OUTPUT" --cases-root "$DEMO_CASES" \
  --host 127.0.0.1 --port 8421 \
  --ollama-host "$OLLAMA_HOST" --model "$OLLAMA_MODEL" --timeout 120
```

In another terminal:

```bash
export ZAYNOR_API=http://127.0.0.1:8421
curl -sS "$ZAYNOR_API/health"
curl -sS "$ZAYNOR_API/v1/models"
curl -sS "$ZAYNOR_API/cases"
curl -sS "$ZAYNOR_API/cases/$DEMO_CASE/audit"
curl -sS "$ZAYNOR_API/cases/$DEMO_CASE/audit-trail"

curl -sS -X POST "$ZAYNOR_API/v1/chat/completions" \
  -H 'content-type: application/json' \
  --data '{
    "model": "zaynor-forensic",
    "stream": false,
    "messages": [{
      "role": "user",
      "content": "case_id: case_026_ventrilocuo_process_hollowing\nExplain the process-hollowing evidence without changing the verdict."
    }]
  }'
```

The API accepts only `model=zaynor-forensic` and rejects `stream=true`.

## OpenWebUI and frontend

OpenWebUI normally runs at `http://127.0.0.1:8080`. Configure its
OpenAI-compatible provider with:

```text
Base URL: http://127.0.0.1:8421/v1
API key: zaynor-local
Model: zaynor-forensic
```

The current API does not validate the API key. The value only satisfies the
field OpenWebUI commonly requires. Keep everything on localhost.

Every question must include the case:

```text
case_id: case_026_ventrilocuo_process_hollowing
What evidence supports the result and what uncertainties remain?
```

Do not connect OpenWebUI directly to Ollama for this demo: that bypasses the
sealed-result verification and authority/hallucination guard.

To start a new frontend instance pointed at `8421`:

```bash
cd "$ZAYNOR/frontend"
NEXT_PUBLIC_ZAYNOR_API_MODE=http \
NEXT_PUBLIC_ZAYNOR_API_BASE_URL=http://127.0.0.1:8421 \
npm run dev -- --hostname 127.0.0.1 --port 3001
```

Open `http://127.0.0.1:3001`. If Next reports an existing server lock, use the
frontend already running on `:3000` or omit it from the recording; do not kill
processes blindly.

## The four MCP surfaces

ZAYNOR documents three auxiliary integrations and one project-owned server:

| MCP | Function | Surface | Authority |
| --- | --- | --- | --- |
| VIGÍA | Bounded local evidence operations | 9 vendored tools | Does not replace the sealed result |
| CRONOS | Reasoning traces, hypotheses, audit | 10 allowlisted tools | Does not produce a verdict |
| MNEME | Bundle custody and verification | 3 allowlisted tools | Does not produce a verdict |
| ZAYNOR | Case-bound memory and audit verification | 6 tools | Cannot mutate result/seal |

### ZAYNOR MCP

```bash
cd "$ZAYNOR"
mkdir -p /tmp/zaynor-mcp-state
ZAYNOR_MCP_STATE_DIR=/tmp/zaynor-mcp-state \
PYTHONPATH=src python3 -m zaynor.zaynor_mcp_server
```

Claude configuration:

```json
{
  "mcpServers": {
    "zaynor": {
      "command": "/usr/bin/python3",
      "args": ["-m", "zaynor.zaynor_mcp_server"],
      "cwd": "/home/labestiadevigia/zaynor",
      "env": {
        "PYTHONPATH": "/home/labestiadevigia/zaynor/src",
        "ZAYNOR_MCP_STATE_DIR": "/tmp/zaynor-mcp-state"
      }
    }
  }
}
```

Tools: `zaynor_info`, `zaynor_verify_audit`, `zaynor_verify_memory`,
`zaynor_list_memory`, `zaynor_add_hypothesis`, and `zaynor_note_question`.

### VIGÍA MCP

The local bridge uses `src/zaynor/vigia_mcp_runner.py` and
`vendor/vigia_engine/vigia/vigia_sift_bridge_min.py`. Its environment must
contain:

```text
VIGIA_EVIDENCE_DIR=/tmp/zaynor-demo-cases/case_026_ventrilocuo_process_hollowing/evidence
VIGIA_LLM_BACKEND=ollama
VIGIA_OLLAMA_HOST=http://127.0.0.1:11434
VIGIA_OLLAMA_MODEL=hermes3:8b
PYTHONPATH=/home/labestiadevigia/zaynor/vendor/vigia_engine
```

Allowlisted tools: `list_files`, `read_evidence`, `search_pattern`,
`generate_forensic_hash`, `calculate_shannon_entropy`, `infer_intent`,
`audit_grice_maxims`, `detect_eco_overinterpretation`, and
`validate_and_correct_analysis`.

### CRONOS and MNEME

Find the real local servers first:

```bash
find /home/labestiadevigia -path '*/cronos/mcp_server.py' -type f -print
find /home/labestiadevigia -path '*/mneme/mcp_server.py' -type f -print
```

CRONOS uses `CRONOS_DB_PATH` and its allowlist is the ten tools documented in
`docs/mcp-locales.md`. MNEME uses `MNEME_DB_PATH` and allows
`mneme_verify_bundle`, `mneme_custody_chain`, and `mneme_info`.

Configuration template:

```json
{
  "mcpServers": {
    "cronos": {
      "command": "/usr/bin/python3",
      "args": ["/REAL/PATH/cronos/mcp_server.py"],
      "env": {"CRONOS_DB_PATH": "/tmp/zaynor-cronos-demo.db"}
    },
    "mneme": {
      "command": "/usr/bin/python3",
      "args": ["/REAL/PATH/mneme/mcp_server.py"],
      "env": {"MNEME_DB_PATH": "/tmp/zaynor-mneme-demo.db"}
    }
  }
}
```

Do not enable grants, claims, authorization, or external side-effect tools.
MCP is auxiliary observation/memory; `result.json` and `result.seal.json`
remain authoritative.

## MCP tests

```bash
cd "$ZAYNOR"
PYTHONPATH=src python3 -m pytest -q \
  tests/test_zaynor_mcp_client.py \
  tests/test_zaynor_mcp_config_security.py -x
```

Current verified result: `11 passed`.

## Recording sequence

1. `freeze`.
2. `analyze`, showing `MALICE`.
3. `audit`, showing `VERIFIED`.
4. `audit-trail`, showing the three-entry chain.
5. `curl` health, models, and cases.
6. Normal chat `curl`.
7. Contradictory-verdict chat `curl`.
8. Repeat `audit` and `sha256sum`.
9. OpenWebUI connected to ZAYNOR.
10. Claude verifies the audit trail through MCP.

More detail about the three auxiliary integrations is in
[`mcp-locales.md`](./mcp-locales.md).
