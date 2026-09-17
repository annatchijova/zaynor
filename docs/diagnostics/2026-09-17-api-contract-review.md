# OpenAI-compatible API review — 2026-09-17

## Scope

Step 4 reviewed the live `create_app()` implementation and its existing API
tests. No scorer, authoritative schema, or chat-path changes were required.

## Verified controls

- `req.model` must equal the exposed `zaynor-forensic` model id.
- `stream=true` is rejected with a structured 400 error; streaming is not
  simulated.
- Completion ids use UUIDs rather than timestamp-only ids.
- Operational failures use structured HTTP errors, including malformed
  requests, missing cases, invalid authority, and unavailable Ollama.
- `/cases` reports artifact presence as `NOT_CHECKED`; file presence is not
  treated as cryptographic verification.
- Unknown token usage is omitted rather than reported as measured zero.
- CORS allows only the configured localhost origins, never `*`.
- CLI and HTTP narration continue to use the shared verified chat path.

## Tests

```text
env PYTHONPATH=src pytest -q tests/test_api.py
```

The existing direct route tests cover the controls above. An exploratory
`TestClient` test was not retained because it blocked on the first request in
this environment, while the route-level tests complete deterministically.
