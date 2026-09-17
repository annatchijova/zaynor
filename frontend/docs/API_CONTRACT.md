# ZAYNOR Frontend API Contract v1

## Status

This is the normative frontend contract for the case console. It is a
frontend/backend agreement, not a replacement for ZAYNOR's Python authority
contracts. The backend owns validation, seals, audit verification, policy,
investigation execution, and all authoritative state.

The TypeScript source of truth is `src/lib/api/contracts.ts`. This document
defines HTTP behavior and semantic rules that cannot be inferred from types
alone.

## General rules

- All identifiers and SHA-256 values are strings.
- Scores and exact values intended for display are strings. The API must not
  use binary floating-point values for any authority-relevant field.
- All timestamps use RFC 3339 UTC strings, or `null` when unavailable.
- JSON uses `snake_case` to match ZAYNOR's Python contracts.
- Every error body uses the `ApiError` shape.
- Every response containing a verdict must identify whether its seal and audit
  are verified.
- Narrative, proposal, observation, and authoritative result remain separate
  objects in every response.

## Current backend and target console API

The current Python API exposes `GET /health`, `GET /cases`, `GET /v1/models`,
and `POST /v1/chat/completions`. The endpoints below are the target console
surface. The frontend begins with `MockApiClient` until the backend implements
them.

| Method | Endpoint | Response | Authority rule |
|---|---|---|---|
| `GET` | `/health` | `SystemHealth` | Health never asserts a forensic verdict. |
| `GET` | `/cases` | `{ cases: CaseSummary[] }` | List metadata only. |
| `GET` | `/cases/{case_id}` | `CaseOverview` | Includes explicit snapshot, result, seal, audit, and investigation layers. |
| `GET` | `/cases/{case_id}/result` | `AuthoritativeResult` | Must derive from a verified stored seal. |
| `GET` | `/cases/{case_id}/audit` | `AuditStatus` | Verification state is backend-computed. |
| `GET` | `/cases/{case_id}/evidence` | `{ evidence: EvidenceArtifact[] }` | Metadata only; never grants mutation. |
| `GET` | `/cases/{case_id}/investigation` | `InvestigationSummary` | Proposals and observations remain non-authoritative. |
| `POST` | `/cases/{case_id}/investigations/proposals` | `InvestigationProposal` | Backend policy must validate the request before creating it. |
| `POST` | `/cases/{case_id}/chat` | `NarrativeAnswer` | Must narrate only a sealed result. |
| `GET` | `/cases/{case_id}/reports/{format}` | `ReportArtifact` | The backend produces the report; the UI only presents it. |

## State vocabulary

### Verdict

```text
MALICE | SUSPICION | ABSTAIN | UNKNOWN | BENIGN
```

Verdicts are top-level result labels. The frontend must not derive one from
findings, scores, framework mappings, proposal state, or observations.

### Finding state

```text
CORROBORATED | CONTRADICTED | INSUFFICIENT
```

The current Mode 1 adapter can also expose a verdict-shaped finding state for
compatibility with the real VIGIA result bundle. The UI must render that value
as received and must not transform it into a top-level verdict.

### Integrity state

```text
VERIFIED | FAILED | UNKNOWN
```

`VERIFIED` may describe a manifest, snapshot, evidence set, audit result, or
authority seal. It never means benign or non-malicious.

### Investigation proposal state

```text
PROPOSED | APPROVED | REJECTED | EXECUTED
```

### Observation state

```text
OBSERVED | UNTRUSTED | FAILED | REJECTED
```

An observation is never a finding and never changes an authoritative result
unless the backend subsequently produces and seals a new result.

## Required case overview shape

```json
{
  "case_id": "CASE-001",
  "snapshot": {
    "status": "VERIFIED",
    "manifest_sha256": "…",
    "evidence_set_sha256": "…",
    "artifact_count": 5,
    "sealed_at": "2026-09-17T12:00:00Z"
  },
  "authoritative_result": {
    "case_id": "CASE-001",
    "verdict": "ABSTAIN",
    "confidence": "UNKNOWN",
    "findings": [],
    "unknowns": [],
    "hypotheses": [],
    "fractures": [],
    "signals": [],
    "result_sha256": "…",
    "engine": {
      "name": "vigia_agent",
      "version": "1.0.0",
      "configuration_hash": "…"
    },
    "audit_refs": []
  },
  "seal": {
    "status": "VERIFIED",
    "result_sha256": "…",
    "canonicalize_version": "zaynor-authority-v1"
  },
  "audit": {
    "status": "VERIFIED",
    "manifest": "VERIFIED",
    "snapshot": "VERIFIED",
    "evidence": "VERIFIED",
    "result": "VERIFIED",
    "seal": "VERIFIED",
    "provenance": "EMPTY",
    "checked_at": "2026-09-17T12:01:00Z",
    "detail": null
  },
  "investigation": {
    "session_id": null,
    "status": "NOT_STARTED",
    "proposals": [],
    "observations": [],
    "authoritative_result_unchanged": true
  }
}
```

## Error response

```json
{
  "code": "CASE_NOT_FOUND",
  "message": "The requested case does not exist.",
  "request_id": "optional-server-request-id"
}
```

The frontend maps known error codes to clear user-facing states. It must not
replace a failed audit or an unavailable model with a success-looking result.

## Compatibility and rollout

1. Frontend uses `MockApiClient` with fixtures conforming to this contract.
2. Backend implements endpoint responses against the same shapes.
3. `HttpApiClient` maps transport errors to `ApiError`.
4. Component contract tests run against both clients.
5. Only after matching output is verified does the application default switch
   from mock to HTTP.

### HTTP client selection

The application selects its client at startup. `mock` is the safe default and
remains active unless HTTP mode is explicitly configured:

```text
NEXT_PUBLIC_ZAYNOR_API_MODE=http
ZAYNOR_API_BASE_URL=http://127.0.0.1:8000
```

`ZAYNOR_API_BASE_URL` is server-only. Server Components use it to reach the
local backend; browser components use the same-origin `/api/zaynor` BFF route.
The BFF exposes only the allowlisted console endpoints and forwards no client
credentials. It also sends `Cache-Control: no-store` for forensic data.

```text
browser -> /api/zaynor (Next.js BFF) -> ZAYNOR_API_BASE_URL -> local FastAPI
```

The BFF allowlist is deliberately narrower than the backend API surface:

- `GET`: `/health`, `/cases`, the documented case resources, report
  descriptors, and report download resources.
- `POST`: `/cases/{case_id}/chat` and
  `/cases/{case_id}/investigations/proposals` only.

It rejects query strings, unsupported methods, malformed case identifiers,
and unrecognized paths before contacting the backend. Mutation requests must
be JSON and are size-limited. The proxy forwards only the method, accepted
content type, and validated JSON body; it never forwards browser cookies,
authorization headers, or arbitrary request headers. It preserves only the
backend response status, content type, and report content disposition.

Server Components must use the private backend client directly. They must not
call `/api/zaynor`, because that creates an unnecessary same-origin HTTP hop
and fails during static builds when no application server is available.

`NEXT_PUBLIC_ZAYNOR_API_MODE` is a non-secret feature flag. Do not expose the
backend URL, credentials, evidence paths, or operator secrets through a
`NEXT_PUBLIC_` variable. Authentication and authorization are deployment
requirements to add only when the backend supplies an operator identity
contract.

`HttpApiClient` validates every successful payload against the TypeScript
contract before returning it to a screen. An invalid payload, an untyped error
body, or a transport failure is surfaced as a typed client error; it is never
coerced into an apparently valid case, seal, narrative, or observation.

The Python service currently exposes an OpenAI-compatible API for chat and a
minimal case list, not the target console surface in this document. Therefore
HTTP mode must not be enabled against that service until it implements the
endpoints and response shapes above.
