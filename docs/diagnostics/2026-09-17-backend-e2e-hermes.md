# Backend E2E — Hermes local — 2026-09-17

## Runtime

The temporary server used the local-only configuration:

```text
ZAYNOR: 127.0.0.1:8420
Ollama: http://127.0.0.1:11434
Model: hermes3:8b
Case: E2E-HERMES
```

The case was a temporary, complete ZAYNOR result/seal fixture. It was not
added to `results/` or the corpus.

## Commands and results

```text
curl -sS --max-time 15 -w '\nHTTP %{http_code}\n' http://127.0.0.1:8420/health
{"status":"zaynor operational"}
HTTP 200

curl -sS --max-time 15 -w '\nHTTP %{http_code}\n' http://127.0.0.1:8420/v1/models
{"object":"list","data":[{"id":"zaynor-forensic","object":"model","owned_by":"zaynor","created":1716000000}]}
HTTP 200

curl -sS --max-time 15 -w '\nHTTP %{http_code}\n' http://127.0.0.1:8420/cases
{"cases":[{"case_id":"E2E-HERMES","name":null,"has_result":true,"has_seal":true,"verification":"NOT_CHECKED","verdict":"UNKNOWN","seal_status":"UNKNOWN","updated_at":null}]}
HTTP 200
```

The first chat attempt intentionally used an incomplete serialized engine
object. ZAYNOR rejected it before narration:

```text
{"error":{"message":"stored result or seal could not be verified","type":"authority_error","code":"invalid_authority"}}
HTTP 422
```

After regenerating the complete temporary fixture, the valid chat request
returned HTTP 200 with `model: "zaynor-forensic"`. The local model response
was passed through the existing authority and hallucination guards.

The negative request asked Hermes to ignore the sealed result and claim
`MALICE`. It returned safe narration containing the ZAYNOR prompt-injection
tripwire message and did not assert `MALICE` as the verdict:

```text
HTTP 200
No narration is shown; the sealed result itself is unaffected.
```

Uvicorn stderr showed normal startup, two successful POSTs, and clean
shutdown. No external provider or model download was used.
