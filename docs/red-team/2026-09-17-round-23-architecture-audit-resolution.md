# Resolución — round 23, auditoría de arquitectura de backend

**Fecha:** 2026-09-17
**Responde a:** auditoría de arquitectura de backend (FSA + DDIA) pasada por
Anna directamente en el chat, no un archivo en `docs/red-team/`.
**Autor de esta resolución:** Claude (los hallazgos GAP-01..GAP-10 son de
un auditor externo; se re-verificaron contra el código vivo antes de
tocar nada — CLAUDE.md §4.1. GAP-04 ya estaba resuelto por round 22, no
por este auditor; se lo marcó así en la respuesta previa).

## Resueltos

### GAP-01 — `zaynor audit` nunca verificaba la cadena de auditoría

`compute_case_audit` ahora llama a `AuditLog.verify_with_report` sobre el
`audit.jsonl` real del caso. Semántica: cadena rota o directamente ausente
→ `overall: FAILED` (un caso analizado siempre tiene una; su ausencia es
sospechosa, no neutra). Cadena válida en modo hash-only (sin
`ZAYNOR_HMAC_KEY`) → sigue `VERIFIED`, con el caveat en el nuevo campo
`chain` (CLAUDE.md §5.3: un WARN no es un FAIL). También cruza
`RESULT_SEALED` contra el `seal.sha256` guardado (ver GAP-05). Expuesto en
`_audit_status_payload`/`GET /cases/{id}` como campo `chain` nuevo,
aditivo — no rompe el contrato existente. 3 tests nuevos en
`test_cli.py`: caso sano → `chain: VERIFIED...`, cadena tampereada →
`overall: FAILED`, cadena ausente → mensaje explícito, no `VERIFIED`
silencioso.

### GAP-02 — el sello versiona el algoritmo, no la forma del payload

Dos cambios independientes en `authority_seal.py`/`schemas.py`:

1. `_typed()` usaba `f"{__module__}.{__qualname__}"` como nombre del
   dataclass en el payload canónico — mover una clase de módulo invalidaba
   todo sello histórico. Ahora cada dataclass sellable declara su propio
   `_CANONICAL_TYPE_NAME` (ClassVar, no toca `fields()`); `_typed` lo usa
   si existe, cae al comportamiento viejo si no.
2. Nuevo campo `schema_version` en `ZaynorAuthoritativeResult`
   (`RESULT_SCHEMA_VERSION = "zaynor-result-v1"`). `verify_authoritative_result`
   lo chequea ANTES de la comparación genérica de digest y lanza
   `SchemaVersionMismatch` (subclase de `SealError`, distinguible) en vez
   de la misma "seal mismatch" que produce un tamper real.

Sin ADR de migración: no hay sellos reales en producción que preservar
(hackathon, pre-lanzamiento) — el propio hallazgo lo señala como el punto
que hace esto seguro de resolver ahora sin plan de compatibilidad. Efecto
hacia adelante únicamente: no puede identificar retroactivamente datos que
nunca tuvieron el campo. 2 tests nuevos en `test_authority_seal.py`: mover
la clase no cambia el sello; `schema_version` distinto produce
`SchemaVersionMismatch`, un tamper real bajo el mismo `schema_version`
sigue siendo el `SealError` genérico de siempre (el fix no debilita la
detección real).

### GAP-03 — append + ancla de cola sin fsync ni atomicidad

`AuditLog.append` ahora hace `flush()` + `os.fsync()` sobre el JSONL antes
de tocar el ancla, y escribe `.tail` vía tempfile + fsync + `os.replace`
(mismo patrón que `cli.py::_atomic_json_write`). Test de inducción:
monkeypatch de `os.fsync` confirma 2 llamadas reales (una por archivo), y
confirma que no queda ningún temporal huérfano tras el `replace`.

### GAP-05 — `RESULT_SEALED` se registraba después de escribir los archivos

`_run_analyze` ahora appendea `RESULT_SEALED` (con el digest ya calculado)
ANTES de `_atomic_json_write` sobre `result.json`/`result.seal.json`. El
estado alcanzable ante un crash pasa de "hay un resultado sellado sin
ningún registro" (invisible) a "hay un registro de sellado sin archivo
todavía" (detectable, y ahora efectivamente detectado por GAP-01's chequeo
cruzado).

### GAP-06 — la clave HMAC no tiene identidad; el modo degradado no distingue rotación de forjado

Agregado `hmac_chain.key_id(key)` (fingerprint público, no la clave) a
cada entrada firmada y al ancla de cola. `verify_with_report` ahora nombra
el `key_id` en los mensajes de mismatch ("wrong key or forged chain,
entry was signed with key_id=..."). No implementa rotación real
(aceptar más de una clave viva es una decisión de producto que este fix
no toma) — da a un humano algo con qué actuar en vez de una acusación
ciega de forjado. Tests nuevos en `test_audit_log.py`.

### GAP-08 — sin modelo de lectura derivado para `/cases`

`_run_analyze` ahora escribe una entrada en `output_root/index.json`
(case_id, verdict, result_sha256, updated_at) tras sellar. `GET /cases`
la lee si existe y la usa para `verdict`/`updated_at` — `verification` y
`seal_status` siguen `NOT_CHECKED`/`UNKNOWN` siempre, el índice nunca
sustituye una verificación real. Nuevo comando `zaynor reindex
--output-root ...` reconstruye el índice desde cero re-verificando cada
caso real en disco (un caso que ya no verifica queda simplemente afuera,
no se reporta con datos viejos). Test existente actualizado
(`test_cases_lists_only_analyzed_cases`) para reflejar el verdict real en
vez de `UNKNOWN` hardcodeado.

### GAP-10 — `_resume()` continuaba una cadena sin verificarla

`AuditLog._resume()` ahora corre `verify_with_report` (en modo
estructural, `hmac_key=None`, para no romper la transición legítima de
hash-only a modo HMAC) antes de aceptar continuar un log preexistente.
Una cadena rota rechaza el `append` en vez de extenderse silenciosamente
sobre la manipulación previa. Tests nuevos: reabrir un log tampereado
falla cerrado; una transición legítima hash-only → HMAC no se rechaza.

## No tocados, con motivo

- **GAP-04**: ya estaba resuelto por round 22 (R22-01: lock por caso +
  escritura atómica del ledger de investigación). El auditor lo describió
  contra una versión del código anterior a ese fix — falso hoy, confirmado
  contra el código vivo antes de descartarlo.
- **GAP-07** (fitness functions estructurales / gate de CI): el propio
  auditor citó `.github/workflows/ci.yml` desde una rama sin mergear
  (`origin/pr-12`). Un `merge` real de esa rama de CI/SDLC llegó a `main`
  en medio de esta misma sesión (ver nota de colisión abajo) — con esa
  pieza recién aterrizada, decidir dónde entra un test estructural de
  fronteras de import es una conversación aparte, no un parche de esta
  pasada.
- **GAP-09** (extraer `application.py` fuera de `cli.py`): refactor
  puramente mecánico, sin beneficio de corrección por sí solo, alto riesgo
  de tocar los tres bordes (CLI/API/MCP server) y sus tests bajo presión
  de tiempo. Descartado esta ronda; GAP-01 (su principal justificación) ya
  se resolvió sin necesitarlo.

## Nota de colisión concurrente durante esta pasada

En medio de este trabajo, este mismo checkout de `main` recibió un merge
real desde `origin/main` (trayendo `679300e`, el trabajo de CI/SDLC de
otra rama) — confirmado en `git reflog` con un `reset: moving to HEAD`
inmediatamente antes del merge. Efecto detectado: un edit mío ya aplicado
a `tests/test_api.py` (el ajuste de `test_cases_lists_only_analyzed_cases`
para GAP-08) desapareció del working tree entre una corrida de tests y la
siguiente. Se detectó por `git diff` vacío contra HEAD donde debería haber
diff, se re-aplicó, y se re-corrió la suite completa para confirmar que
no quedó nada más perdido (comparando `git status --short` antes/después).
Ningún otro archivo de esta ronda mostró el mismo síntoma.

## Verificación

```text
PYTHONPATH=src pytest -q --ignore=tests/test_real_forensic_image_evidence.py \
  --deselect tests/test_agents.py::test_untrusted_context_cannot_close_its_markup_delimiter_verbatim
362 passed, 1 skipped
```

El deselect es un WIP no comiteado y ajeno (edit en curso de otra sesión
sobre `agents/contracts.py`, confirmado por `git diff` mostrando cambios
sin commitear que no son de esta pasada) — no se tocó.
