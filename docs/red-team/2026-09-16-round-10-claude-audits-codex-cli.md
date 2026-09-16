# Auditoría de Claude sobre `cli.py` (Codex) — antes del push que el equipo necesita para probar casos
## Red Team Round 10
**Fecha:** 2026-09-16
**Método:** Abductive Engineering (A-D-I) + Red-Team Auditing —
lectura completa del código, verificación de la suite de tests existente,
y un smoke test end-to-end real (no simulado) contra el motor VIGÍA real.
**Origen:** Anna quiere pushear `src/zaynor/cli.py` (comandos `replay`,
`detect`, `case`, `freeze`, `analyze`, `audit`) porque una compañera de
equipo necesita probar casos con él. Pedido explícito de red-team antes
del push.
**Base:** working tree local (`dd3d5d4` + `cli.py`/`test_cli.py`/
`pyproject.toml` sin commitear). **Evidencia reproducible:** 10 tests
existentes corridos (`tests/test_cli.py`), más un smoke test manual
end-to-end (`freeze` → `analyze` real contra `vigia_agent.py` real →
`audit`) ejecutado en `/tmp/zaynor-cli-smoke` y descartado al terminar.

## Threat model

A diferencia de rondas anteriores (bridge MCP expuesto a un modelo local,
o un runtime de agente procesando texto adversarial), `cli.py` es una
herramienta de línea de comando de un solo operador, corrida localmente
por el propio analista — no un servicio de red, no multi-tenant. El
modelo de amenaza relevante acá es:

- El operador puede pasar cualquier argumento (paths, case-id) —
  intencional o por error de tipeo/copy-paste.
- Un `evidence_profile.json` o un directorio de evidencia podría venir de
  una fuente parcialmente no confiable (un fixture descargado, evidencia
  de un caso real).
- NO se asume un segundo usuario/proceso corriendo una carrera de
  filesystem contra este mismo operador en la misma máquina — ese modelo
  de amenaza (TOCTOU multi-actor) es el que sí aplica a `tools.py`/
  `path_guard.py` (superficie expuesta al LLM/MCP), no a este CLI.

## Epistemic legend
CODE FACT · PLAUSIBLE HYPOTHESIS · CONFIRMED BY INDUCTION · FALSIFIED

## Executive summary

**Ningún hallazgo bloqueante.** El código está sólidamente construido:
validación de paths acotada y anti-symlink en cada frontera, `case_id`
restringido a un patrón seguro, escritura atómica de resultados, y —lo
más importante— la suite de tests ya incluye tamper-evidence real para
CADA artefacto que `audit` verifica (evidencia, manifest, bundle,
sidecar, result, seal), no sólo el camino feliz.

| Vector investigado | Resultado |
|---|---|
| Algoritmo de hash de `_snapshot_digest` (frozen_snapshot.py) vs `_hash_evidence_dir` (zaynor_mode1_executor.py) — ¿son comparables en `_run_audit`? | FALSIFIED como discrepancia — ambos producen el mismo digest en POSIX (mismo orden de campos, `str(Path)` == `.as_posix()` en Linux, `bytes.fromhex(hexdigest)` == `.digest()`); confirmado por el test positivo `test_audit_accepts_untouched_stored_case_and_source_mutation`, que ya lo ejercita |
| TOCTOU en `_atomic_json_write` (symlink creado entre el chequeo y `os.replace`) | FALSIFIED — `os.replace`/`rename()` reemplaza el symlink en sí, no sigue el destino; no hay escritura-a-través-de-symlink posible en la ventana de carrera |
| `except (OSError, RuntimeError, ValueError)` en `_run_analyze`/`_run_audit` — ¿cubre todas las excepciones reales de `AdapterError`/`FrozenSnapshotError`/`Mode1ExecutionError`? | FALSIFIED como gap — las tres heredan de `ValueError` o `RuntimeError`, confirmado leyendo cada declaración de clase |
| Smoke test real: `freeze` → `analyze` (subprocess real de `vigia_agent.py`) → `audit`, caso `inc-2026-demo-001` | CONFIRMED BY INDUCTION — flujo completo funciona, `audit` devuelve `overall: VERIFIED` para un caso genuino, sin fabricar nada |

## Lo que Codex hizo bien (confirmado, no se re-litiga)

- Cada función de parseo de argumento (`_fixture_path`, `_directory_path`)
  rechaza symlinks en toda la cadena de componentes del path, no sólo en
  el componente final — mismo patrón riguroso que `path_guard.py`.
- `--python` en `analyze` está deliberadamente detrás de `--dev` — un
  operador no puede apuntar el ejecutor a un intérprete arbitrario sin
  una bandera explícita adicional.
- `_run_audit` re-verifica TODO de forma independiente al momento del
  análisis: recomputa el hash del manifest, recomputa el hash del
  snapshot de evidencia actual, valida el sidecar del bundle, verifica el
  seal, y cruza `authorized_manifest_sha256`/`analyzed_snapshot_sha256`/
  `authorized_case_id` del resultado contra lo recién recomputado — no
  confía en ningún campo del resultado guardado sin volver a comprobarlo
  contra la evidencia real en disco.
- La suite de tests ya prueba el camino adversarial explícitamente:
  `test_audit_fails_closed_for_each_stored_artifact_tamper` tampera cada
  uno de los 6 artefactos (evidencia, manifest, bundle, sidecar, result,
  seal) uno por uno y confirma que `audit` falla cerrado para cada caso
  — no es un test genérico, es específico por artefacto.
- `test_audit_accepts_untouched_stored_case_and_source_mutation` prueba
  el caso positivo Y confirma que mutar la fuente ORIGINAL (no congelada)
  después del freeze no afecta el resultado del audit — la frontera de
  congelamiento se sostiene.

## Discarded (non-exploitable) vectors

| Vector | Result | Why it failed |
|--------|--------|----------------|
| `next(event for event in events if ...)` en `_run_case` sin default — ¿puede levantar `StopIteration` sin capturar? | No confirmado como alcanzable | Los `triggering_event_ids` de una alerta siempre provienen de `events` mismo por construcción de `detect_suspicious_privileged_login`; no se encontró un caso real donde el generador quede vacío. Anotado como hipótesis de bajo riesgo, no confirmado por inducción — no bloqueante |

## Decisión

**Sin hallazgos que arreglar.** Push autorizado para que el equipo pruebe
casos.
