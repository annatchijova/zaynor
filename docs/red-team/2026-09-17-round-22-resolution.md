# Resolución — round 22, auditoría general de backend

**Fecha:** 2026-09-17
**Responde a:** `docs/red-team/2026-09-17-round-22-backend-general.md`
**Autor de esta resolución:** Claude (los hallazgos son de un agente
red-team independiente lanzado en esta misma sesión; se verificaron
contra el código vivo antes de aplicar nada — CLAUDE.md §4.1)

Los 4 hallazgos nuevos (R22-01 a R22-04) se re-leyeron contra el código
actual antes de tocar nada. R22-01 se verificó línea por línea en
`api.py` antes de aceptarlo como real. Los tres re-verificados de round
21 (R21-01, R21-06, R21-07) no cambiaron y no se tocan acá.

## Resueltos

### R22-01 — Carrera entre propuestas de investigación concurrentes para el mismo caso (CONFIRMED BY INDUCTION → RESUELTO)

Confirmado real: `propose_investigation` (`api.py`) era un ciclo
leer → computar → escribir sin ningún lock. Dos requests concurrentes
para el mismo `case_id` cargaban el mismo ledger viejo, ambas ejecutaban
de verdad su llamada MCP, y el `os.replace` que corría segundo pisaba al
primero — la observación ya ejecutada del que "perdió" desaparecía del
ledger, indistinguible de "nunca se preguntó". Ninguna corrupción de
archivo (la atomicidad de `_save_investigation_state` de R21-03 seguía
intacta); el problema era la base sobre la que se escribía, no la
escritura en sí.

Arreglo: `_investigation_write_lock(output_root, case_id)`, un
`contextlib.contextmanager` que toma un `fcntl.flock` exclusivo sobre
`investigation.lock` (nuevo archivo, uno por caso) y envuelve el ciclo
completo — carga, `propose_and_execute`, guardado — no solo el guardado.
La segunda request ya no corre en paralelo contra una base vieja: se
bloquea hasta que la primera termina y guarda, y ahí recién carga el
ledger ya actualizado. El lock se toma con un chequeo de symlink previo
sobre `investigation.lock` mismo, para no introducir una instancia nueva
de R22-02 en el archivo de lock.

Test nuevo en `tests/test_api.py`
(`test_propose_investigation_serializes_concurrent_requests_for_the_same_case`):
dos threads reales, un `ThreadPoolExecutor`, cada uno dispara una
propuesta real contra el mismo caso con una llamada MCP real (subproceso
real contra el bridge vendorizado de VIGÍA, no mockeada). Confirmado:
ambas requests terminan en `EXECUTED` y el ledger final tiene las 2
propuestas y las 2 observaciones — antes del fix, esta misma prueba
habría mostrado 1 de las 2.

### R22-02 — `AuditLog` seguía un symlink pre-colocado en vez de rechazarlo (CONFIRMED BY INDUCTION → RESUELTO)

Confirmado real: ni `_resume()` (lectura, en `__init__`) ni `append()`
(escritura) ni los estáticos `load_entries`/`verify_with_report`
chequeaban si `self._path`/`self._tail_path` eran un symlink antes de
abrirlos — el único módulo del código cuyo propósito es evidencia de
tamper, sin el chequeo de symlink que el resto del código sí tiene
(`PathGuard`, `cli.py::_atomic_json_write`, `_fixture_path`,
`api.py::_save_investigation_state`).

Arreglo: nueva función `_reject_symlink(path)` en `audit_log.py`,
aplicada en los 5 puntos de entrada: `_resume()` (lectura en
construcción), `append()` (re-chequea `self._path` y `self._tail_path`
en cada escritura, no solo una vez — cubre el caso de un symlink
insertado después de construir el objeto), `load_entries`, y
`verify_with_report` (sobre el log y sobre el tail-anchor).

3 tests nuevos en `tests/test_audit_log.py`: symlink pre-existente
rechazado en construcción/lectura, symlink insertado después de
construir el objeto rechazado en `append()` (confirmando que el target
externo queda intacto, sin escritura), y `load_entries`/
`verify_with_report` rechazando un symlink directamente.

### R22-03 — Path absoluto del servidor filtrado en un error HTTP ante evidencia desincronizada (CONFIRMED BY INDUCTION → RESUELTO)

Confirmado real: `frozen_snapshot.py::_inventory` interpolaba el `Path`
absoluto (`root.rglob("*")`, sobre el `evidence_dir` real del servidor)
en el mensaje de `FrozenSnapshotError`, y `api.py::get_case_evidence`
reenvía ese string tal cual al cliente HTTP. El resto del mismo módulo
(`_validated_entries`) ya usaba paths relativos al caso
(`entry.relative_path`) en sus propios mensajes — la inconsistencia era
puntual, no sistémica.

Arreglo: los 3 mensajes de error de `_inventory`/`_snapshot_digest` que
interpolaban `path` ahora interpolan `path.relative_to(root)`.

Test nuevo en `tests/test_frozen_snapshot_security.py`
(`test_inventory_symlink_error_does_not_leak_the_absolute_server_path`):
symlink real dentro de un directorio de evidencia, confirma que el
mensaje de error contiene el nombre del archivo pero no el prefijo
absoluto de `tmp_path`.

### R22-04 — Sin tope de tamaño en `AuditLog.load_entries`/`verify_with_report` (CODE FACT → RESUELTO)

Confirmado real: estas dos funciones —escritas en esta misma sesión—
no seguían el patrón `_read_bounded` que R21-05 estableció para
Ollama. El propio hallazgo ya había refutado la escalada a "DoS remoto
hoy" (nada alcanzable por la API escribe `TOOL_INVOKED` en volumen), así
que esto se cierra como higiene preventiva, no como hueco explotable
hoy.

Arreglo: `_MAX_AUDIT_LOG_BYTES = 16 MiB` y `_reject_oversized(path)`,
chequeado antes de abrir el archivo en `load_entries` y
`verify_with_report`.

Test nuevo (`test_verify_with_report_rejects_an_oversized_log`):
monkeypatchea el límite a 10 bytes contra un log real de 5 entradas y
confirma que ambas funciones lo rechazan.

## Verificación

```text
PYTHONPATH=src pytest -q --ignore=tests/test_real_forensic_image_evidence.py
355 passed, 1 skipped
```

Baseline antes de esta resolución: 349 passed, 1 skipped (round 21). Los
6 tests nuevos son inducción real (threads reales + subproceso MCP real,
symlinks reales, archivo de tamaño real, monkeypatch acotado a un solo
límite numérico) — ninguno mockea lo que efectivamente se está probando.
Ningún test preexistente cambió de comportamiento esperado.

## Re-verificación de lo que quedó abierto de round 21

Sin cambios, tal como el propio round 22 ya re-confirmó: R21-01 (sin
auth fuera de loopback), R21-06 (sin lockfile de Python), R21-07
(`VigiaMCPClient` sin allowlist propia) siguen siendo decisiones del
equipo, no defectos de código — no se tocan en esta resolución.
