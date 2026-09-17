# Resolución — round 21, invariantes generales

**Fecha:** 2026-09-17
**Responde a:** `docs/red-team/2026-09-17-round-21-general-invariants-draft.md`
**Autor de esta resolución:** Claude (los hallazgos son de Codex; acá se
verifican contra el código vivo y se resuelven o se dejan explícitamente
pendientes, no se aceptan sin re-verificar — CLAUDE.md §4.1)

Cada hallazgo se re-leyó contra el código actual antes de tocar nada.
Ninguno se aplicó a ciegas.

## Resueltos

### R21-02 — Espera indefinida en `VigiaMCPClient` (CONFIRMED BY INDUCTION → RESOLVED)

Confirmado real: `initialize`/`list_tools`/`call_tool` no tenían deadline
propio. Agregado `VigiaMCPConfig.timeout_seconds` (default 30s) y
`asyncio.wait_for` alrededor de los tres — sin cambiar el backend de
asyncio, tal como pedía la recomendación original. Test de inducción
real (`tests/test_zaynor_mcp_client.py::test_initialize_times_out_instead_of_hanging_forever`):
un bridge falso que nunca completa el handshake ahora corta a los ~1s en
vez de colgarse indefinidamente. Los 10 tests reales existentes contra
el bridge vendorizado siguen pasando sin cambios de comportamiento.

### R21-03 — Ledger de investigación sin escritura atómica (CODE FACT → RESOLVED)

Confirmado real: `_save_investigation_state` escribía con
`Path.write_text()` directo, y `_load_investigation_state` capturaba
*cualquier* falla de lectura y volvía silenciosamente a una sesión
nueva y vacía — pérdida de datos disfrazada de `NOT_STARTED`.

Dos cambios:
1. Escritura atómica real: temp file en el mismo directorio + `fsync` +
   `os.replace`, igual al patrón ya establecido en `cli.py::_atomic_json_write`.
2. Nueva excepción `InvestigationLedgerCorrupted`: un archivo presente
   pero ilegible ya no se trata igual que "no hay archivo" — se
   propaga como error real (`ApiError` 500) en vez de resetearse solo.

Dos tests nuevos en `tests/test_api.py`:
- `test_propose_investigation_writes_the_ledger_atomically` — confirma
  por inducción que se usa un archivo temporal real y que `os.replace`
  lo consume (no queda huérfano).
- `test_get_case_investigation_fails_closed_on_a_corrupted_ledger` —
  un `investigation.json` truncado a mano ahora produce un 500 explícito,
  no un `NOT_STARTED` falso.

### R21-04 — Efecto MCP antes de persistencia durable (PLAUSIBLE HYPOTHESIS → mitigado, no cerrado)

No estaba pedido cerrar esto (la inducción propuesta en el draft queda
pendiente), pero el arreglo de R21-03 reduce la ventana real: antes, un
crash a mitad de la escritura podía truncar el archivo Y perder la
observación. Ahora un crash entre "el tool ya corrió" y "se escribió el
archivo" sigue perdiendo esa observación puntual (la llamada MCP en sí
fue de lectura y determinista, así que no altera nada autoritativo), pero
ya no puede corromper el resto del ledger acumulado hasta ese punto. La
inducción exacta que pide el draft (inyectar el fallo justo en ese punto
y confirmar que el próximo GET puede distinguir `lost-after-tool` de
`NOT_STARTED`) no se hizo — requeriría una API de fallo inyectado que no
existe hoy. Queda anotado, no resuelto.

### R21-05 — Respuesta de Ollama sin límite de tamaño (CODE FACT → RESOLVED)

Confirmado real: `OllamaClient.generate()` y `list_available_models()`
hacían `response.read()` sin límite. Agregado `_read_bounded()` con
topes (8 MiB para narración, 1 MiB para el listado de modelos). Dos
tests nuevos en `tests/test_ollama_client_transport.py`, contra un
servidor HTTP real en loopback (no un mock) que efectivamente manda un
cuerpo de más de 8 MiB — confirmado que ambas funciones lo rechazan con
`OllamaError`, no que lo aceptan silenciosamente.

Efecto colateral encontrado y arreglado: dos fixtures `Response` falsas
en `tests/test_agents.py` tenían `read(self)` sin el parámetro de tamaño
que `_read_bounded` ahora pasa siempre — no coincidían con la firma real
de `http.client.HTTPResponse.read(amt=None)`. Corregido a `read(self,
size=-1)` en ambas.

## No resueltos — quedan como decisión del mantenedor

### R21-01 — API sin autenticación fuera de localhost

Confirmado como CODE FACT: `--host 0.0.0.0` no tiene ningún control de
autenticación. No se implementó nada acá porque es una decisión de
producto (qué mecanismo de auth, para quién, con qué UX), no un bug de
código. El default sigue siendo `127.0.0.1`.

### R21-06 — Dependencias Python sin lockfile

Confirmado. No se generó un lockfile en esta pasada — requiere elegir
herramienta (`pip-compile`, `uv`, etc.) y decidir si entra al repo o al
CI, decisión del equipo.

### R21-07 — `VigiaMCPClient.call_tool()` sin allowlist propia

Confirmado: el cliente genérico acepta cualquier nombre de tool que el
bridge publique; la restricción real vive en `InvestigatorToolAdapter` +
`agents.policy.authorize_tool()`, no en el cliente. No se tocó porque
mover la allowlist al cliente genérico cambiaría su contrato para todo
consumidor futuro — vale una decisión explícita, no un parche apurado.

## Verificación

```text
PYTHONPATH=src pytest -q  # excepto tests/test_real_forensic_image_evidence.py (colgado ajeno, en investigación por Codex)
344 passed, 1 skipped
```

Ningún test preexistente cambió de comportamiento esperado; los 6 tests
nuevos son inducción real (subprocess real, servidor HTTP real, archivo
corrupto real), no mocks de lo que se está probando.
