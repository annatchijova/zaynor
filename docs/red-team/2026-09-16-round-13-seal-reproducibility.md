# Reproducibilidad del sello: `engine.configuration_hash` cambiaba entre ejecuciones idénticas
## Red Team Round 13
**Fecha:** 2026-09-16
**Método:** Abductive Engineering (A-D-I) + Red-Team Auditing.
**Origen:** auditoría externa e independiente ("VIGIA-BREAK-014 — Evidence
Mirage"), corrida por un compañero de equipo con acceso de solo lectura,
sobre `6b49cfa` — flujo `freeze → analyze → audit` con casos JSON reales
de VIGÍA. El informe confirmó el flujo funcional, pero encontró y
diagnosticó por completo una falla de reproducibilidad del sello,
citando el contrato de CLAUDE.md §5.2. Verificado acá contra el código
vivo antes de aplicar nada (CLAUDE.md §4.1), luego arreglado.
**Base:** `main` @ `6b49cfa` (antes de este fix). **Evidencia
reproducible:** `freeze` una vez, `analyze` tres veces sobre el mismo
caso congelado, comparar `result.seal.json` entre las tres corridas —
antes y después del fix, contra el motor VIGÍA real, en `/tmp`
(descartado al terminar).

## Threat model

No es una ronda adversarial contra un atacante — es una violación de un
invariante determinista que CLAUDE.md §5.2 exige explícitamente
("Prove it. Produce the result at least twice and assert the seals
match"). El "atacante" acá es la propia arquitectura: cualquier
componente en el camino de sellado que dependa de estado efímero
(un path aleatorio, un timestamp, un PID) rompe la garantía de
reproducibilidad bit a bit sin que nadie manipule nada.

## Epistemic legend
CODE FACT · PLAUSIBLE HYPOTHESIS · CONFIRMED BY INDUCTION · FALSIFIED

## Executive summary

| ID | Severity | Level | Módulo | Resultado |
|----|----------|-------|--------|-----------|
| R13-1 | High | CODE FACT + CONFIRMED BY INDUCTION → fix aplicado | `frozen_snapshot.py` | El directorio privado del snapshot usaba un sufijo aleatorio (`tempfile.TemporaryDirectory`). ZAYNOR apunta `VIGIA_EVIDENCE_DIR`/`VIGIA_ALLOWED_REGISTRY_PATHS`/`VIGIA_ALLOWED_DUMP_PATHS` a ese path, y el fingerprint de ejecución de VIGÍA (`runtime_execution_fingerprint`) hashea TODAS las variables `VIGIA_*` — por diseño, ya que algunas sí afectan el cómputo determinista. Un path aleatorio no aporta información de decisión, pero cambiaba `engine.configuration_hash` — y por lo tanto el sello — en cada corrida del mismo caso congelado idéntico. |

## Findings

### R13-1 — El nombre del directorio del snapshot contaminaba el fingerprint de VIGÍA

**Bucket:** vulnerabilidad de determinismo real — viola directamente
CLAUDE.md §5.2 ("The decision path must be reproducible bit-for-bit").
No es un bypass de autoridad: el veredicto, los findings, las
referencias de evidencia y los hashes de manifest/snapshot eran
idénticos entre corridas — sólo `engine.configuration_hash` (y por lo
tanto el sello completo, que lo incluye) variaba.

- **Firstness (observación pura):** tres ejecuciones de `analyze` sobre
  el MISMO caso congelado produjeron tres sellos distintos. La única
  diferencia estructural entre los tres `result.json` era
  `engine.configuration_hash`.
- **Secondness (contraste con la línea base):** un resultado sellado
  debe ser reproducible bit a bit cuando el caso, la configuración y la
  decisión no cambian — es el contrato explícito de CLAUDE.md §5.2. Una
  diferencia por-corrida en un campo del resultado sellado, sin que
  ninguna evidencia o decisión real haya cambiado, es una violación de
  ese contrato, no "flakiness".
- **Thirdness (la ley general):** cualquier valor que entra al camino de
  sellado y depende de estado efímero de la ejecución (aquí: un
  directorio con sufijo aleatorio, usado como valor de una variable de
  entorno que a su vez entra a un fingerprint) rompe el determinismo,
  sin importar cuán "razonable" sea el mecanismo que lo introduce en
  cada paso individual.
- **Abducción (múltiples hipótesis, la auditoría externa ya las probó
  todas):**
  1. Diferencias de evidencia/manifest/decisión — refutada por
     comparación estructural de campos y hashes.
  2. Cambio del directorio de salida entre corridas — refutada:
     reaparece incluso repitiendo exactamente el mismo comando.
  3. Un timestamp incluido en el resultado sellado — refutada por diff:
     el único campo que cambia es `engine.configuration_hash`.
  4. **Confirmada:** el path aleatorio del snapshot entra a
     `VIGIA_ALLOWED_REGISTRY_PATHS`/`VIGIA_ALLOWED_DUMP_PATHS`/
     `VIGIA_EVIDENCE_DIR`, que `runtime_execution_fingerprint` (vigia-repo,
     `vigia/core/runtime_fingerprint.py`) hashea junto con toda variable
     `VIGIA_*` para construir el fingerprint de ejecución — confirmado
     leyendo esa función línea por línea: `names = sorted(name for name
     in env if name.startswith("VIGIA_") or name == "PYTHONHASHSEED")`.
- **Causal chain:**
  ```
  materialize_frozen_snapshot() crea .zaynor_snapshot_<random> (tempfile)
      ↓
  run_vigia_mode1() fija VIGIA_ALLOWED_REGISTRY_PATHS=VIGIA_ALLOWED_DUMP_PATHS=
      evidence_root (deriva del path aleatorio)
      ↓
  vigia_agent.py fija VIGIA_EVIDENCE_DIR desde --evidence si no está seteada
      (también deriva del path aleatorio)
      ↓
  runtime_execution_fingerprint(repo_root) hashea TODAS las VIGIA_* —
      por diseño, correcto para variables como VIGIA_EBS_RESOLVE
      ↓
  bundle["runtime_fingerprint"] cambia en cada corrida (nada de decisión
      cambió — sólo el nombre del directorio efímero)
      ↓
  translate_mode1_bundle() copia esto a engine["configuration_hash"]
      ↓
  seal_authoritative_result() sella engine completo → sello distinto
  ```
- **Deducción:** si el nombre del directorio del snapshot se deriva
  únicamente de la identidad de contenido del manifest
  (`manifest.content_sha256`, ya determinista y ya parte del contrato de
  `CaseManifest`) en vez de un sufijo aleatorio, `VIGIA_EVIDENCE_DIR`/
  `VIGIA_ALLOWED_*` deberían ser idénticos entre corridas del mismo caso
  congelado, y por lo tanto también `runtime_execution_fingerprint`,
  `engine.configuration_hash`, y el sello completo.
- **Induction (antes del fix):** reproducido exactamente el síntoma
  reportado — tres corridas de `analyze` sobre el mismo caso congelado
  (`admin-session-investigation`), tres sellos distintos, sólo
  `engine.configuration_hash` cambiando.
- **Fix aplicado:** `materialize_frozen_snapshot()` en `frozen_snapshot.py`
  ahora crea el directorio privado como
  `<case_root>/.zaynor_snapshot_<manifest.content_sha256>` — determinista
  para el mismo contenido de caso, distinto entre casos distintos — en
  vez de `tempfile.TemporaryDirectory(prefix=".zaynor_snapshot_")` (sufijo
  aleatorio). Se preserva la limpieza automática (`shutil.rmtree` en un
  `finally`) y se agrega un chequeo explícito de colisión: si el
  directorio ya existe (una corrida concurrente sobre el mismo caso, o
  uno abandonado por un crash previo), falla cerrado con
  `FrozenSnapshotError` en vez de reusar o pisar silenciosamente ese
  directorio. No se tocó código de vigia-repo (AGENTS.md §2.1): el fix
  vive enteramente del lado de ZAYNOR, en el valor que le da a las
  variables de entorno que él mismo construye.
- **Induction (después del fix):** mismo caso, tres corridas de
  `analyze`, mismo `engine.configuration_hash` y mismo sello sha256 en
  las tres. `audit` sobre el resultado sigue devolviendo
  `overall: VERIFIED`. Test de regresión (contra el motor VIGÍA real):
  `tests/test_adapter.py::
  test_repeated_analyze_of_the_same_frozen_case_produces_the_same_seal`.
  Tests unitarios adicionales en `test_frozen_snapshot_security.py`:
  el nombre del directorio es el mismo entre dos `materialize_frozen_snapshot`
  del mismo manifest; una colisión (mismo caso, snapshot concurrente)
  falla cerrado; el directorio se limpia después de usarse.

## Por qué el test de reproducibilidad existente no lo atrapó

`tests/test_zaynor_mode1_executor.py::
test_mode1_is_reproducible_on_the_same_frozen_case` ya existía y "pasaba"
— pero llama a `run_vigia_mode1` directamente sobre el directorio
congelado real (`evidence_dir`), sin pasar por
`materialize_frozen_snapshot` (que es donde vive el path efímero), y sólo
compara `evidence_sha256`/`agent_verdict` — nunca el `runtime_fingerprint`
ni el sello. Confirma que la falla vivía específicamente en la capa del
adapter (`ZaynorMode1Adapter.analyze`), no en el executor de más bajo
nivel — y que un test de reproducibilidad que no ejercita el camino
completo (freeze → snapshot → adapter → sello) puede dar un falso
verde. El nuevo test cierra exactamente ese hueco.

## Lo que la auditoría externa hizo bien (confirmado, no se re-litiga)

- Diagnóstico completo del mecanismo antes de reportarlo — cuatro
  hipótesis, tres refutadas con evidencia concreta, una confirmada
  reconstruyendo el fingerprint exacto de las tres corridas observadas.
- Distinción correcta entre "la decisión se mantuvo estable" (verdad) y
  "el resultado es reproducible" (falso) — exactamente la separación que
  esta clase de bug exige para no subestimarlo ni sobre-reaccionar.
- Control negativo real (alterar el veredicto en una copia del resultado,
  confirmar que `audit` lo rechaza) antes de reportar el hallazgo
  principal — confirma que el mecanismo de auditoría en sí funciona,
  aislando la falla de reproducibilidad como el único problema real.
- No propuso un parche a ciegas — documentó el hallazgo completo y dejó
  la corrección para revisión, exactamente el patrón "audit before
  patch" que este proyecto sigue.

## Discarded (non-exploitable) vectors

Ninguno nuevo — el hallazgo de la auditoría externa se confirmó tal cual
fue reportado, sin necesidad de descartar vectores alternativos.

## Recommendations (fuera de alcance de este cambio — sólo registro)

- Ninguna pendiente — R13-1 quedó cerrado con fix y tests de regresión,
  confirmados contra el motor VIGÍA real.
