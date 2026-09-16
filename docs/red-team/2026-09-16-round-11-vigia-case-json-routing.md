# Compatibilidad real: casos JSON de VIGÍA a través del pipeline de ZAYNOR
## Red Team Round 11
**Fecha:** 2026-09-16
**Método:** Abductive Engineering (A-D-I) + Red-Team Auditing.
**Origen:** Anna preguntó por qué su amigo, al elegir uno de los casos
JSON reales de VIGÍA (`vigia-repo/cases/*.json`) para probar, no sabía si
serían compatibles con el CLI de ZAYNOR — investigación en vivo, no
hipotética, contra el motor real.
**Base:** `main` @ `2c13b1f` (antes de este fix). **Evidencia
reproducible:** ejecución directa de `vigia_agent.py` contra
`OWL-NEXUS5-CASE.json`, luego el mismo caso a través del pipeline
completo de ZAYNOR (`freeze` → `analyze` → `audit`), antes y después del
fix, en `/tmp` (descartado al terminar).

## Threat model

No es una ronda adversarial en el sentido clásico — es una investigación
de compatibilidad real que expuso dos bugs de enrutamiento/consistencia,
uno de los cuales es un **falso negativo de integridad** (un caso
genuino, no manipulado, habría fallado la auditoría por una razón
incorrecta) — exactamente la clase de problema que CLAUDE.md §5.3
("never emit a result that looks correct... a WARN, not a silent PASS")
exige tratar con la misma seriedad que un hallazgo de seguridad.

## Epistemic legend
CODE FACT · PLAUSIBLE HYPOTHESIS · CONFIRMED BY INDUCTION · FALSIFIED

## Executive summary

| ID | Severity | Level | Módulo | Resultado |
|----|----------|-------|--------|-----------|
| R11-1 | Medium | CONFIRMED BY INDUCTION → fix aplicado | `adapter.py` | Un caso congelado cuya única evidencia es un JSON de caso de VIGÍA (`cases/*.json`, formato rico `artifacts[]`) llegaba a Mode 1 como directorio — el escáner de directorio no tiene patrón `*.json`, así que VIGÍA nunca veía el caso: 0 señales, en vez de las señales reales que VIGÍA sí produce cuando se le apunta al archivo directamente. |
| R11-2 | High | CONFIRMED BY INDUCTION → fix aplicado | `cli.py` | Consecuencia directa de R11-1: `zaynor audit`, para ese mismo tipo de caso, comparaba el hash de evidencia del bundle (ahora un hash de ARCHIVO, tras el fix de R11-1) contra un hash de DIRECTORIO recalculado localmente — un caso genuino, sin ninguna manipulación, fallaba la auditoría con `overall: FAILED` por una comparación de algoritmos incompatibles, no por integridad real comprometida. |

## Findings

### R11-1 — Un caso JSON de VIGÍA nunca llegaba a Mode 1 como tal

**Bucket:** vulnerabilidad de compatibilidad/enrutamiento real — no es un
bypass de autoridad, es un caso legítimo que el pipeline no sabía
manejar, produciendo un ABSTAIN vacío en vez de un análisis real.

- **Surprise / expectation violada:** corrí `vigia_agent.py --evidence
  OWL-NEXUS5-CASE.json --case-id X` directo (sin pasar por ZAYNOR) y
  obtuve 20 señales primarias reales y un veredicto genuino. Pero al
  congelar ese mismo archivo con `zaynor freeze` (copiándolo dentro de
  `evidence/`) y correr `zaynor analyze`, el resultado fue 0 findings,
  `unknowns: ["no usable signals..."]` — como si el caso no tuviera nada.
- **Abducción:** `ZaynorMode1Adapter.analyze()` siempre pasaba
  `snapshot.path` (el directorio del snapshot congelado) a
  `run_vigia_mode1`, nunca un archivo suelto — aunque
  `run_vigia_mode1`/VIGÍA sí soportan `--evidence <archivo>.json`
  directamente (la vía EBS-JSON, ya confirmada en fases anteriores del
  proyecto). El detector de artefactos de VIGÍA para el modo directorio
  (`_build_orchestrator_kwargs`) busca extensiones como `.evtx`/`.raw`/
  `.pcap`/hives de registro — no tiene ningún patrón `*.json` — así que
  un directorio que sólo contiene un `.json` no dispara ningún
  analizador.
- **Causal chain:**
  ```
  zaynor freeze copia OWL-NEXUS5-CASE.json a evidence/OWL-NEXUS5-CASE.json
      ↓
  zaynor analyze → ZaynorMode1Adapter.analyze(manifest, evidence_dir)
      ↓ materialize_frozen_snapshot() → snapshot.path (directorio)
  run_vigia_mode1(evidence_path=snapshot.path, ...)  # SIEMPRE directorio
      ↓
  VIGÍA escanea el directorio buscando .evtx/.raw/.pcap/hives — ninguno
      ↓
  0 señales, ABSTAIN vacío — el caso nunca fue realmente analizado
  ```
- **Deducción:** si en cambio se le pasa a Mode 1 el ARCHIVO `.json`
  mismo (cuando la evidencia congelada consiste en exactamente un
  archivo `.json`), VIGÍA debería producir las mismas señales reales que
  produce al correrse directo.
- **Induction (antes del fix):** confirmado exactamente ese resultado —
  0 findings vía ZAYNOR, 20 señales primarias vía VIGÍA directo, mismo
  archivo, mismo contenido.
- **Fix aplicado:** nueva función `_evidence_path_for_mode1(snapshot_path)`
  en `adapter.py` — si el snapshot congelado contiene exactamente un
  archivo y termina en `.json`, se le pasa ESE ARCHIVO a
  `run_vigia_mode1` en vez del directorio; en cualquier otro caso
  (múltiples archivos, o extensión distinta), se mantiene el
  comportamiento existente (pasar el directorio). Cambio puramente de
  enrutamiento — el snapshot, su verificación de hashes, y todo lo demás
  del caso congelado quedan exactamente iguales.
- **Induction (después del fix):** mismo archivo, mismo pipeline
  (`freeze` → `analyze`), ahora produce 1 `AuthoritativeFinding` con 20
  `evidence_refs` — igual a las 20 señales reales que VIGÍA produce
  directo. Test de regresión:
  `tests/test_adapter.py::test_evidence_path_for_mode1_routes_a_lone_json_file_to_itself`
  (más 3 tests de casos negativos: múltiples archivos, cero archivos,
  archivos no-JSON, todos mantienen el modo directorio) y
  `test_mode1_adapter_routes_a_lone_json_case_file_to_mode1_by_itself`
  (confirma el enrutamiento real dentro del adapter completo, con
  `run_vigia_mode1` mockeado).

### R11-2 — `zaynor audit` fallaba un caso genuino después del fix de R11-1

**Bucket:** falso negativo de integridad — el hallazgo más serio de esta
ronda, porque el síntoma es indistinguible de "la evidencia fue
manipulada" para cualquiera que use el comando sin saber la causa real.

- **Surprise / expectation violada:** con R11-1 ya aplicado, corrí el
  pipeline completo (`freeze` → `analyze` → `audit`) contra el mismo caso
  JSON real, SIN tocar nada — y `zaynor audit` devolvió `overall: FAILED`
  con `"error": "stored bundle evidence hash does not match current
  snapshot"`.
- **Abducción:** `_run_audit` en `cli.py` siempre calcula
  `snapshot_digest = _snapshot_digest(evidence_dir)` (hash de
  DIRECTORIO) y lo compara contra `bundle.get("evidence_sha256")` — pero
  tras el fix de R11-1, para un caso de un solo `.json`, VIGÍA calculó
  `evidence_sha256` sobre el ARCHIVO (hash de archivo, no de directorio)
  porque así es como realmente se le pasó `--evidence`. Comparar un hash
  de archivo contra un hash de directorio nunca puede coincidir, sin
  importar si algo fue manipulado o no.
- **Deducción:** `_run_audit` debe recomputar el hash de evidencia
  exactamente de la misma manera en que Mode 1 lo hizo — replicando la
  MISMA decisión de enrutamiento que `_evidence_path_for_mode1` toma en
  `adapter.py`, no asumiendo siempre modo-directorio.
- **Induction (antes del fix):** confirmado el `FAILED` con un caso
  100% genuino, sin ninguna manipulación — un falso positivo de
  "tamper detected".
- **Fix aplicado:** `_run_audit` ahora llama a la misma
  `_evidence_path_for_mode1(evidence_dir)` (importada desde `adapter.py`)
  para decidir si el hash a comparar es el de directorio
  (`_snapshot_digest`, sin cambios) o el de archivo (`sha256` del
  archivo específico) — exactamente la misma lógica que decide qué le
  pasó realmente a VIGÍA.
- **Induction (después del fix):** mismo caso, mismo pipeline completo,
  ahora `overall: VERIFIED`, `findings: 1`, `verdict: ABSTAIN` — sin
  tocar nada más. Test de regresión:
  `tests/test_cli.py::test_analyze_and_audit_a_single_vigia_case_json_file`
  (usa un stub de `vigia_agent.py` que calcula el hash correctamente
  según si `--evidence` es archivo o directorio, igual que el VIGÍA
  real, y corre `freeze`→`analyze`→`audit` de punta a punta).

## Discarded (non-exploitable) vectors

Ninguno — ambos vectores investigados resultaron ser hallazgos reales,
no hipótesis descartadas. La verificación de `analyzed_snapshot_sha256`
(la OTRA comparación de hash en `_run_audit`, contra
`result.integrity.get("analyzed_snapshot_sha256")`) se revisó y NO
necesitaba el mismo fix: ese campo siempre se deriva de
`_snapshot_digest` sobre el snapshot COMPLETO congelado por ZAYNOR
(`materialize_frozen_snapshot`'s propio cálculo interno), independiente
de qué le pasó `run_vigia_mode1` a VIGÍA — nunca cambia de algoritmo.

## Recommendations (fuera de alcance de este cambio — sólo registro)

- Ninguna pendiente — R11-1 y R11-2 quedaron cerrados con fix y test de
  regresión, confirmados contra el motor VIGÍA real y a través de la
  suite mockeada.
