# Auditoría de Claude sobre el informe consolidado (ronda 3) y su fix

**Fecha:** 2026-09-16
**Método:** verificación empírica de cada hallazgo de la ronda 3
(`docs/red-team/2026-09-16-round-3-consolidated.md`) y del fix `71fba6b`
("fix: close evidence path and TOCTOU gaps"), no solo lectura de código.

**Nota de estado:** este archivo queda sin commitear a propósito — se sigue
agregando en la misma ronda antes de consolidar y commitear junto con las
soluciones.

## Hallazgos re-verificados

### #1 — TOCTOU de evidencia — CONFIRMED BY INDUCTION, fix cerrado

Reproduje el ataque contra el código YA arreglado: un thread modifica el
`evidence.json` mientras `vigia_agent.py` corre. Primer intento con delay de
1s no disparó nada (la corrida EBS ya había terminado antes del tamper — falla
de mi propio test, no del fix). Con delay de 0.05s, el rehash post-ejecución
detectó el cambio y `run_vigia_mode1` rechazó limpio: `"evidence changed
while Mode 1 was running"`. **Cerrado.**

### #2 — Evidencia fuera de raíz autorizada — CONFIRMED BY INDUCTION, fix cerrado

Probé `evidence_path` apuntando fuera de `allowed_evidence_root` (ahora
kwarg obligatorio) — rechazado limpio: `"evidence path escapes allowed
root"`. **Cerrado.**

### #5 — EBS derivado no revalidado contra el caso congelado — CONFIRMED BY INDUCTION, sigue abierto

Reproduje exactamente el escenario del informe: generé `evidence.json` desde
`score_inc_2026_demo_001()`, después sobreescribí el `auth.jsonl` crudo
congelado (cambié cuenta, rol y device a uno conocido). El `evidence.json`
ya escrito **siguió citando** la descripción vieja ("Privileged login...
device DEV-UNKNOWN-17...") sin ningún chequeo. Es el mismo problema que
`AGENTS.md` §2.3 previene para un LLM ("el gate vuelve a leer los
predicados directo de la evidencia, no confía en el relato") — acá el que
"relata" sin revalidación es el scorer de ZAYNOR, no un LLM, pero el
invariante es el mismo. **Éste es el hallazgo más importante de la ronda.**

### #3, #4, #6, #7, #9 — confirmados como reales, sin re-verificación adicional necesaria

Leí el código actual y coincido con el diagnóstico de la ronda 3 sin
necesitar una inducción propia adicional:

- #3: `lineage_id` por `artifact_type` es conservador pero no prueba
  independencia real — es una heurística, hay que dejar de presentarla como
  más que eso.
- #4: veredicto `NOISE` → finding `BENIGN` con evidence_refs es defendible
  ("se examinó, resultado limpio") pero no está documentado como decisión
  semántica explícita en el código.
- #6: `next()` en el scorer descarta silenciosamente registros adicionales
  que también calificarían para una regla.
- #7: `write_ebs_evidence` no es atómica y no protege contra symlink en el
  directorio padre.
- #9: correcto tal cual está — sigue siendo cierto después del fix de la
  ronda 3.

## Prioridad de cierre acordada

1. #5 (predicados revalidables) — estructural, el más importante.
2. #6 (scorer robusto a múltiples registros) y #7 (escritura atómica +
   symlink de parent) — correctitud y hygiene, rápidos de cerrar.
3. #3 y #4 — clarificación de documentación, no requieren cambio de
   comportamiento.

## Cierre — todo lo priorizado arriba está resuelto y probado

- **#5**: `ebs_artifact_scorer.py` ahora embebe
  `_zaynor_source_records_sha256` (hash de los 4 JSONL exactos que el scorer
  lee) en el `evidence.json` escrito, y expone `verify_ebs_freshness(ebs_path,
  evidence_dir)`. Test de regresión reproduce el ataque original (tamperear
  `auth.jsonl` después de escribir el EBS) y confirma que
  `verify_ebs_freshness` lo detecta con `EbsFreshnessError`. El flujo
  end-to-end (`test_end_to_end_scored_evidence_produces_traceable_findings`)
  ahora llama `verify_ebs_freshness` antes de invocar Mode 1 — documentado en
  el docstring que cualquier caller real debe hacer lo mismo justo antes de
  la ejecución, no solo al momento de escribir.
- **#6**: las tres reglas del scorer ahora iteran todos los registros que
  matchean, no solo el primero (`next()` → loop). `_read_jsonl` además
  descarta líneas JSON válidas que no son objetos, en vez de dejar que un
  `.get()` posterior explote. Test de regresión agrega un segundo login
  privilegiado y confirma que ambos artifact_id aparecen.
- **#7**: `write_ebs_evidence` ahora escribe atómico (`tempfile.mkstemp` +
  `os.replace`) y rechaza tanto un destino symlinkeado como un directorio
  padre symlinkeado (mismo patrón que `case_freezer.py`/
  `zaynor_mode1_executor.py`). Test de regresión confirma el rechazo.
- **#3**: agregada nota explícita en `_signal_evidence_ref` — agrupar por
  `artifact_type` es una heurística conservadora, no una cadena de
  procedencia verificada; cualquier código que lea `lineage_id` debe
  tratarlo como "no se sabe que sea la misma lineage", nunca como
  "confirmado independiente".
- **#4**: agregado comentario explícito en `translate_mode1_bundle` — un
  finding con veredicto `BENIGN`/`NOISE` se lee como "estos artifacts se
  analizaron, el resultado compuesto es limpio", nunca como "el caso está
  limpio" en general.

75/75 tests de la suite completa pasan, incluyendo los 5 nuevos de esta
ronda.
