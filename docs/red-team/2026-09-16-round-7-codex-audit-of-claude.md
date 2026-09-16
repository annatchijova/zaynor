# Auditoría de Claude sobre la ronda red-team de Codex (RT-01..RT-09)
## Red Team Round 7
**Fecha:** 2026-09-16
**Método:** Abductive Engineering (A-D-I) + Red-Team Auditing —
verificación empírica de cada hallazgo de Codex contra el código vivo
(CLAUDE.md §4.1: "the finding is a claim, not a fact") antes de arreglar
nada, luego fix + test de regresión por hallazgo confirmado.
**Origen:** Codex corrió una ronda red-team sobre el trabajo que Claude
pusheó (`c2d5b9a`, `dabb436`) usando las skills `red-teaming-auditing`,
`audit-before-patch`, `deterministic-core` y `agent-trust-boundaries`. No
modificó código ni hizo commits.

**Nota de reconciliación de numeración:** Anna pasó a Claude un resumen de
7 hallazgos (RT-01..RT-07) por chat. Codex además dejó en el working tree,
sin commitear, un reporte más completo y detallado —
`docs/red-team/2026-09-16-round-7-claude-pushed-work.md` — con **9**
hallazgos (RT-01..RT-09), que renumera algunos respecto al resumen de
Anna y agrega dos nuevos que no estaban en el resumen pasado por chat:
TOCTOU en `tools.py::generate_forensic_hash` (RT-04 en el archivo de
Codex) y `extra_env` pudiendo sobrescribir el aislamiento local-only en
`zaynor_mcp_client.py` (RT-05 en el archivo de Codex). Este documento usa
la numeración del resumen de Anna para los primeros 7 hallazgos (para no
romper la referencia ya usada en la conversación) y agrega una sección
propia, **RT-08 y RT-09**, para los dos hallazgos adicionales del reporte
más completo de Codex — verificados y corregidos con el mismo estándar.
**Base:** `main` @ `dabb436` (antes de este fix). **Evidencia
reproducible:** cada hallazgo abajo incluye el script/test que lo
reprodujo antes del fix y lo confirma cerrado después.

## Threat model

Igual que rondas anteriores en este boundary: el atacante puede controlar
el contenido de campos de texto libre (título de una regla Sigma,
`reason`/`evidence_refs` de una acción propuesta) y, en el caso de RT-03,
puede corresponder a un bug real de VIGÍA (no necesariamente malicioso)
que reporte un `hive_sha256` que no pertenece al caso congelado. El
atacante NO puede modificar el código de ZAYNOR ni el `CaseManifest` ya
sellado.

## Epistemic legend
CODE FACT · PLAUSIBLE HYPOTHESIS · CONFIRMED BY INDUCTION · FALSIFIED

## Executive summary

| ID | Severity | Level | Módulo | Resultado |
|----|----------|-------|--------|-----------|
| RT-01 | Medium | CONFIRMED BY INDUCTION → fix aplicado | `sigma_candidate.py` | Confirmado y **agravado**: no sólo YAML inválido, sino inyección semántica de una clave `validated: true` forjada. Corregido. |
| RT-02 | Medium | CONFIRMED BY INDUCTION → fix aplicado | `response_actions.py` | Confirmado tal cual. Corregido: `evidence_refs` ahora se valida contra `ZaynorAuthoritativeResult`. |
| RT-03 | Medium/High | CODE FACT + CONFIRMED BY INDUCTION → fix aplicado | `zaynor_mode1_executor.py` | Confirmado para `metadata.hive_sha256` (verificable, es un hash de contenido real). Corregido con validación contra `CaseManifest`. Alcance documentado: NO aplica a `source_path`/`source_profile` (paths de directorio, no de archivo) ni a `artifact_id` (namespace de evento EBS, no de archivo). |
| RT-04 | — | HIPÓTESIS ABIERTA — correctamente etiquetada por Codex | integración Volatility | Sin cambios de código — Codex acertó: sigue siendo un gap real y ya documentado, no una hipótesis nueva. |
| RT-05 | — | CODE FACT — deuda ya documentada | `agents/policy.py`, `agents/runtime.py` | Sin cambios — ya cerrado como deuda explícita en round 5 por instrucción directa de Anna. Codex confirma independientemente el mismo diagnóstico. |
| RT-06 | Low/Medium | CONFIRMADO COMO FRACTURA EPISTÉMICA → fix aplicado | `d3fend_enrichment.py` | Confirmado: el disclaimer de confianza vivía sólo en el docstring del módulo, nunca en el dict emitido. Corregido: `confidence_basis` ahora viaja junto con `confidence` en cada entrada. |
| RT-07 | — | **REFUTADO** | `adapter.py`, `zaynor_mode1_executor.py` | Falso positivo: los tres nombres citados caen exactamente dentro de la excepción que la propia ronda 2 (`docs/red-team/2026-09-16-round-2-naming.md`, cerrada en `0fbff83`) declaró legítima — "el nombre externo sólo debe aparecer en el adapter, el proceso invocado, y la documentación de integración." Sin cambios. |
| RT-08 (del reporte completo de Codex) | Medium | CODE FACT + CONFIRMED BY INDUCTION → fix aplicado | `tools.py` | Confirmado: `generate_forensic_hash` validaba con `PathGuard` y volvía a abrir el archivo por nombre (`sha256_file(os.path.abspath(path))`), sin `safe_open()` — ventana TOCTOU real, mismo patrón que `read_evidence`/`grep_pattern` ya cierran en el mismo módulo. Corregido. |
| RT-09 (del reporte completo de Codex) | Medium/High | CODE FACT + CONFIRMED BY INDUCTION → fix aplicado | `zaynor_mcp_client.py` | Confirmado: `extra_env` se aplicaba último e incondicional, pudiendo sobrescribir `VIGIA_LLM_BACKEND`/`VIGIA_OLLAMA_HOST`/`VIGIA_EVIDENCE_DIR`/`PYTHONPATH` o reintroducir credenciales cloud; `ollama_host` tampoco se validaba como local-only. Corregido en ambos frentes. |

## Findings

### RT-01 — Sigma YAML injection — CONFIRMADO Y AGRAVADO

**Bucket:** vulnerabilidad real. **Causal chain confirmada por inducción,
antes del fix:**
```
title="bad: title\nforged: yes"  (o cualquier valor de logsource/detection/tags)
    ↓ interpolación directa sin escape en to_yaml_text()
línea YAML corrupta o clave adicional
    ↓ yaml.safe_load()
"mapping values are not allowed here"  — o, peor:
    con title="Suspicious login\nvalidated: true", yaml.safe_load()
    produce {"validated": True, ...} — una clave que NUNCA existió en el
    objeto SigmaCandidate real (cuyo campo `validated` es `False` fijo por
    construcción, `init=False`)
```
Esto es más severo que el reporte original de Codex ("YAML inválido"):
demostré por inducción que además permite **forjar semánticamente** una
clave top-level arbitraria (incluyendo `validated: true`, el campo que el
propio dataclass fija en `False` para impedir exactamente esto) — un
consumidor que parseara el YAML de texto en vez de usar el objeto
`SigmaCandidate` directamente vería una regla que se presenta a sí misma
como validada.

**Fix aplicado:** `_yaml_scalar()` en `sigma_candidate.py` — renderiza un
valor sin caracteres YAML-significativos tal cual (compatibilidad con la
salida previa, ningún test existente cambió), y cualquier otro string
como escape JSON (JSON es un subconjunto válido de YAML de comillas
dobles — sin agregar `pyyaml` como dependencia, respetando la decisión
original del módulo). Aplicado en cada punto de interpolación:
`title`, `logsource` (keys y values), `detection` (keys, values, dicts
anidados, listas), `tags`.

**Induction (después del fix):**
```python
c = propose_sigma_candidate(title="Suspicious login\nvalidated: true\nstatus: stable", ...)
parsed = yaml.safe_load(c.to_yaml_text())
assert parsed["title"] == "Suspicious login\nvalidated: true\nstatus: stable"
assert "validated" not in parsed
```
Confirmado — ver `tests/test_sigma_candidate.py::
test_yaml_text_is_always_valid_yaml_even_with_hostile_field_values`.
115→122 tests totales, todos en verde.

### RT-02 — Response actions sin vínculo verificado al caso — CONFIRMADO

**Bucket:** vulnerabilidad de diseño (defense-in-depth) —
**threat-model precondition** honesta: hoy no existe ningún caller en el
codebase que invoque `propose_response_action` con evidencia controlada
por un LLM (`grep` confirma cero llamadas fuera del propio módulo y sus
tests) — el módulo está construido pero no cableado. El hallazgo es real
sobre el contrato del constructor, no sobre un exploit alcanzable hoy.

**Fix aplicado:** `propose_response_action` ahora requiere
`authorized_result: ZaynorAuthoritativeResult` y valida que cada
`evidence_refs` esté en `{(ref.artifact, ref.lineage_id) for finding in
authorized_result.findings for ref in finding.evidence_refs}` —
exactamente el mismo patrón que `authority_guard.py` ya usa para
`evidence_refs`. `EvidenceRef("fabricated", "not-bound-to-any-result")`
ahora es rechazado con `ResponseActionError`.

**Induction:** `tests/test_response_actions.py::
test_action_citing_evidence_not_in_the_authoritative_result_is_rejected`
y su variante mixta (`test_action_citing_a_mix_of_real_and_fabricated_
evidence_is_rejected`) — ambas confirman el rechazo; los 5 tests
preexistentes actualizados para pasar `authorized_result` siguen en
verde.

### RT-03 — EvidenceRef no verificado contra el manifest congelado — CONFIRMADO (alcance acotado)

**Bucket:** vulnerabilidad real de integridad para el caso verificable;
gap documentado (no forzado) para los casos no verificables.

Investigación más profunda que el reporte original mostró que el
`artifact_id` de la vía EBS-JSON (`login["ref"]`/`fs_record["ref"]`/
`egress["ref"]` en `ebs_artifact_scorer.py`) es un identificador de
**evento dentro de un archivo**, no un identificador de archivo — no
tiene equivalente en `CaseManifest.entries` (que son pares
`relative_path`/`sha256` de ARCHIVOS), así que "verificar contra el
manifest" no aplica a esa rama sin comparar cosas de distinto namespace.

Para la vía de imagen forense real, en cambio, confirmé contra el imagen
pública 2019-OWL de Digital Corpora que `metadata.hive_sha256` **es**
literalmente `sha256sum` del archivo de hive real en disco:
```
NTUSER.DAT: 9a99d2d6adeb52b994d9293d55d7bd460e948cce63e9b8a848306e8e4603ebdc
metadata.hive_sha256 del signal correspondiente: (idéntico)
```
Esto SÍ es directamente comparable a `ManifestEntry.sha256` — y antes del
fix, nada lo comparaba. `metadata.source_path`/`source_profile`, en
cambio, resultaron ser paths de **subdirectorio completo**, no de
archivo individual (confirmado corriendo el bundle real) — forzar una
comprobación de membresía exacta ahí produciría falsos rechazos, así que
deliberadamente NO se comprueban; queda documentado como alcance más
angosto, no como el hallazgo resuelto en su totalidad.

**Fix aplicado:** `translate_mode1_bundle` acepta `manifest:
CaseManifest | None = None`; cuando se pasa, `_signal_evidence_ref`
recibe el conjunto de hashes autorizados y rechaza con `AdapterError` (no
descarta en silencio — un hash de hive que no está en el manifest es una
violación de integridad real, no un gap benigno) cualquier
`metadata.hive_sha256` fuera de ese conjunto. `ZaynorMode1Adapter.analyze`
(el único caller de producción, que ya tenía `manifest` en scope) ahora
lo pasa siempre.

**Induction (caso negativo, sintético):**
`tests/test_zaynor_mode1_security.py::
test_signal_hive_sha256_outside_the_manifest_is_rejected` — un
`hive_sha256` fabricado (`"f"*64`) contra un manifest que no lo contiene
levanta `AdapterError`.

**Induction (caso positivo, real — el más importante):** congelé la
imagen 2019-OWL completa (257 archivos reales) con `case_freezer.
freeze_case()` y corrí `ZaynorMode1Adapter.analyze()` de punta a punta
contra Mode 1 real:
```
VERDICT: ABSTAIN
FINDINGS: 1
 - F-INC-OWL-ADAPTER-TEST ABSTAIN 11 refs
```
Sin este paso, el fix podría haber introducido falsos rechazos en el
único caso real disponible — confirmado que NO los introduce cuando el
manifest realmente cubre la evidencia analizada.

### RT-04 — Integración Volatility sin dump real — CORRECTAMENTE ABIERTA, sin acción

Codex etiquetó esto como "HIPÓTESIS ABIERTA — NO CONFIRMADA" y no forzó
un veredicto — exactamente el uso correcto de la escalera epistémica.
Coincido: `test_memory_forensics_readiness.py` (después del fix de la
ronda 6) confirma que el binario `vol` real corre bajo el alias `vol3`
que VIGÍA busca, pero eso es resolución de binario, no análisis forense.
Sigue pendiente, como ya estaba documentado, conseguir un dump real de
Digital Corpora para correr Mode 1 de punta a punta contra memoria y
confirmar señales reales (pslist/malfind/netscan). Sin cambios de código
en esta ronda — no hay nada que "arreglar" en una hipótesis
correctamente no confirmada.

### RT-05 — `human_approved: bool` — deuda ya documentada, sin acción nueva

Codex re-confirma independientemente el mismo diagnóstico que el round 5
(`docs/red-team/2026-09-16-round-5-agents-authority-boundary.md`, R5-2):
ningún caller productivo abusa hoy del parámetro, pero el contrato sigue
sin ligar la aprobación a identidad/alcance/caso. Ya está marcado
explícitamente como deuda de seguridad por instrucción directa de Anna
("no lo frenaría el hackathon por esto, pero lo marcaría explícitamente
como deuda de seguridad"). Sin cambios en esta ronda.

### RT-06 — D3FEND `HIGH_CONFIDENCE` sin trazabilidad — CONFIRMADO

**Bucket:** fractura epistémica (framing), no vulnerabilidad de control
de acceso — coincido con la clasificación de Codex.

El módulo ya tenía un docstring explícito distinguiendo `HIGH_CONFIDENCE`
(mapeo bien conocido) de `NEEDS_VERIFICATION` (dirección plausible, ID
exacto no verificado contra d3fend.mitre.org) — pero ese docstring vive
en el código fuente, nunca en el dict que `enrich_finding_d3fend()`
emite. Un analista leyendo un reporte renderizado nunca ve esa
distinción; ve la palabra "HIGH_CONFIDENCE" sola, que puede leerse como
una certificación oficial de MITRE — exactamente lo que Codex señaló
citando que D3FEND describe sus relaciones ofensivo↔defensivo como
inferidas/experimentales, no equivalencias deterministas.

**Fix aplicado:** `_CONFIDENCE_BASIS` — texto explicativo por nivel de
confianza, agregado como `confidence_basis` en cada entrada del dict que
`enrich_finding_d3fend()` devuelve. Aclara explícitamente que
`HIGH_CONFIDENCE` es juicio editorial de ZAYNOR, no una calificación
oficial de MITRE D3FEND (que no publica ratings de confianza por
relación).

**Induction:** `tests/test_d3fend_enrichment.py::
test_confidence_basis_travels_with_the_label_into_the_emitted_dict` —
confirma que el texto explicativo llega al mismo dict que el label,
distinguiendo el contenido esperado por nivel.

### RT-07 — Nombres públicos "Vigia" — REFUTADO

**Bucket:** ninguno — no es un hallazgo válido contra el estándar real
del repo.

Codex cita `adapter.py:27` (`VigiaExecutor`), `adapter.py:126` (`class
VigiaAdapter`), y `zaynor_mode1_executor.py:179` (`def run_vigia_mode1`)
como violación de "la convención que definiste." Verificado contra la
convención REAL, no contra una paráfrasis de ella: `docs/red-team/
2026-09-16-round-2-naming.md` (cerrada, mergeada en `0fbff83`) es
explícita:

> "El contrato pedido es que los módulos del repo se identifiquen como
> ZAYNOR; **el nombre externo sólo debe aparecer en el adapter, el
> proceso invocado, y la documentación de integración.**"
>
> "**No es un hallazgo**: no se considera bug que el executor invoque
> `vigia_agent.py`, ni que los campos del bundle externo se llamen
> `vigia_agent_version`."

El alcance real de round 2 (confirmado por su propio diff, `0fbff83`) fue
específicamente **nombres de módulo importables** (`vigia_mode1_executor.py`
→ `zaynor_mode1_executor.py`, `vigia_mcp_client.py` → `zaynor_mcp_client.py`)
— ya cerrado, y confirmado por inducción que ningún módulo propio de
`src/zaynor` es importable con prefijo `vigia_*` hoy
(`find src/zaynor -name 'vigia_*.py'` → vacío).

Los tres símbolos que Codex cita son, precisamente, "el adapter" y "el
proceso invocado" — las dos categorías que round 2 designó explícitamente
como el lugar CORRECTO para que el nombre externo aparezca:
- `VigiaAdapter`/`VigiaExecutor` (`adapter.py`): la clase adapter en sí y
  el tipo del callable que inyecta.
- `run_vigia_mode1` (`zaynor_mode1_executor.py`): la función que invoca
  el proceso externo `vigia_agent.py`.

Por la misma lógica, `VigiaMCPClient`/`VigiaMCPConfig`/`VigiaMCPError` en
`zaynor_mcp_client.py` (módulo ya renombrado desde round 2, cliente del
propio servidor MCP `Vigia_Sift_Bridge` de VIGÍA) caen en la misma
categoría — el cliente/adapter del bridge externo, no un módulo que
oculta su origen.

**No se aplica ningún rename.** Documentado acá para que quede explícito
que el hallazgo fue verificado y rechazado con razón, no ignorado.

### RT-08 (reporte completo de Codex) — TOCTOU en `generate_forensic_hash` — CONFIRMADO

**Bucket:** vulnerabilidad real, mismo patrón ya cerrado en otras dos
funciones hermanas del mismo módulo.

**Causal chain confirmada leyendo el código, antes del fix:**
```
guard.validate(path)  →  check.valid == True  (path OK en este instante)
    ↓ (ventana de carrera)
sha256_file(os.path.abspath(path))  →  open() plano por nombre, sin
    O_NOFOLLOW, sin fstat-verify, sin verify_no_toctou() posterior
```
`read_evidence` y `grep_pattern`, en el mismo archivo, ya usan
`guard.safe_open()` (apertura con `O_NOFOLLOW` + verificación de que sigue
siendo un archivo regular + lock compartido) seguido de
`guard.verify_no_toctou()` — `generate_forensic_hash` era la única de las
tres que no seguía ese patrón, pese a ser la función cuyo propósito
completo es producir un hash con valor de cadena de custodia.

**Fix aplicado:** reemplazado el `sha256_file(os.path.abspath(path))`
suelto por lectura en bloques a través de `guard.safe_open(path, "rb")`
más `guard.verify_no_toctou(path, check)` después de leer — exactamente
el mismo patrón que `_read_evidence`. Import de `sha256_file`/`os` (ya no
usados) eliminado.

**Induction:**
`tests/test_tools_readonly.py::test_generate_forensic_hash_rejects_symlink_escape` —
un symlink apuntando fuera del directorio permitido, antes indetectable
por esta función específica (aunque sí por `read_evidence` con el mismo
truco), ahora es rechazado con `SYMLINK` en el error, igual que las otras
dos. `test_generate_forensic_hash_matches_real_sha256` confirma que el
hash calculado sigue siendo el correcto para el caso benigno.

### RT-09 (reporte completo de Codex) — `extra_env` y `ollama_host` sin guardas — CONFIRMADO

**Bucket:** vulnerabilidad de diseño real sobre una garantía explícita del
producto (Anna: "no permiten uso IA que no sea local... por favor no
hagamos eso").

**Dos gaps distintos, confirmados por separado:**

1. `VigiaMCPConfig.ollama_host: str = "http://127.0.0.1:11434"` no tenía
   ninguna validación — a diferencia de `agents/ollama_client.py`'s
   `OllamaClient`, que ya rechaza cualquier host no-local
   (`_local_url()`). El mismo tipo de valor (endpoint de Ollama pasado al
   bridge de VIGÍA vía `VIGIA_OLLAMA_HOST`) tenía el invariante aplicado
   en un lugar del codebase y no en el otro.
2. `env.update(self.extra_env)` corría último e incondicional en
   `server_params()`, después de fijar `VIGIA_LLM_BACKEND=ollama` y de
   remover las variables de credenciales cloud — cualquier caller que
   construyera `VigiaMCPConfig(extra_env={"VIGIA_LLM_BACKEND":
   "anthropic", "ANTHROPIC_API_KEY": "sk-..."})` habría revertido
   silenciosamente ambas protecciones para el subproceso del bridge.

**Fix aplicado:**
- `_local_ollama_url()` (duplicado en miniatura del contrato de
  `agents/ollama_client.py`, con el tipo de error propio de este módulo)
  validado en un nuevo `VigiaMCPConfig.__post_init__`.
- `__post_init__` también rechaza, con `VigiaMCPError` explícito en el
  momento de construir el config (no en silencio al lanzar el
  subproceso), cualquier clave de `extra_env` que colisione con
  `VIGIA_EVIDENCE_DIR`/`VIGIA_LLM_BACKEND`/`VIGIA_OLLAMA_MODEL`/
  `VIGIA_OLLAMA_HOST`/`PYTHONPATH` o las 4 variables cloud que este mismo
  método ya limpia.
- Defensa en profundidad adicional: `server_params()` ahora aplica
  `extra_env` ANTES de fijar las variables de seguridad (no después),
  así que incluso si el chequeo de `__post_init__` se evadiera (p.ej. via
  `object.__setattr__` sobre el dataclass frozen), el orden de escritura
  por sí solo seguiría garantizando que las variables protegidas ganen.

**Induction:** `tests/test_zaynor_mcp_config_security.py` — 4 tests
nuevos, todos en verde: rechazo de `ollama_host` remoto
(`https://example.invalid`, `http://10.0.0.4:11434`), aceptación de
`localhost`/`127.0.0.1`, rechazo de `extra_env` intentando sobrescribir
`VIGIA_LLM_BACKEND`/`ANTHROPIC_API_KEY`/`VIGIA_EVIDENCE_DIR`/`PYTHONPATH`,
y aceptación de una clave de `extra_env` genuinamente no relacionada.

## Discarded (non-exploitable) vectors

| Vector | Result | Why it failed |
|--------|--------|----------------|
| Cross-check de `metadata.source_path`/`source_profile` contra `CaseManifest` (extensión de RT-03) | Descartado por diseño | Confirmado por inducción que son paths de subdirectorio completo, no de archivo — un chequeo de membresía exacta produciría falsos rechazos en casos reales, no cierra una vulnerabilidad real |
| Cross-check de `artifact_id` (vía EBS) contra `CaseManifest` | Descartado por diseño | `artifact_id` es un identificador de evento dentro de un JSONL (namespace distinto de rutas de archivo); el chequeo aplicable ahí es `verify_ebs_freshness` (ya existente desde round 3/4), no membresía en el manifest |
| Renombrar `VigiaAdapter`/`VigiaExecutor`/`run_vigia_mode1`/`VigiaMCP*` (RT-07 tal como fue planteado) | FALSIFIED contra el estándar real | Round 2 designa explícitamente el adapter y el proceso invocado como el lugar correcto para el nombre externo — renombrar violaría esa misma convención, no la cumpliría |

## Recommendations (fuera de alcance de este cambio — sólo registro)

- Cuando se consiga un memory dump real (RT-04), correr Mode 1 de punta a
  punta y confirmar señales reales de Volatility, no sólo resolución del
  binario.
- Si alguna vez se necesita una verificación de independencia real de
  `metadata.source_path` (RT-03, alcance no cubierto), requeriría que
  VIGÍA emita un path de ARCHIVO específico por señal, no un directorio —
  cambio del lado de VIGÍA, fuera de alcance de ZAYNOR (AGENTS.md §2.1).
