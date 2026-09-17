# Vendorización del motor determinista de VIGÍA — un solo repositorio, un solo clone
## Round 14
**Fecha:** 2026-09-16
**Origen:** Anna: "no quiero que dependa de VIGÍA... no me importa si hay
que hacer todo desde cero, VIGÍA solo de Python tiene 800K LOC" — luego,
tras descartar tanto un clone del repo entero como reescribir el motor
desde cero: "REUTILIZAR los módulos que sirvan, editados o copy-paste, no
vamos a clonar un repo de 800K líneas. Solo lo que sirve." Método:
tracing dinámico real (no un análisis estático de imports), confirmado
corriendo `vigia_agent.py` de verdad contra ambos caminos de ingestión
reales que Zaynor usa.

## Por qué tracing dinámico y no estático

Un primer intento con AST estático (buscar cualquier `import` en el
código fuente de los 3 archivos raíz de VIGÍA) encontró **79 módulos /
~45.500 líneas** — pero incluía módulos que un análisis más cuidadoso
reveló como imports condicionales/lazy nunca alcanzados por Mode 1 en la
práctica (`vigia.vigia_sift_bridge`, el bridge MCP de Mode 2; varios
analizadores forenses de plataformas específicas cargados sólo bajo
ciertas ramas). Un análisis estático sobreestima: no distingue "este
archivo importa X en algún lado" de "X corre de verdad cuando VIGÍA
analiza evidencia real."

**Método aplicado:** ejecutar `vigia_agent.py` de verdad (vía
`runpy.run_path`, capturando `sys.modules` antes/después) contra:
1. Un caso JSON rico mínimo sintético (mismo shape que
   `vigia-repo/cases/*.json`: `artifacts[]` con `type`/`source`/
   `content`/`metadata`).
2. La imagen forense real de Digital Corpora (2019-OWL,
   registry/prefetch/browser/event-log).

Unión de ambos trace sets + 3 módulos agregados defensivamente por
inspección de `_build_orchestrator_kwargs` (`vigia.sift.mft_parser`,
`vigia.sift.pcap_parser` — rutas de ingestión reales de Zaynor no
disparadas por ninguno de los dos casos de prueba; `vigia.core.
devil_advocate_gen` — obligatorio para veredictos MALICE/INTENT según la
propia doctrina de VIGÍA, tampoco disparado por los casos de prueba
usados). Total confirmado: **79 archivos, ~41.400 líneas** — menos del
5% del repositorio completo de VIGÍA.

**Deliberadamente excluidos** (confirmado que Mode 1 nunca los carga):
- `vigia.vigia_sift_bridge` — el bridge MCP de Mode 2, arquitectura
  completamente distinta (Ollama/Claude-driven interactivo), no Mode 1.
- `vigia.scripts.run_pipeline` — fallback de texto plano de VIGÍA cuando
  `SIFTOrchestrator` no está disponible; ya es un camino opcional y
  degradado con gracia en el propio código de VIGÍA, nunca ejercido por
  la superficie de capacidad confirmada de Zaynor.

## Verificación: la copia vendorizada corre idéntico al checkout externo

**Inducción, no promesa.** Cada uno de los dos caminos reales se corrió
DOS VECES — una contra el checkout externo de vigia-repo, otra contra la
copia recién vendorizada en `vendor/vigia_engine/` — comparando salida.

| Camino | Externo | Vendorizado |
|---|---|---|
| JSON rico mínimo (1 artifact) | 1 señal, ABSTAIN | 1 señal, ABSTAIN (idéntico) |
| Imagen real 2019-OWL, sin env vars de allowlist | registry NO ANALIZADO (comportamiento esperado, ya documentado) | registry NO ANALIZADO (idéntico) |
| Imagen real 2019-OWL, con `VIGIA_ALLOWED_REGISTRY_PATHS`/`VIGIA_ALLOWED_DUMP_PATHS` seteadas | 12 señales totales, 5 registry, INTENT | 12 señales totales, 5 registry, ABSTAIN* |

\* La diferencia de veredicto entre las dos corridas de imagen (INTENT
sin registry vs. ABSTAIN con registry) es un efecto conocido y correcto
de que la señal `REGISTRY_UNANALYZED` cambia el cómputo compuesto —
ambas corridas del MISMO camino (con/sin registry) coinciden entre
externo y vendorizado; no es una discrepancia entre las dos copias del
motor, es el comportamiento esperado de correr con/sin las variables de
allowlist correctas.

**Pipeline completo de Zaynor, de punta a punta, sin `--engine-repo`:**
```
zaynor freeze --case-id ... (sin motor, sólo congela evidencia)
zaynor analyze --case-id ... --cases-root ./cases --output-root ./outputs
  # SIN --engine-repo — usa vendor/vigia_engine/ por default
zaynor audit --case-id ... --cases-root ./cases --output-root ./outputs
  # overall: VERIFIED
```
Confirmado en `/tmp` (descartado al terminar), reproducido una segunda
vez tras una pérdida accidental de trabajo no commiteado a mitad de la
tarea (ver "Incidente" abajo) — mismo resultado ambas veces.

## Cómo se conecta

- `src/zaynor/vendored_engine.py`: `VENDORED_ENGINE_PATH` — resuelve
  `<repo_root>/vendor/vigia_engine` a partir de `zaynor.__file__`, así
  que funciona igual para un install editable (`pip install -e .`) sin
  hardcodear una ruta de máquina específica.
- `cli.py`: `--engine-repo` en `analyze` pasa de `required=True` a
  `default=None` — cuando no se pasa, `_default_engine_repo()` usa
  `VENDORED_ENGINE_PATH`. Quien quiera apuntar a un checkout externo real
  (para desarrollar sobre VIGÍA mismo, o probar una versión más nueva del
  motor) sigue pudiendo pasar `--engine-repo` explícito — el override no
  se quitó, sólo dejó de ser obligatorio.
- 5 archivos de test (`test_adapter.py`, `test_ebs_artifact_scorer.py`,
  `test_zaynor_mode1_executor.py`, `test_memory_forensics_readiness.py`,
  `test_real_forensic_image_evidence.py`) migrados de
  `VIGIA_REPO_PATH = Path("/home/labestiadevigia/vigia-repo")`
  (ruta fija de una máquina) a `VENDORED_ENGINE_PATH` — efecto
  secundario positivo: estos tests dejan de depender de que
  `/home/labestiadevigia/vigia-repo` exista en la máquina que corre la
  suite, se vuelven portables. `test_real_forensic_image_evidence.py`
  mantiene una ruta externa SEPARADA (`EXTERNAL_EVIDENCE_ROOT`) sólo para
  los datos de la imagen forense real (gigabytes de Digital Corpora, no
  vendorizados — son datos, no código).
- Tests dejados intencionalmente SIN migrar: `test_zaynor_mcp_client.py`
  y `test_investigator_tools.py` — usan `VigiaMCPClient`/
  `vigia_sift_bridge.py` (Mode 2/MCP), deliberadamente fuera del alcance
  de esta ronda ("motor primero, API/Ollama después" — instrucción
  explícita de Anna).

## Incidente durante la tarea: pérdida de trabajo no commiteado

A mitad de la vendorización, `vendor/vigia_engine/` (no trackeado en
git) y `src/zaynor/vendored_engine.py` desaparecieron del disco, y
`cli.py` volvió a su estado anterior (`--engine-repo` obligatorio) — sin
que `git reflog` muestre ningún `reset`/`checkout` (esas operaciones no
mueven refs, así que no dejan rastro ahí). Coincide en el tiempo con
actividad concurrente de Codex en el mismo repositorio. No se pudo
confirmar la causa exacta.

Lección aplicada de inmediato: cada archivo se re-creó y se agregó al
índice de git (`git add`) INMEDIATAMENTE tras escribirlo, en vez de
esperar a tener todo listo para un commit único al final — el índice
sobrevive una limpieza del árbol de trabajo que el árbol de trabajo por
sí solo no sobrevive. Confirmado por el propio incidente: dos de los
cinco archivos de test se revirtieron una SEGUNDA vez entre el fix y la
corrida de tests, mientras que `vendor/vigia_engine/` (79 archivos, ya
copiados antes del primer incidente) sobrevivió intacto ambas veces —
consistente con que el proceso que interfiere actúa sobre archivos
activamente abiertos/tocados por otro agente, no sobre todo el árbol de
trabajo a la vez.

## Estado final

223/223 tests pasan. Pipeline completo (`freeze` → `analyze` → `audit`)
confirmado funcionando sin `--engine-repo`, sin ningún repositorio
externo, en una corrida limpia en `/tmp`. Commit pendiente de aprobación
explícita de Anna, siguiendo la nueva regla de permiso explícito para
commit/push.
