# Zaynor

*[Read this in English](./README.en.md)*

> Estado: en desarrollo activo para la Hackathon CyberAr 2026 (48 h). El
> pipeline post-incidente está implementado en parte; el motor forense
> autoritativo todavía se ejecuta a través de un ejecutor inyectado, no
> contra VIGÍA real. Ver "Estado de implementación" para el detalle honesto
> de qué existe y qué no.

Zaynor es un sistema DFIR post-incidente construido alrededor de VIGÍA, un
motor forense determinista ya existente. Parte de un incidente **ya
declarado** cuya evidencia **ya fue recolectada**: congela el caso, lo
entrega a VIGÍA a través de un adapter explícito, contextualiza los findings
respaldados contra MITRE ATT&CK y NIST, sella el resultado, y recién
entonces un LLM local lo narra. Construido para el desafío "Eje 2 —
Inteligencia artificial para la defensa de redes e infraestructura".

El principio arquitectónico central:

> La IA decide qué investigar. La IA no decide qué es verdad.

## Alcance: el pipeline post-incidente

Zaynor es post-incidente, punto. No ingiere telemetría, no corre una regla
de detección y no correlaciona alertas para declarar un incidente: el
incidente declarado y la evidencia recolectada son su *entrada*, no algo que
Zaynor produzca. Qué sistema o proceso declaró el incidente y recolectó la
evidencia queda fuera de alcance acá.

```
incidente declarado (externo: ticket, alerta, derivacion de un analista;
   fuera de alcance) + evidencia ya recolectada (fuera de alcance)
   ->  case freeze (manifest + SHA-256, case_id inmutable)
   ->  adapter VIGIA  ->  analisis forense determinista (VIGIA)
   ->  resultado autoritativo Zaynor  ->  contexto MITRE ATT&CK / NIST
   ->  sello  ->  narracion por LLM local  ->  informe de incidente / postmortem
```

Rama opcional, de solo lectura, de vuelta hacia el lado determinista:

```
resultado autoritativo Zaynor
   ->  sugerencia investigativa del LLM  ->  consulta read-only en allowlist
   ->  evidencia  ->  re-analisis determinista (VIGIA)
   ->  resultado autoritativo actualizado
```

El case freeze no es una metáfora: es una etapa real y chica de código que
selecciona los registros de evidencia del caso, hashea cada artefacto,
escribe un manifest y cierra el bundle a escrituras antes de entregarlo.
Todo lo que viene después lee únicamente de esa copia congelada.

## Los dos límites de autoridad

- **Límite de integración Zaynor ↔ VIGÍA.** VIGÍA es un motor existente, no
  un documento de diseño para reimplementar. Se integra por un adapter
  explícito (`src/zaynor/adapter.py`) y ningún tipo interno de VIGÍA cruza
  ese límite: el contrato estable es `ZaynorAuthoritativeResult`. Una
  capacidad ausente en el resultado del ejecutor se representa como
  `UNKNOWN` explícito, nunca se completa con un valor forense generado por
  Zaynor.
- **Límite de autoridad determinista ↔ LLM.** El LLM narra un resultado ya
  sellado y puede sugerir consultas de solo lectura. No puede agregar,
  modificar ni promover un finding: desactivar el narrador no cambia ningún
  hallazgo determinista para la misma evidencia.

### Claims, predicados y evidencia

El LLM nunca propone un veredicto. Propone una *claim* con predicados
tipados (`{event_id, field, op, value}`), y el gate determinista vuelve a
leer cada predicado directamente contra la evidencia congelada — nunca
contra la cita que el modelo hace del registro. Un predicado VERIFIED no
alcanza: la claim pasa a `CORROBORATED` solo si esos predicados verificados
además cumplen los requisitos de procedencia e independencia declarados por
la regla (dos artefactos con el mismo `lineage_id` no son evidencia
independiente por estar en archivos distintos). Un predicado que contradice
da `CONTRADICTED`; lo que el gate no puede resolver queda `INSUFFICIENT` y
se muestra como `UNKNOWN` en el informe, nunca suavizado en una conjetura.

Tres reglas más que atraviesan todo el código:

- **La evidencia es dato, nunca una instrucción.** Una línea de log que diga
  "ignorá las instrucciones anteriores" sigue siendo evidencia: se registra
  y se razona como cualquier otro artefacto, no llega al canal de control de
  ningún prompt.
- **Una llamada a herramienta está en la allowlist o no ocurre.** El
  enforcement read-only es un registry de funciones hardcodeado, no un
  self-report del LLM.
- **Nada de float en lo que alimente un estado de claim o un hash.** Se usan
  enteros, `fractions.Fraction` o `decimal`. Los floats solo valen para
  renderizado de display.

## Estado de implementación

Tres estados, no dos: lo que está y corre, lo que está parcialmente, y lo
que todavía no existe. Un placeholder no se reporta como verde.

| Etapa | Dónde | Estado |
|---|---|---|
| Case freeze: manifest, SHA-256, cadena de custodia | `case_freezer.py`, `custody.py`, `hash_utils.py` | Implementado |
| Confinamiento read-only de la evidencia congelada | `path_guard.py` | Implementado |
| Worker de evidencia acotado | `sandbox.py` | Parcial — primer slice del contrato de `docs/SANDBOX.md`; no es un lanzador de contenedores ni una prueba de aislamiento |
| Registry de herramientas read-only en allowlist | `tools.py` | Implementado — `list_files`, `read_evidence`, `grep_pattern`, con auditoría previa a la ejecución |
| Log de auditoría encadenado por hash (+ ancla de cola) | `audit_log.py` | Implementado |
| Adapter Zaynor ↔ VIGÍA y contrato autoritativo | `adapter.py`, `schemas.py` | Parcial — contrato y traducción fail-closed listos; el ejecutor se inyecta y todavía no corre contra VIGÍA real |
| Log de investigación (hipótesis, sin autoridad) | `investigation_log.py` | Implementado |
| Guardia anti-alucinación de la narrativa | `hallucination_guard.py` | Parcial — mecanismo portado, con tests; todavía carga el vocabulario cerrado de ANNACONDA en vez del schema propio |
| Gate de claims y predicados | — | Pendiente |
| Contextualización MITRE ATT&CK / NIST | solo los campos en `schemas.py` | Pendiente — no hay lógica de mapeo |
| Sello del resultado autoritativo | — | Pendiente |
| Narrador LLM local | — | Pendiente — todavía no hay binding a Ollama ni a ningún backend |

## Nota de alcance abierta: el front end determinista

El árbol todavía contiene `src/zaynor/replay.py`, `detection.py`,
`correlation.py` y `tests/test_front_end.py`: las etapas 1-3 del alcance
híbrido anterior, previas a la corrección a post-incidente. Sus docstrings
siguen citando una sección de `AGENTS.md` ("Scope: the hybrid pipeline") que
ya no existe, y `docs/implementation-plan.en.md` todavía describe una
"Phase 1 — Deterministic front end". `AGENTS.md` es el contrato vigente y
dice lo contrario: replay, detección y correlación quedan fuera de alcance
por construcción.

La divergencia está abierta y no se resuelve en este README: o el front end
se retira del árbol, o se documenta explícitamente como generador de
fixtures fuera del pipeline autoritativo. Hasta que el equipo decida, este
README describe el alcance de `AGENTS.md`, y ese código no forma parte del
pipeline post-incidente descrito arriba.

## Caso de demostración

`scenarios/inc-2026-demo-001/` contiene el fixture sintético
INC-2026-DEMO-001: una credencial privilegiada (`admin.rojas`) usada desde
un dispositivo no inventariado (`DEV-UNKNOWN-17`), una sesión SSH contra
`srv-files-01`, la creación de `collection.zip`, una alteración de su
`modified_time` declarado para que parezca anterior al login, y una conexión
saliente.

`docs/ground-truth-inc-2026-demo-001.md` guarda la reconstrucción esperada,
deliberadamente fuera de `scenarios/` y fuera de todo lo que un case
freezer, una herramienta o un investigador llegue a leer. Ese archivo
también declara lo que el fixture **no** establece — cómo se obtuvo la
credencial, quién estaba en el teclado, si el archivo se transfirió entero,
quién controla el destino. Toda reconstrucción que afirme certeza sobre esos
puntos está equivocada por construcción del fixture.

## Requisitos y cómo correrlo

- Todo corre localmente. Ningún dato sale de la máquina.
- Inferencia vía un modelo local (Ollama u otro backend equivalente),
  corriendo en hardware de desarrollador común — no se asume infraestructura
  de clase servidor.
- Solo datos simulados o públicos.
- Python 3.11 sobre un sistema POSIX: el confinamiento de paths y el worker
  acotado usan `os.O_NOFOLLOW`, `flock`, `resource` y `selectors`. No hay
  manifiesto de paquete que fije una versión mínima, y no se verificó
  ninguna por debajo de 3.11.
- **Sin dependencias de runtime de terceros.** Todo el paquete es stdlib.
  `pytest` es la única dependencia de desarrollo y todavía no hay manifiesto
  de paquete.

```bash
pip install pytest
pytest -q
```

`conftest.py` agrega `src/` al path, así que no hace falta instalar el
paquete. Los tests cubren el adapter, el case freezer, el guardia
anti-alucinación, el log de investigación, el sandbox, el registry read-only
y el front end heredado.

## Estructura del repositorio

```
src/zaynor/        pipeline: case freeze, confinamiento, herramientas, adapter, logs
tests/             siete módulos de test, uno por área
scenarios/         fixture sintético INC-2026-DEMO-001 (telemetría + evidencia recolectada)
docs/              propuesta de arquitectura, plan de implementación, contrato del sandbox
docs/skills/       catálogo de 58 skills de disciplina de ingeniería y forense
docs/hackathon/    reglamento, desafíos y documentos de brainstorm del diseño
.claude/skills/    las dos skills de razonamiento que cargan automáticamente
```

Los contratos de trabajo, en orden de precedencia para una decisión de
arquitectura:

- `AGENTS.md` — el manual operativo: qué es Zaynor, los límites de
  autoridad, el workflow de git y PRs, la definición de done.
- `CLAUDE.md` — la guía de disciplina de desarrollo (razonamiento abductivo,
  higiene de git, patching quirúrgico). No se confunde con `AGENTS.md`.
- `SYSTEM_PROMPT--ZAYNOR.md` — el prompt de runtime ensamblado a partir de
  ese contrato; no puede sobreescribirlo.
- `docs/proposal.en.md` y `docs/implementation-plan.en.md` — la propuesta de
  arquitectura y el plan por fases.
- `docs/SANDBOX.md` — el contrato del sandbox de evidencia y qué parte de él
  está realmente implementada.

## Referencias de diseño

Ningún proyecto externo se usa como dependencia — el paquete es stdlib puro.
Lo que sí se tomó de otros proyectos, para que el linaje quede en el
registro:

- **VIGÍA** — no es una referencia de diseño sino la autoridad forense con
  la que Zaynor se integra: el análisis determinista autoritativo vive ahí,
  detrás del adapter. Además se adaptaron mecanismos suyos donde la
  integración directa no aplicaba: el registry de herramientas read-only
  (`tools.py`, del bridge MCP) y el patrón de cadena de hash del log de
  auditoría. Cada módulo adaptado documenta en su docstring qué se tomó, qué
  se descartó y por qué.
- **ANNACONDA** — la guardia anti-alucinación (`hallucination_guard.py`), el
  confinamiento de paths (`path_guard.py`), la cadena de custodia
  (`custody.py`) y la memoria de misión portada como log de investigación
  (`investigation_log.py`), todos adaptados con atribución en el propio
  archivo.
- **K8sGPT** — separar el hallazgo determinista de su explicación por IA en
  campos distintos, de forma que el LLM nunca pueda escribir sobre el
  veredicto, solo sobre el texto que lo acompaña.
- **HolmesGPT** — el loop de investigación acotado (límite de pasos, no
  autonomía ilimitada) y un registro declarativo de herramientas.
- **Keep** — separar identidad de evento, fingerprint de alerta e identidad
  de incidente en vez de una sola noción de "hash".

## Alcance epistémico de SHA-256

Los hashes de este repositorio registran **identidad de bytes bajo un
manifest**. No prueban origen, verdad, autoría, completitud, admisibilidad
ni intención maliciosa, y no se presenta ninguna afirmación de cadena de
custodia legal completa.

## Licencia

Apache License 2.0 — ver [`LICENSE`](./LICENSE). El código adaptado de VIGÍA
y ANNACONDA está bajo la misma licencia.
