# Propuesta mejorada — Zaynor: DFIR híbrido con postmortem verificable

*[Read this in English](./proposal.en.md)*

> Este documento reemplaza y amplía el reconocimiento inicial
> (`hackathon_dfir_recon_2026-09-15.md`) a la luz de dos señales del jurado:
> quieren ver un **postmortem** como entregable explícito, no implícito en el
> informe de incidente; y el mecanismo de **VIGÍA** (sandbox de solo lectura +
> sellado determinista antes de narrar) fue el punto que más les convenció.
> Ambas cosas cambian dónde ponemos el esfuerzo, no la arquitectura de fondo
> — el límite determinista/LLM de `AGENTS.md` §2 sigue siendo la columna
> vertebral.

## 0. Qué cambia respecto a la recon inicial

1. **Postmortem pasa de "mencionado" a componente de primera clase.** La
   recon original terminaba en un "incident report renderer" (§I) que ya
   incluía acciones propuestas, pero no un postmortem estructurado y
   separado. Ahora es la etapa 10 del pipeline (ver `AGENTS.md`), con su
   propio contrato de contenido (§5 más abajo).
2. **VIGÍA sube de "referencia de diseño" a "mecanismo adaptado" en tres
   puntos donde antes quedaba en el margen:** el hash-chain de auditoría
   (`tool_log_chain.py`) pasa de P1/opcional a P0 — es exactamente lo que
   volvió creíble la demo ante el jurado, así que no lo dejamos afuera por
   presión de tiempo; la separación sellar-antes-de-narrar
   (`bundle_builder.py`) deja de ser solo "referencia" y se adapta
   directamente para el renderer de postmortem; CAIE (`caie.py`) se mantiene
   como referencia de diseño — sigue sin ser necesaria para un solo
   incidente con una sola fractura diseñada, y forzarla ahora sería la forma
   más fácil de consumirse el tiempo que queda (ver §K de la recon original,
   sigue vigente).
3. **Terminología alineada con el contrato ya vigente del repo**
   (`AGENTS.md` §2): ya no se habla de "hypothesis ledger" genérico ni de
   "corroboration count ≥2" — el gate determinista trabaja sobre *claims* con
   *predicados* tipados (`{event_id, field, op, value}`), cada predicado se
   verifica releyendo la evidencia congelada, y una claim solo llega a
   `CORROBORATED` si además cumple los requisitos de procedencia e
   independencia de linaje (`lineage_id`, `distinct_lineages`) declarados
   por la regla del gate. El postmortem hereda esa misma disciplina: no
   puede citar nada que no esté en el ledger como `CORROBORATED` o marcado
   explícitamente `UNKNOWN`.

## 1. Tesis de producto (actualizada)

Zaynor cubre el incidente de punta a punta. Un frente liviano y
determinista (etapas 1-3) detecta y correlaciona sobre un replay
determinista de telemetría sintética hasta declarar un incidente; ahí la
evidencia se congela (case freeze: manifest + SHA-256 + `incident_key`
inmutable) y arranca la investigación profunda (etapas 5-9): un LLM local
elige qué evidencia inspeccionar, propone *claims* con predicados
verificables, y un gate determinista los re-verifica contra la evidencia
congelada antes de dejarlos entrar al ledger como `CORROBORATED`,
`CONTRADICTED` o `INSUFFICIENT` (renderizado como `UNKNOWN`). La etapa final
(10) es el **postmortem**: un documento bilingüe, generado por una plantilla
determinista más prosa del LLM, que solo puede narrar sobre hechos ya
autorizados por el ledger — nunca inventar uno nuevo (patrón
`hallucination_guard` de ANNACONDA).

## 2. Diferenciador (sin cambios de fondo, con foco en lo que el jurado valoró)

El aporte no es operacional (no compite con un SIEM ni con un asistente de
alertas en vivo): es arquitectónico. El LLM solo puede *elegir qué
investigar* sobre un toolset de solo lectura y *proponer claims con
predicados*; nunca escribe directamente un estado de finding. La demo
prueba ese límite en vivo con un ítem de evidencia adversarial que intenta y
falla en tomar autoridad sobre el veredicto — y ahora, además, prueba que el
**postmortem final** hereda la misma disciplina: cada afirmación en el
postmortem es trazable a una entrada `CORROBORATED` del ledger, con su cita
de evidencia y su `lineage_id`.

## 3. Arquitectura mínima (actualizada)

```
 [1] Replay determinista      [2] Detección/Correlación    [3] Case Freezer
  de telemetría sintética --> (regla + regla de           --> manifest + SHA-256
                                correlación)                  incident_key inmutable
                                                                    |
                                                                    v
                                                      [4] Evidencia congelada +
                                                          capa de herramientas
                                                          de solo lectura
                                                      (list_events, read_artifact,
                                                       grep_pattern, get_timeline_window)
                                                                    |
                                                                    v
                                                      [5] Investigador LLM local
                                                      (Ollama, loop de tool-calling)
                                                      propone CLAIMS con predicados,
                                                      nunca un veredicto
                                                                    |
                                                                    v
                                          [6] Gate determinista (predicate re-check)
                                          VERIFIED por relectura directa de evidencia;
                                          CORROBORATED solo si además cumple
                                          procedencia + independencia de linaje
                                                                    |
                                                                    v
                                          [7] Ledger de claims (autoridad única)
                                          CORROBORATED / CONTRADICTED / INSUFFICIENT
                                                                    |
                                            +-----------------------+-----------------------+
                                            v                                               v
                                  [8] Renderer de informe                        [9] Renderer de POSTMORTEM
                                  de incidente (bilingüe)                        (bilingüe, etapa 10)
                                  narrativa sellada aparte,                      plantilla determinista +
                                  nunca dentro del veredicto                     prosa LLM validada por
                                                                                  hallucination_guard;
                                                                                  cadena de auditoría
                                                                                  (hash-chain, VIGÍA)
                                                                                  citada como evidencia
                                                                                  de integridad del proceso
```

El postmortem (componente 9) es deliberadamente un renderer separado del
informe de incidente (componente 8), no una sección extra del mismo
documento: el informe de incidente responde "¿qué pasó y con qué
confianza?" para quien está respondiendo ahora; el postmortem responde "¿qué
aprendimos y qué cambia?" para quien audita después — son audiencias y
momentos distintos, y separarlos es lo que le permite al jurado ver
específicamente lo que pidió sin tener que extraerlo de un documento más
grande.

## 4. Reconocimiento de repos (tabla actualizada)

| Mecanismo | Repo | Decisión anterior | Decisión ahora | Por qué cambia |
|---|---|---|---|---|
| Sandbox de solo lectura sobre evidencia | VIGÍA (`vigia_sift_bridge.py`) | ADAPT | ADAPT (sin cambio) | ya era P0 |
| Canonicalizador | VIGÍA (`canonicalize.py`) | REUSE | REUSE (sin cambio) | ya era P0 |
| **Hash-chain de auditoría** | VIGÍA (`tool_log_chain.py`, `hash_chain.py`) | ADAPT, **P1/opcional** | ADAPT, **P0** | el jurado valoró explícitamente la cadena de integridad de VIGÍA; el postmortem cita esta cadena como evidencia de que el proceso de investigación no fue alterado |
| Gate determinista (forma) | VIGÍA (`collapse_decision.py`) | ADAPT | ADAPT (sin cambio, ahora expresado como predicate/claim gate por `AGENTS.md` §2) | terminología alineada, mecanismo igual |
| **Sellar-antes-de-narrar** | VIGÍA (`bundle_builder.py`) | referencia de diseño | **ADAPT directo** para el renderer de postmortem | es exactamente el patrón que necesita el componente 9 |
| CAIE cross-artifact scoring | VIGÍA (`caie.py`) | referencia de diseño | referencia de diseño (sin cambio) | sigue sin ser necesaria para un incidente con una fractura diseñada |
| Guardia contra alucinaciones | ANNACONDA (`hallucination_guard.py`) | REUSE | REUSE (sin cambio) | valida tanto el informe de incidente como el postmortem |
| Chain of custody | ANNACONDA (`chain_of_custody.py`) | REUSE | REUSE (sin cambio) | — |
| OpenHands (loop de agente, sandboxing, risk self-report) | — | IGNORE | IGNORE (sin cambio) | el análisis de costo/beneficio de la recon original sigue vigente: Python ≥3.12 pin, dependencia LiteLLM, Docker o `LocalWorkspace` sin sandbox real, para capacidades que este proyecto no necesita |

## 5. Postmortem — contrato de contenido

El postmortem es un documento generado, no escrito a mano, con esta
estructura fija (plantilla determinista; el LLM solo llena las secciones de
prosa marcadas, y solo con hechos ya `CORROBORATED`):

1. **Resumen ejecutivo** (prosa LLM, validada) — una a tres oraciones.
2. **Línea de tiempo reconstruida** (datos del ledger, sin prosa) — cada
   evento con su `event_id`, timestamp, y estado de la claim que lo respalda.
3. **Causa raíz** (prosa LLM sobre la claim `CORROBORATED` correspondiente,
   citando su `lineage_id` y las fuentes independientes que la corroboran).
4. **Hipótesis descartadas** — cada una con la evidencia puntual
   (`CONTRADICTED`) que la refutó, nunca "se descartó" sin cita.
5. **Ítems `UNKNOWN`** — explícitos, no omitidos. Esto es lo que separa un
   postmortem honesto de uno que sobre-reclama certeza (ver
   `daubert-defensible-writing`: un `UNKNOWN` documentado vale más que un
   `CORROBORATED` forzado).
6. **Acciones de prevención propuestas** (no ejecutadas) — atadas a la causa
   raíz corroborada, no a la lista completa de hipótesis.
7. **Cadena de auditoría** — hash de la cadena de tool-calls de la
   investigación (mecanismo VIGÍA adaptado), para que el postmortem mismo
   sea verificable independientemente de quién lo lea.

Cada sección de prosa pasa por el mismo `hallucination_guard` antes de
renderizarse: si el LLM cita un hecho que no matchea contra el ledger
sellado, esa sección se marca como fallida y se renderiza con el dato crudo
del ledger en su lugar — nunca se deja pasar una cita no verificada por
default.

## 6. Incidente simulado, test de necesidad de IA, demo de 3 minutos

Sin cambios de fondo respecto a la recon original (`INC-2026-DEMO-001`,
servicio comprometido escalando a credencial admin robada, ítem
adversarial en `ticket_comment.txt`, ítem `UNKNOWN` deliberado sobre la
intencionalidad del pivote final). El único ajuste es de guion: el tramo
final de la demo (antes "2:30–2:50 informe final") ahora muestra
explícitamente la **generación del postmortem** como paso separado, con la
cadena de auditoría visible en pantalla:

- **2:10–2:30** — comentario adversarial en el ticket; el sistema lo
  registra como evidencia y continúa sin alterarse (sin cambios).
- **2:30–2:50** — se genera el **postmortem**: causa raíz corroborada,
  hipótesis descartadas con su evidencia, un ítem `UNKNOWN` explícito, y la
  cadena de auditoría de la investigación visible como prueba de integridad.
- **2:50–3:00** — dos acciones de prevención propuestas + cierre.

## 7. Plan de construcción (actualizado)

**P0 (antes P1, ahora requerido):**
- Hash-chain de auditoría sobre las tool-calls de la investigación (VIGÍA
  `tool_log_chain.py` adaptado) — ya no es "valioso si sobra tiempo", es lo
  que el postmortem cita como prueba de integridad.
- Renderer de postmortem (plantilla determinista + prosa LLM validada,
  patrón sellar-antes-de-narrar de `bundle_builder.py`).

**P0 (sin cambio respecto a la recon original):** fixture de incidente,
normalizador/timeline, fracture detector, capa de herramientas de solo
lectura, loop de tool-calling con Ollama, gate de predicate/claim, guardia
contra alucinaciones, renderer de informe de incidente, el ítem adversarial.

**P1:** CLI o vista web simple para la demo; traza explícita de
"qué confirmaría/refutaría cada hipótesis" en la UI.

**P2 (no tocar hasta que todo lo demás funcione):** Docker/sandboxing más
allá del confinamiento de paths; soporte multi-incidente; CAIE-style
cross-artifact fusion.

## 8. Veredicto

La arquitectura de la recon original no cambia — el postmortem y el peso
mayor de VIGÍA se insertan en los puntos donde ya había un espacio
reservado (renderer de informe, hash-chain opcional), no requieren un
componente nuevo fuera de lo ya mapeado. El riesgo principal sigue siendo el
mismo de la recon original (§K): no dejar que construir un motor general de
timeline/fractura (o ahora, un motor general de postmortem) consuma el
tiempo que un solo incidente con una sola fractura diseñada no necesita.
