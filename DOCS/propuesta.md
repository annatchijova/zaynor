# Propuesta — Zaynor: DFIR post-incidente sobre el motor determinista de VIGÍA

*[Read this in English](./proposal.en.md)*

> Esta es la segunda revisión de la propuesta (reemplaza la versión anterior,
> que todavía asumía que Zaynor reimplementaba en miniatura los mecanismos de
> VIGÍA). El cambio de fondo, después del feedback del jurado/mentores: **VIGÍA
> es un motor forense determinista preexistente, y Zaynor no lo reescribe —
> lo consume detrás de una frontera estrecha.** Ver
> `DOCS/plan-implementacion.md` para el desglose capa por capa de cómo se
> construye esto.

## 0. Por qué cambia la arquitectura (y qué no cambia)

Lo que **no** cambia: el principio rector sigue siendo el mismo de la primera
propuesta —

> La IA decide qué investigar. La IA no decide qué es verdad.

Lo que cambia es *quién* implementa la autoridad epistémica determinista. La
propuesta anterior tenía a Zaynor reconstruyendo, a escala de hackathon,
versiones chicas de mecanismos que VIGÍA ya tiene resueltos y probados: un
gate de corroboración, un detector de fracturas, una cadena de auditoría, un
guardia contra alucinaciones. Reescribir eso en 48 horas produce una versión
peor de algo que ya existe, y le da al jurado —que ya vio y valoró VIGÍA— la
peor historia posible: "teníamos 100k líneas y reescribimos 1800 para poder
decir que las hicimos nosotros". La corrección es tratar a VIGÍA como
**motor/backend** detrás de un adapter, no como referencia de diseño para
reimplementar.

Esto obliga a distinguir dos nociones de autoridad que la propuesta anterior
mezclaba en una sola:

- **Agencia investigativa** — decidir qué evidencia inspeccionar a
  continuación, dada una pregunta discriminante entre hipótesis en
  competencia. Esto lo puede tener el LLM.
- **Autoridad epistémica** — decidir qué estado (`OBSERVED`, `CORROBORATED`,
  `CONTRADICTED`, `UNKNOWN`) tiene una afirmación sobre la evidencia. Esto lo
  tiene únicamente el motor determinista (VIGÍA), nunca el LLM.

`investigative authority ≠ epistemic authority`: el LLM puede guiar una
investigación adaptativa sin que eso implique que decide la verdad. Esa
distinción es lo que permite que Zaynor funcione en dos modos sin
contradecirse:

```
Modo básico (sin investigador LLM):
  evidencia -> VIGÍA (motor determinista) -> findings -> LLM narra

Modo asistido (con investigador LLM):
  evidencia -> VIGÍA (análisis inicial)
      -> LLM: "quiero comprobar X"
      -> herramienta determinista de solo lectura
      -> observación
      -> VIGÍA (re-verifica, actualiza estado autoritativo)
      -> finding
```

## 1. Tesis de producto (actualizada)

> Zaynor es un sistema de DFIR post-incidente construido sobre una frontera
> de autoridad forense determinista. Los mecanismos existentes de VIGÍA
> proveen el análisis reproducible de evidencia, el estado epistémico, la
> procedencia, la detección de fracturas y la auditabilidad — sin
> reescribirse para el hackathon. Zaynor agrega la capa de integración
> orientada a incidentes, la contextualización con MITRE ATT&CK/NIST, el flujo
> de postmortem y una interfaz de LLM local. El LLM puede explicar los
> findings deterministas y, opcionalmente, guiar investigación adicional de
> solo lectura, pero nunca puede promover sus propias conclusiones a estado
> forense autoritativo.

## 2. Diferenciador

El aporte de Zaynor no es "otro motor forense" — es la capa de integración
que convierte un motor determinista de propósito general (VIGÍA) en una
aplicación de investigación post-incidente orientada a ciberdefensa: declara
el incidente, congela el caso, invoca a VIGÍA a través de un adapter
tipado, enriquece el resultado con MITRE ATT&CK/NIST, y genera un informe y
un postmortem cuya prosa nunca puede exceder lo que el ledger de VIGÍA
efectivamente corroboró. La demo prueba ese límite en vivo con un ítem de
evidencia adversarial que intenta y falla en tomar autoridad — y prueba,
además, que **Zaynor nunca duplica lógica que VIGÍA ya resuelve**: si algo
tiene equivalente en VIGÍA, se llama; no se reimplementa "chico" solo para
poder decir que Zaynor lo hizo de cero.

## 3. Arquitectura

```
                              ZAYNOR
                                │
                         INCIDENT / CASE
                                │
                                ▼
                      FROZEN EVIDENCE
                manifest + hashes + lineage (Zaynor propio)
                                │
               ┌────────────────┴────────────────┐
               │                                  │
               ▼                                  ▼
     VIGÍA — MOTOR DETERMINISTA          RUTA ASISTIDA POR IA (opcional)
     (existente, vía adapter,                     │
      NO reimplementado)                   LLM decide qué investigar
               │                                  │
               │                          herramientas de solo lectura
               │                                  │
               │                          candidate claims (predicados)
               │                                  │
               └────────────────┬─────────────────┘
                                 ▼
                     FRONTERA DE AUTORIDAD
                    (dentro de VIGÍA: verificación
                     de procedencia/independencia,
                     fracturas, contradicciones)
                                 │
                                 ▼
                    ESTADO AUTORITATIVO (VIGÍA)
              OBSERVED / CORROBORATED / CONTRADICTED / UNKNOWN
                                 │
                                 ▼
                    ADAPTER: ZaynorAuthoritativeResult
              (Zaynor NO conoce las tripas de VIGÍA — solo
               este contrato tipado y estable)
                                 │
                                 ▼
                    ENRIQUECIMIENTO CON FRAMEWORKS
            MITRE ATT&CK (qué técnica) · NIST (cómo encaja
            en investigación/respuesta) — nunca sube la
            certeza de un finding, solo lo contextualiza
                                 │
                                 ▼
                       RESULTADO SELLADO
                                 │
                                 ▼
                          LLM LOCAL
              (narra; guard de alucinaciones valida cada
               cita contra el resultado sellado)
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                   ▼
      informe de incidente   postmortem       resumen ejecutivo /
      (qué pasó, con qué     (qué aprendimos,  guía por audiencia
       respaldo)              qué cambia)      (analista/junior/directivo)
```

`VigiaAnalysisResult` (nombre provisorio, se confirma contra la firma real
de `vigia_agent.py` al construir el adapter en la capa correspondiente del
plan de implementación) es tratado como una caja con un contrato estable:
observaciones, timeline, fracturas, hipótesis en competencia, findings con
estado/evidence_refs/procedencia/racional, ítems `UNKNOWN`, metadata de
auditoría/integridad y versión del motor. Si internamente VIGÍA tiene quince
objetos distintos, Zaynor no necesita saberlo — el adapter es exactamente el
punto donde se absorbe esa complejidad.

## 4. Reconocimiento de repos — decisión de reutilización

Se reemplaza la categoría anterior ("ADAPT / design reference") por una que
distingue explícitamente si algo se llama en vivo o se reimplementa:

> **`REUSE/CALL`** — se invoca el motor/módulo existente de VIGÍA a través
> de un adapter; Zaynor no reimplementa su lógica.
> **`ADAPT`** — se copia un contrato/firma acotado (no el archivo completo),
> porque VIGÍA lo trae embebido en un componente con demasiado acoplamiento
> propio para llamarlo directo.
> **`NEW ZAYNOR CODE`** — lógica específica de la integración
> (incidente→caso, enriquecimiento MITRE/NIST, postmortem) que no existe en
> VIGÍA porque no es su dominio.

Todas las rutas de abajo se confirmaron contra el repo real de VIGÍA
(`/home/labestiadevigia/vigia-repo`) antes de escribir esta tabla:

| Mecanismo | Ruta confirmada en VIGÍA | Decisión | Nota |
|---|---|---|---|
| Motor de análisis / punto de entrada | `vigia_agent.py` | **REUSE/CALL** | firma exacta de invocación a confirmar al construir el adapter |
| Sandbox de solo lectura sobre evidencia | `vigia/core/path_guard.py` (`PathGuard`) | **ADAPT** | se copia el contrato de confinamiento de paths, no el módulo completo — VIGÍA lo trae acoplado a su propio bridge MCP |
| Canonicalizador | `vigia/core/canonicalize.py` | **REUSE/CALL** | módulo stdlib, sin acoplamiento — se importa directo |
| Cadena de auditoría (hash-chain) | `vigia/core/tool_log_chain.py`, `vigia/core/hash_chain.py` | **REUSE/CALL** | esto fue lo que más convenció al jurado — no se reescribe una versión chica |
| Gate de corroboración determinista | `vigia/collapse_decision.py` | **REUSE/CALL** | Zaynor no reimplementa un gate propio |
| Sellar-antes-de-narrar | `vigia/core/bundle_builder.py` (también existe una variante en `forensics/bundle_builder.py` — a resolver cuál aplica al invocar el adapter) | **ADAPT** | se adapta el contrato de secuencia (sellar antes de narrar), la implementación de sellado se llama, no se copia |
| CAIE (cross-artifact scoring) | `vigia/tools/caie.py` | **fuera de alcance** | sigue sin ser necesario para un incidente con una fractura diseñada; no se llama ni se reimplementa |
| Guardia contra alucinaciones | `vigia/llm/hallucination_guard.py` (`AuthorizedFact`) | **ADAPT** | se adapta el patrón `AuthorizedFact`/matching; el vocabulario cerrado específico del dominio de VIGÍA (verdicts, scores propios) no se importa — Zaynor define su propio vocabulario de facts autorizados |
| Mapeo MITRE ATT&CK | referencias de TTP como comentarios en `vigia_scorer.py` (reglas de detección) | **verificado: NO existe como motor de mapeo dedicado** | esto es una diferencia real con lo asumido en el pizarrón — el enriquecimiento MITRE/NIST se construye como capa nueva de Zaynor (§5), no se "reutiliza" porque no hay un módulo equivalente que llamar |
| OpenHands (loop de agente, sandboxing, risk self-report) | — | **IGNORE** | sin cambios respecto a la recon original: Python ≥3.12 pin, dependencia LiteLLM, Docker o `LocalWorkspace` sin sandbox real, para capacidades que este proyecto no necesita |

La fila de MITRE es la corrección más importante de esta revisión frente al
pizarrón: no hay un módulo de VIGÍA para llamar ahí, así que decir
"reutilizado" sería la misma falsa reutilización de la que se está huyendo
en el resto de la tabla. Se construye como capa nueva, explícitamente
marcada como tal.

## 5. Enriquecimiento MITRE ATT&CK / NIST

Capa nueva de Zaynor (no existe en VIGÍA como motor dedicado), insertada
entre el estado autoritativo de VIGÍA y el sellado final — nunca antes:

- **MITRE ATT&CK** describe qué técnica/comportamiento corresponde a un
  finding ya `CORROBORATED`. Es contextualización, no evidencia adicional:
  un mapeo a una técnica ATT&CK no puede mover un finding de `INSUFFICIENT`
  a `CORROBORATED`.
- **NIST** (marco de respuesta a incidentes) estructura cómo ese finding
  encaja en el ciclo de investigación/respuesta/postmortem — es la
  taxonomía que organiza el documento final, no una fuente de verdad sobre
  los hechos.

Ninguno de los dos frameworks tiene autoridad epistémica. Si en algún punto
un mapeo MITRE terminara siendo tratado como si aumentara la certeza de un
finding, eso es exactamente el tipo de fuga de autoridad que `AGENTS.md` §2
prohíbe — se lo trata igual que a la prosa del LLM: contextualiza, no
decide.

## 6. Postmortem — contrato de contenido (corregido)

Se mantiene casi intacta la estructura de la propuesta anterior, con una
corrección epistemológica: el template **no puede asumir que siempre existe
una causa raíz corroborada.**

1. Resumen ejecutivo (prosa LLM validada, 1-3 oraciones).
2. Timeline reconstruida (datos del resultado sellado, sin prosa).
3. **Causa raíz** — si existe una claim `CORROBORATED` que la sostiene, se
   narra citando su procedencia y fuentes independientes. **Si no existe,
   la sección dice explícitamente `ROOT CAUSE: UNKNOWN` o lista los
   factores contribuyentes respaldados sin forzar una causa raíz única.**
   El template nunca inventa una causa raíz para llenar una sección.
4. Hipótesis descartadas, cada una con la evidencia `CONTRADICTED`
   específica que la refutó.
5. Ítems `UNKNOWN` explícitos — nunca omitidos.
6. Acciones defensivas propuestas, **ligadas a findings corroborados y/o
   riesgos observados, indicando explícitamente cuándo la causa raíz
   permanece `UNKNOWN`** — no atadas a una causa raíz que puede no existir.
7. Rastro de auditoría — hash de la cadena de llamadas de la investigación
   (mecanismo de VIGÍA, llamado vía `REUSE/CALL`, no reimplementado).

Tampoco se fuerza un veredicto global tipo `MALICE`/`BENIGN`/`SUSPICIOUS`
por sección: el objeto principal del postmortem puede terminar perfectamente
como una lista de findings con estado individual (`CORROBORATED`,
`CONTRADICTED`) más campos explícitos en `UNKNOWN` (atribución, vector de
acceso inicial, intención) sin necesitar una etiqueta única de veredicto. Si
VIGÍA expone un estado equivalente con semántica propia, se usa ese; no se
inventa uno nuevo solo para completar una casilla del diagrama.

## 7. Incidente simulado, demo de 3 minutos

Sin cambios de fondo respecto a la propuesta anterior
(`INC-2026-DEMO-001`, servicio comprometido escalando a credencial admin
robada, ítem adversarial en `ticket_comment.txt`). El guion de demo
incorpora el enriquecimiento MITRE/NIST como paso visible entre el
resultado sellado de VIGÍA y la narración del LLM, y el postmortem final
debe mostrarse con al menos un ítem `UNKNOWN` explícito — incluyendo,
potencialmente, la causa raíz misma, sin que eso se lea como una falla de
la demo sino como prueba de que el sistema no sobre-reclama certeza.

## 8. Veredicto

La arquitectura de fondo (LLM sin autoridad epistémica, gate determinista,
postmortem separado del informe de incidente, hash-chain de auditoría) no
cambia entre esta revisión y la anterior. Lo que cambia es dónde vive la
implementación de esa autoridad determinista: en VIGÍA, invocado vía
adapter, no reescrito en miniatura dentro de Zaynor. El riesgo principal
pasa de "quedarse sin tiempo reimplementando mecanismos que ya existen" a
"construir un adapter mal especificado que oculte de más o de menos las
tripas de VIGÍA" — ver `DOCS/plan-implementacion.md` para cómo se acota ese
riesgo capa por capa.
