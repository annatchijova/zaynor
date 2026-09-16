# Auditoría de Claude sobre `investigation_contracts.py`/`investigation_runner.py` (Codex)
## Red Team Round 8
**Fecha:** 2026-09-16
**Método:** Abductive Engineering (A-D-I) + Red-Team Auditing.
**Origen:** trabajo de Codex, sin commitear, aún sin pasar por ninguna
ronda de red-team — `src/zaynor/agents/investigation_contracts.py` (tipos:
`AuthorizedFacts`, `InvestigationProposal`, `ObservationEnvelope`,
`InvestigationSession`) y `src/zaynor/agents/investigation_runner.py`
(`BoundedInvestigator`, el turno propuesta → policy → observación).
**Base:** working tree local (uncommitted), leído en su estado más
reciente — el archivo cambió más de una vez mientras se auditaba, dado
que Codex sigue trabajando en paralelo. **Evidencia reproducible:**
scripts inline (reproducidos abajo) ejecutados directamente contra el
código vivo, antes y después del fix.

## Threat model

- El atacante controla el texto que el modelo local (Ollama) genera como
  propuesta — puede intentar JSON con campos extra, tipos incorrectos,
  nombres de tool inventados, o reusar un `proposal_id`.
- El atacante controla el contenido de la evidencia que un tool handler
  devuelve como observación (ya cubierto por `ObservationEnvelope`'s
  `epistemic_authority=UNTRUSTED` fijo).
- El atacante NO puede modificar el código Python de ZAYNOR ni el
  `ZaynorAuthoritativeResult` ya sellado.
- Frontera de confianza: entre "lo que el modelo propone" y "lo que
  `InvestigationSession` registra como historial real de la
  investigación" — un jurado o auditor externo asumiría que ese registro
  es completo.

## Epistemic legend
CODE FACT · PLAUSIBLE HYPOTHESIS · CONFIRMED BY INDUCTION · FALSIFIED

## Executive summary

| ID | Severity | Level | Módulo | Resultado |
|----|----------|-------|--------|-----------|
| R8-1 | Medium | CODE FACT + CONFIRMED BY INDUCTION → fix aplicado | `investigation_runner.py` | Reusar el mismo `BoundedInvestigator` para más de un turno perdía en silencio el historial de turnos anteriores — `execute()` nunca sincronizaba `self._session` con la sesión que devolvía. |
| R8-2 | Low/Medium | CODE FACT + CONFIRMED BY INDUCTION → fix aplicado (autorizado por Anna: "si hay algo para arreglar, te doy luz verde") | `investigation_runner.py` | Una excepción inesperada de un tool handler (p. ej. un error de red real llamando al bridge MCP de VIGÍA) se propagaba sin capturar y abortaba todo el turno, en vez de degradar a una observación `ObservationStatus.ERROR` — estado que existía en el enum pero que ningún código producía jamás. |

## Findings

### R8-1 — Reusar el mismo investigador entre turnos pierde historial en silencio

**Bucket:** vulnerabilidad de diseño real (composition break, categoría
Round 3 de esta skill) — no es un bypass de autoridad, es una garantía de
completitud del ledger que se rompe.

- **Surprise / expectation violada:** `InvestigationSession` se
  autodescribe como "Immutable investigation ledger anchored to one
  sealed result version" — la expectativa razonable es que acumula todo
  lo que pasó. `BoundedInvestigator.execute()` calculaba
  `session = self._session.add_proposal(proposal)` y devolvía
  `session.record_observation(observation)`, pero **nunca** actualizaba
  `self._session` con ese resultado.
- **Abducción:** el docstring de la clase dice "Execute at most one
  proposal against already-bound tool handlers" — sugiere un diseño de
  un-solo-uso, construir una instancia nueva por turno. Pero nada en el
  código impide ni advierte contra llamar `propose_and_execute()` dos
  veces en la misma instancia — que es, de hecho, la forma más natural de
  escribir el loop multi-turno que este módulo existe para habilitar
  (`investigation_runner.py` es justamente la pieza que faltaba para que
  `agents/investigator_tools.py` sirva en una investigación real de más
  de una pregunta).
- **Causal chain (antes del fix):**
  ```
  investigator.propose_and_execute(q1)
      → handler real corre (side effect real, p.ej. llamada MCP a VIGÍA)
      → session_1 = original_session + [P-1] + [O-1]  (devuelto al caller)
      → self._session sigue siendo original_session (SIN P-1/O-1)
  investigator.propose_and_execute(q2)  # misma instancia
      → parse_proposal() chequea duplicados contra self._session (stale) — no ve P-1
      → handler real corre OTRA VEZ (segundo side effect real)
      → session_2 = original_session + [P-2] + [O-2]   ← P-1/O-1 desaparecieron
  ```
- **Deducción:** si el handler real ya ejecutó (p.ej. una llamada MCP real
  a `read_evidence`/`generate_forensic_hash`), el efecto real ocurrió
  igual — lo que se pierde es el REGISTRO de que ocurrió, en la sesión
  que el caller efectivamente se queda usando para el turno siguiente.
- **Induction (antes del fix):** reproducido con dos preguntas sobre el
  mismo `BoundedInvestigator`:
  ```python
  session_1, p1, o1 = investigator.propose_and_execute(question="q1")
  session_2, p2, o2 = investigator.propose_and_execute(question="q2")
  # handler llamado 2 veces (dos side effects reales)
  # session_1.proposals == ["P-1"]
  # session_2.proposals == ["P-2"]   <- perdió P-1 por completo
  ```
- **Fix aplicado:** `execute()` ahora hace `self._session = session`
  (post `record_observation`) antes de retornar — la instancia queda
  sincronizada con lo que devuelve, así que reusarla acumula en vez de
  bifurcar. Efecto colateral correcto: `parse_proposal`'s propio chequeo
  de `proposal_id` duplicado ahora sí ve los turnos anteriores de la
  misma instancia.
- **Induction (después del fix):** mismo script, `session_2.proposals ==
  ["P-1", "P-2"]` — historial completo. Test de regresión:
  `tests/test_investigation_runner.py::
  test_reusing_the_same_investigator_across_turns_accumulates_the_session`
  y `test_reusing_the_same_investigator_rejects_a_repeated_proposal_id`.
- **Threat-model precondition:** ninguna especial — reproducible con
  cualquier caller que use la instancia para más de un turno, el patrón
  de uso más natural para este módulo.

### R8-2 — `ObservationStatus.ERROR` es inalcanzable; un fallo real de red aborta todo el turno

**Bucket:** robustez/disponibilidad, no autoridad.

- **Surprise / expectation violada:** `ObservationStatus` define
  `OBSERVED`/`REJECTED`/`ERROR`, pero grep confirma que sólo `OBSERVED`
  se construye alguna vez en todo el árbol — `ERROR`/`REJECTED` son
  miembros de enum sin ningún código que los produzca. `AgentRuntime.run()`
  (el otro camino equivalente, en `runtime.py`) sí captura
  `except Exception as exc:` alrededor específicamente de la llamada al
  handler, convirtiendo el fallo en `{"error": ...}` — datos que el
  modelo puede leer y sobre los que puede replantear su próxima pregunta,
  en vez de abortar la sesión completa. `investigation_runner.py::execute()`
  no tiene ese comportamiento: su único `try/except` envuelve TODO el
  bloque (autorización + handler + construcción del envelope) y sólo
  captura `(AgentPolicyError, InvestigationContractError, TypeError,
  ValueError)` — cualquier otra excepción se propaga sin capturar.
- **Abducción:** el enum `ObservationStatus.ERROR` fue diseñado
  anticipando exactamente este caso (un tool handler que falla debe
  producir una observación de estado `ERROR`, no una excepción que mate
  el turno) pero `execute()` todavía no se conectó a esa intención.
- **Deducción:** un error de red real llamando al bridge MCP de VIGÍA
  (`ConnectionError`, `TimeoutError`, cualquier excepción de `asyncio`
  que no sea `VigiaMCPError`/`InvestigatorToolError`) debería producir
  una observación con contenido de error, no reventar el turno completo.
- **Induction (antes del fix):** reproducido con un handler que levanta
  `ConnectionError("network hiccup calling VIGIA MCP bridge")` —
  la excepción se propagaba sin capturar fuera de `execute()`,
  confirmado por script directo (no por lectura de código).
- **Fix aplicado:** la llamada al handler (`payload = handler(...)`)
  ahora está en su propio `try/except Exception`, específicamente
  acotado a esa llamada (no a todo el bloque de autorización +
  construcción del envelope) — mismo patrón que `AgentRuntime.run()` ya
  usa en `runtime.py`. Un fallo del handler produce
  `payload={"error": f"tool failed: {type(exc).__name__}: {exc}"}` con
  `status=ObservationStatus.ERROR`, y el turno sigue construyendo una
  `ObservationEnvelope` normal — el error queda registrado en la sesión
  como dato, no como excepción que mata el turno. Un fallo en
  `authorize_tool` (política) o en la construcción del envelope mismo
  (p.ej. un float colado en el payload, vía `InvestigationContractError`)
  sigue abortando el turno con `InvestigationRunnerError` — esos SÍ son
  violaciones estructurales que deben fallar alto, no degradarse.
- **Induction (después del fix):** mismo script, el handler roto ahora
  produce `observation.status == ObservationStatus.ERROR` y
  `observation.payload == {"error": "tool failed: ConnectionError: ..."}`
  — la sesión registra la observación de error normalmente
  (`len(session.observations) == 1`). Test de regresión:
  `tests/test_investigation_runner.py::
  test_a_broken_tool_handler_produces_an_error_observation_not_an_exception`.
  Ésta es también la primera vez que `ObservationStatus.ERROR` se
  construye en todo el árbol — antes existía en el enum sin ningún
  código que lo alcanzara.
- **Autorización para el fix:** Anna dio luz verde explícita ("si hay
  algo para arreglar, te doy luz verde") tras revisar el hallazgo,
  incluyendo aplicar el fix sobre un archivo que Codex seguía editando
  en paralelo — la coordinación quedó documentada acá para que Codex vea
  qué cambió y por qué al retomar el archivo.

## Lo que Codex hizo bien (confirmado, no se re-litiga)

- `parse_proposal` rechaza campos de autoridad (`verdict`, `finding`,
  `hypothesis`, `score`, `seal`, `result`, etc.) Y exige el conjunto EXACTO
  de campos permitidos — ni faltantes ni extras — confirmado con
  `test_model_cannot_create_authoritative_hypothesis_or_finding`.
- `execute()` usa el MISMO gate determinista (`authorize_tool`) que
  `AgentRuntime.run()` — no hay una segunda ruta de autorización más débil
  para este camino "bounded" alternativo.
- `ObservationEnvelope.__post_init__` fija `epistemic_authority=UNTRUSTED`
  por construcción — no hay forma de marcar una observación como
  autorizada.
- `AuthorizedFacts.from_sealed_result` re-verifica el seal
  (`verify_authoritative_result`) antes de construir el proyecto de
  hechos — no confía en que el `result` recibido ya esté validado.

## Discarded (non-exploitable) vectors

| Vector | Result | Why it failed |
|--------|--------|----------------|
| Inyectar `"verdict": "MALICE"` dentro de `arguments` (campo permitido) en vez de como key top-level (bloqueada) | FALSIFIED | Ningún tool handler existente lee `arguments.get("verdict")`; el valor queda en `proposal.arguments` como dato sin interpretación estructural — no hay camino que lo trate como autoritativo hoy |
| Llamar `execute()` con un `InvestigationProposal` construido a mano, sin pasar por `propose()` (bypaseando al LLM) | FALSIFIED como vulnerabilidad nueva | Sigue pasando por el mismo `authorize_tool()` determinista — el diseño ya asume que la autorización nunca depende de si "el modelo realmente lo propuso", sólo del nombre del tool y el rol |

## Recommendations (fuera de alcance de este cambio — sólo registro)

- Ninguna pendiente de esta ronda — R8-1 y R8-2 quedaron cerrados con fix
  y test de regresión.
