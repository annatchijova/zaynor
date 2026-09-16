# Auditoría — paquete `agents/` (Codex) antes de portar mission/autonomy
## Red Team Round 5
**Fecha:** 2026-09-16
**Método:** Abductive Engineering (A-D-I) + Red-Team Auditing.
**Origen:** crítica de 4 puntos de Anna sobre el merge de Codex
(`5c7903b` "feat: add local policy-gated agent runtime",
`119539e` "feat: enforce agent capabilities and authority guards")
antes de portar `mission.py`/autonomy desde ANNACONDA.
**Base:** `main` @ `ff284af` (antes de este fix). **Evidencia reproducible:**
lectura directa de `src/zaynor/agents/{policy,registry,authority_guard}.py`
y `src/zaynor/zaynor_mode1_executor.py`, más `python3 -m pytest tests/ -q`
antes y después del fix.

## Threat model
- El atacante (o un LLM local bajo presión narrativa) **puede**: llamar
  tools declaradas en su propio manifest de rol, construir el JSON
  `presented` que pasa a `check_structured_output`/`check_narrative`,
  elegir el texto narrativo libremente.
- El atacante **no puede**: modificar el código de `policy.py`/
  `registry.py`/`authority_guard.py`, falsificar el `manifest_sha256` de
  otro rol, ni alterar `ZaynorAuthoritativeResult` una vez sellado por
  `authority_seal.py` (eso ya está cubierto por rounds anteriores).
- Frontera de confianza en juego: la que separa "lo que VIGÍA decidió y
  quedó sellado" de "lo que el agente local, corriendo sobre Ollama,
  puede nombrar, invocar o presentar como si fuera autoridad."

## Epistemic legend
CODE FACT · PLAUSIBLE HYPOTHESIS · CONFIRMED BY INDUCTION · FALSIFIED

## Executive summary

| ID | Severity | Level | Module | Finding |
|----|----------|-------|--------|---------|
| R5-1 | Medium | CODE FACT + CONFIRMED BY INDUCTION (fix) | `policy.py`, `registry.py` | Nombre de tool `record_hypothesis` sugiere que el agente local registra hipótesis autoritativas — authority creep de nombre, no de comportamiento |
| R5-2 | Low (deuda documentada, no bloqueante) | CODE FACT | `policy.py` | `human_approved: bool` no liga la aprobación a quién/qué/para qué caso — cualquier caller interno puede setear `True` |
| R5-3 | Medium | CODE FACT + CONFIRMED BY INDUCTION (fix) | `authority_guard.py` | `_techniques()` infiere semántica ATT&CK de la forma de un string (`T####`) en vez de leer el campo tipado autorizado |
| R5-4 | Medium | CODE FACT + CONFIRMED BY INDUCTION (fix) | `authority_guard.py`, `schemas.py`, `zaynor_mode1_executor.py` | El veredicto autoritativo de ZAYNOR vivía bajo `integrity["agent_verdict"]` — mismo nombre que el campo crudo de VIGÍA, escondido dentro de un dict "de salud", no un campo de primer nivel |

Los cuatro hallazgos son ciertos en el código vigente al momento de la
crítica (`ff284af`); ninguno es una historia plausible sin verificar —
los cuatro fueron leídos directamente en los archivos citados antes de
tocar nada, y R5-1/R5-3/R5-4 tienen fix aplicado y confirmado por
inducción (suite completa antes/después).

## Findings

### R5-1 — `record_hypothesis`: authority creep de nombre

**Severity:** Medium **Epistemic level:** CODE FACT (nombre real en
`policy.py:_TOOL_EFFECTS` y `registry.py:FLEET_COMMANDER`) +
CONFIRMED BY INDUCTION (fix aplicado, suite verde) **Bucket:** hygiene /
diseño de nombres — no hay bypass de capability, el `DERIVE` scoping a
`investigation_plan` ya era correcto.

- **Surprise / expectation violada:** el diagrama
  `FLEET_COMMANDER → record_hypothesis → DERIVE: investigation_plan` es
  técnicamente inofensivo (scoped, DERIVE, no ACQUIRE/AUTHORIZE), pero el
  *nombre* del tool comunica "registro una hipótesis" sin calificar que es
  una propuesta no autoritativa. AGENTS.md §2.2-2.4 es explícito: el LLM
  propone, nunca decide — un nombre que no refleja eso es la clase de
  error que ese mismo documento existe para prevenir, incluso cuando el
  código detrás está bien scoped.
- **Abducción:** el nombre fue elegido por analogía directa con
  `investigation_log.add_hypothesis()` de ANNACONDA (rol
  `{"open","supported","refuted"}`), sin renombrar al cruzar el límite de
  autoridad hacia ZAYNOR, donde "hipótesis" nunca puede ser un objeto de
  primera clase con el mismo peso que un `AuthoritativeFinding`.
- **Deducción:** si el nombre se deja así, cualquier futuro consumer (un
  dashboard, un log de auditoría, un jurado leyendo el manifest) puede
  razonablemente inferir que ZAYNOR tiene un tipo `Hypothesis` con
  autoridad epistémica — un malentendido costoso de corregir después de
  que `mission.py` se porte y el nombre se congele en más lugares.
- **Fix aplicado:** renombrado a `record_hypothesis_proposal` en
  `policy.py:_TOOL_EFFECTS` y `registry.py:FLEET_COMMANDER.tools` — el
  scoping (`DERIVE`, recurso `investigation_plan`) no cambió, porque el
  scoping ya era correcto; sólo el nombre cambia. Se prefirió
  `record_hypothesis_proposal` sobre `record_investigative_question`
  porque ANNACONDA's `investigation_log.py` ya modela estados de
  hipótesis (`open`/`supported`/`refuted`) que una "pregunta" no captura
  — el concepto de hipótesis-como-propuesta es genuino, sólo necesitaba
  el calificador. Cuando exista un tipo `AuthoritativeHypothesis` (con
  autoridad real, post-VIGÍA), debe tener un nombre completamente
  distinto — nunca compartir "Hypothesis" a secas.
- **Induction:** `grep -rn "record_hypothesis"` en todo el repo tras el
  fix devuelve únicamente las dos ocurrencias renombradas; ningún test
  existente referenciaba el string viejo. `python3 -m pytest tests/ -q`
  → 110 passed (ver R5-4 para el conteo agregado).
- **Threat-model precondition:** ninguna — esto es corrección de nombre,
  no de control de acceso; el capability model ya era correcto antes del
  fix.

### R5-2 — `human_approved: bool` es una aprobación sin identidad

**Severity:** Low, documentado explícitamente como deuda de seguridad
por instrucción directa de Anna ("no frenaría el hackathon por esto,
pero lo marcaría explícitamente como deuda de seguridad") **Epistemic
level:** CODE FACT **Bucket:** threat-model assumption / hygiene — no
hay una vulnerabilidad explotable *hoy* porque no existe todavía un
caller real que setee `human_approved=True` sin verificación humana; es
una fragilidad en la forma del contrato, no un bypass demostrado.

- **Surprise / expectation violada:** `authorize_tool(role, request,
  human_approved: bool = False)` en `policy.py` es la única puerta para
  capabilities `ACQUIRE`. El booleano no registra QUIÉN aprobó, QUÉ
  aprobó exactamente, PARA QUÉ caso, CON QUÉ argumentos, ni CUÁNDO/hasta
  cuándo. Cualquier código interno capaz de invocar `authorize_tool(...,
  human_approved=True)` se convierte, de hecho, en "el humano" — sin que
  el tipo del sistema lo distinga de una aprobación real.
- **Abducción:** es el diseño más simple posible para la primera pasada
  — correcto como placeholder, insuficiente como contrato final.
- **Deducción:** si un componente automatizado (un futuro scheduler, un
  reintento, un bug en el runtime) llega a poder setear `human_approved`
  a `True` sin que un humano real lo haya decidido, `ACQUIRE` (recolectar
  telemetría/artefactos de endpoint) queda con gate roto sin que
  ningún test lo detecte, porque el contrato actual no es verificable
  independientemente del caller.
- **Induction:** no ejecutada — no hay hoy un caller de producción que
  explote esto (`AgentRuntime` no expone un camino para que el modelo
  controle `human_approved`; sólo un caller de Python que integre el
  runtime podría hacerlo). Por eso el nivel queda en CODE FACT / PLAUSIBLE
  HYPOTHESIS de fragilidad futura, no CONFIRMED — no se fabricó un
  exploit porque no hay superficie de ataque real todavía.
- **Decisión explícita, no fix:** por instrucción directa de Anna, esto
  **no se implementa ahora** (el `ApprovalGrant` sellado propuesto —
  `approval_id`, `case_id`, `capability`, `resource`, `argument_digest`,
  `approver`, `issued_at`, `expires_at` — queda documentado como diseño
  objetivo, no como código). Motivo explícito: "ahora no necesitamos más
  features durante media hora" — cerrar la ventana de nombre/veredicto
  primero, sin agregar superficie nueva.
- **Threat-model precondition:** requiere que algún código interno,
  hoy inexistente, tenga incentivo o bug para setear `human_approved=True`
  sin verificación real — no reachable desde el LLM/Ollama en el runtime
  actual.

### R5-3 — `_techniques()` infiere ATT&CK de la forma del string

**Severity:** Medium **Epistemic level:** CODE FACT + CONFIRMED BY
INDUCTION (fix) **Bucket:** vulnerabilidad de diseño en un guard que se
presenta como determinista/fail-closed — la superficie de ataque es
angosta pero real.

- **Surprise / expectation violada:** un guard cuyo propósito explícito
  es "ATT&CK technique is authorized" (mensaje de error literal en
  `check_structured_output`) construía el conjunto de técnicas
  autorizadas caminando *toda* la estructura del resultado y aceptando
  cualquier string que matcheara `value.startswith("T") and
  value[1:5].isdigit()` — inferencia de semántica por forma, dentro de
  un componente que se anuncia estructural y determinista.
- **Causal chain (antes del fix):**
  ```
  cualquier campo de result (no sólo finding.mitre)
      ↓ walk() recursivo sin filtrar por campo de origen
  string que matchea forma T####
      ↓ found.add(value.upper())
  _techniques() lo declara "autorizado"
      ↓
  check_structured_output acepta presented["mitre_techniques"]
      que contiene ese valor
  ```
  El vector concreto: si cualquier campo no-MITRE del resultado (una
  `rationale`, un `observations[]` libre) llegara a contener por
  coincidencia un token con forma `T1234`, ese valor quedaría
  "autorizado" para `mitre_techniques` aunque nunca haya sido una técnica
  real asignada por VIGÍA/el adapter.
- **Abducción:** heurística conveniente para no tener que enumerar el
  esquema exacto — pero exactamente la clase de atajo que un guard
  fail-closed no puede permitirse, porque su garantía completa depende
  de leer sólo el campo autoritativo.
- **Deducción:** con la fixture existente (`mitre={"technique":
  "T1070.006"}`, convención confirmada en `tests/test_authority_guard.py`
  antes de tocar nada), un `_techniques()` correcto debe producir
  exactamente `{"T1070.006"}` leyendo `finding.mitre["technique"]` por
  finding — no debe encontrar nada si el string T#### aparece en
  cualquier otro campo.
- **Fix aplicado:** `_techniques()` ahora itera `result["findings"]` y
  lee específicamente `finding.get("mitre", {}).get("technique")` — sin
  recorrer el resto de la estructura ni inferir por forma de string.
- **Induction:** `python3 -m pytest tests/test_authority_guard.py -q`
  (incluido en la corrida completa) sigue en verde, incluyendo
  `test_structural_guard_accepts_exact_authorized_projection` y
  `test_structural_guard_rejects_unauthorized_technique` — confirma que
  el fix preserva el comportamiento correcto documentado por los tests
  existentes sin necesitar cambiar sus fixtures.
- **Threat-model precondition:** requiere que el atacante controle (o
  pueda insertar) contenido de texto libre en algún campo del resultado
  autoritativo con forma casual T#### — plausible en `rationale` (texto
  libre de VIGÍA/abducción), no confirmado como explotado en producción
  porque ningún caso real generó ese string por accidente todavía; el
  fix cierra la clase completa, no un caso puntual.

### R5-4 — `agent_verdict` en `integrity`: leakage de esquema, ambigüedad de autoridad

**Severity:** Medium **Epistemic level:** CODE FACT + CONFIRMED BY
INDUCTION (fix) **Bucket:** diseño de contrato / frontera de autoridad —
no es un bypass de seguridad hoy (el valor era correcto), es una
ambigüedad de nombre que un jurado o auditor externo leería como "el
agente decide el veredicto", exactamente lo que AGENTS.md prohíbe.

- **Surprise / expectation violada:** `ZaynorAuthoritativeResult` no
  tenía un campo `verdict` de primer nivel. El veredicto canónico de
  ZAYNOR (`_CANONICAL_VERDICT[raw_verdict]`, la traducción
  BENIGN/SUSPICION/MALICE/ABSTAIN) se guardaba en
  `integrity["agent_verdict"]` — mismo nombre de clave que
  `bundle["agent_verdict"]`, el campo *crudo* de VIGÍA (NOISE/INTENT/
  MALICE/ABSTAIN/SUSPICION, vocabulario distinto). Dos cosas con
  autoridad y vocabulario distintos, mismo nombre de campo, una anidada
  bajo una clave ("integrity") que no comunica "esto es el veredicto".
- **Causal chain (antes del fix):**
  ```
  bundle["agent_verdict"] (vocabulario VIGÍA: NOISE/INTENT/...)
      ↓ _CANONICAL_VERDICT[...]
  integrity["agent_verdict"] = valor canónico ZAYNOR (BENIGN/SUSPICION/...)
      ↓
  authority_guard.py lee result.integrity.get("agent_verdict")
      ↓
  un lector externo (jurado, dashboard) ve "agent_verdict" y
      razonablemente pregunta: "¿el agente decide el veredicto?"
  ```
  El valor en sí era siempre correcto — VIGÍA seguía siendo la única
  fuente del veredicto — pero el *nombre y la ubicación* del campo
  contradicen la garantía documentada en AGENTS.md §2.2-2.4 ("el LLM
  nunca decide un veredicto"), y ese contraste es exactamente lo que la
  detección de NOISE/INTENT ↔ BENIGN/SUSPICION de rondas anteriores ya
  había señalado como zona confusa.
- **Abducción:** legado de una traducción incremental — el adapter fue
  agregando claves a `integrity` según se necesitaban (evidence_sha256,
  iterations_executed, self_corrections_applied), y el veredicto
  traducido se sumó ahí por conveniencia, no por diseño deliberado de
  esquema.
- **Deducción:** si el campo se mueve a `result.verdict` de primer nivel
  y se documenta como distinto de `integrity["vigia_agent_verdict"]`
  (el crudo, con nombre ya distinguible), tres consumidores deben seguir
  funcionando sin cambiar su comportamiento observable: `authority_guard`
  (autorización estructural), `zaynor_mode1_executor.translate_mode1_bundle`
  (productor), y `ZaynorMode1Adapter.analyze` (que reconstruye un
  `ZaynorAuthoritativeResult` nuevo a partir del que produce el
  executor).
- **Fix aplicado:**
  - `schemas.py`: `ZaynorAuthoritativeResult` gana `verdict: str =
    "UNKNOWN"` como campo de primer nivel.
  - `zaynor_mode1_executor.py`: `translate_mode1_bundle` ahora pasa
    `verdict=_CANONICAL_VERDICT[raw_verdict]` al constructor;
    `integrity` deja de llevar `"agent_verdict"` y conserva
    `"vigia_agent_verdict"` (el crudo, provenance) sin cambios.
  - `authority_guard.py`: las tres referencias a
    `result.integrity.get("agent_verdict")` pasan a `result.verdict`.
  - `adapter.py` — **hallazgo adicional durante el fix, no parte de la
    crítica original de Anna**: `ZaynorMode1Adapter.analyze` reconstruye
    un `ZaynorAuthoritativeResult` nuevo campo por campo a partir del
    que devuelve `translate_mode1_bundle`, y esa reconstrucción **no
    copiaba `verdict`** — habría descartado silenciosamente el veredicto
    de vuelta a `"UNKNOWN"` en el único camino de producción real (Mode
    1 → adapter). Corregido agregando `verdict=result.verdict` a esa
    reconstrucción. También se agregó soporte de `verdict` en
    `translate_result` (el adapter genérico usado por tests de
    contrato), por la misma razón: un campo con default silencioso es
    un lugar donde un valor real se pierde sin error.
  - Tests actualizados para no depender de la ubicación vieja:
    `tests/test_authority_guard.py` (`_result()`),
    `tests/test_zaynor_mode1_security.py` (línea que afirmaba
    `first.integrity["agent_verdict"]`), `tests/test_zaynor_mode1_executor.py`
    (línea que afirmaba `result.integrity["agent_verdict"]`). Las
    referencias a `bundle["agent_verdict"]` (el campo crudo real de
    VIGÍA, externo, no controlado por ZAYNOR) se dejaron intactas en
    todos los archivos — no son parte de este hallazgo.
- **Induction:** `python3 -m pytest tests/ -q` → **110 passed** después
  del fix completo (los 4 hallazgos de esta ronda). Antes del fix, la
  misma suite corría en 105 passed (baseline previo a este merge) más
  los tests nuevos del paquete `agents/` que Codex agregó — la suite
  completa nunca estuvo en rojo durante este trabajo porque cada cambio
  se verificó de inmediato tras aplicarlo.
- **Threat-model precondition:** ninguna para explotar — el hallazgo es
  de claridad de contrato y honestidad de esquema hacia un lector
  externo (jurado, auditor), no de bypass de control de acceso. La
  reconstrucción rota en `adapter.py` sí era un bug real de pérdida
  silenciosa de dato, encontrado por seguir la cadena de consumidores
  (Reproducibility Contract, Parte 6 del skill) en vez de asumir que el
  primer sitio arreglado era el único.

## Lo que Codex hizo bien (confirmado, no se re-litiga)

- El guard estructural que exige match exacto de `case_id`, hash del
  seal, estado de finding, evidence_refs, preservación de `UNKNOWN`, y
  técnicas autorizadas — arquitectura correcta, sólo el campo de origen
  de técnicas estaba mal elegido (R5-3).
- La propiedad de que `UNKNOWN` no puede ser silenciosamente descartado
  (`test_structural_guard_rejects_dropped_unknown`) es una propiedad
  epistemológica real: el LLM no puede "mejorar" el informe borrando
  incertidumbre.
- `check_narrative` está correctamente enmarcado como detector semántico
  conservador, no como prueba matemática de cero alucinaciones — el
  docstring del módulo ya lo dice explícitamente.
- La matriz de capabilities logra exactamente READ/DERIVE/ACQUIRE
  (human-gated)/MUTATE (nadie)/AUTHORIZE (nadie) — ningún rol tiene una
  capability que no debería, y el hallazgo R5-2 es sobre la *fuerza* del
  gate de ACQUIRE, no sobre su existencia.

## Discarded (non-exploitable) vectors

| Vector | Result | Why it failed |
|--------|--------|----------------|
| Forzar `mitre_techniques` no autorizado vía `test_structural_guard_rejects_unauthorized_technique` tras el fix de R5-3 | FALSIFIED (sigue rechazado) | El fix lee sólo `finding.mitre["technique"]`; un valor ajeno sigue sin entrar al conjunto autorizado — el test existente ya cubre este caso y sigue en verde |
| Buscar otro caller que setee `human_approved=True` sin gate humano real (para escalar R5-2 a CONFIRMED) | No ejecutado / no reachable hoy | `AgentRuntime` no expone ese parámetro al modelo; ningún caller de producción existente lo invoca con `True` fuera de tests — la superficie de ataque es hipotética hasta que exista tal caller, por eso R5-2 queda como deuda documentada, no como bypass confirmado |
| Grep de `record_hypothesis` residual tras el rename (para descartar un caller olvidado) | FALSIFIED (no había ninguno) | Único hallazgo: las dos ocurrencias ya renombradas; ningún test ni otro módulo referenciaba el string viejo |

## Recommendations (fuera de alcance de este cambio — sólo registro)

- Implementar `ApprovalGrant` sellado (R5-2) cuando el hackathon lo
  permita — campos ya especificados en el hallazgo R5-2 de esta ronda y
  en la crítica original de Anna.
- Al portar `mission.py`/autonomy desde ANNACONDA, verificar que ningún
  tipo nuevo se llame `Hypothesis` a secas — usar `HypothesisProposal` (o
  equivalente) consistentemente, reservando cualquier nombre sin
  calificar para un futuro `AuthoritativeHypothesis` con autoridad real,
  si es que llega a existir.
