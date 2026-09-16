# Auditoría de Claude sobre `Mentor.chat_checked` (Codex)
## Red Team Round 9
**Fecha:** 2026-09-16
**Método:** Abductive Engineering (A-D-I) + Red-Team Auditing.
**Origen:** trabajo de Codex, sin commitear, sin pasar por ninguna
ronda de red-team todavía — `src/zaynor/agents/mentor.py`'s nuevo método
`Mentor.chat_checked()` y `tests/test_mentor_checked.py`.
**Base:** working tree local (uncommitted). **Evidencia reproducible:**
script inline reproducido abajo, ejecutado contra el código vivo antes y
después del fix.

## Threat model

- El atacante controla el texto que narra el LLM local (vía Ollama).
- El atacante NO puede modificar el código Python de ZAYNOR.
- Foco de esta ronda: la frontera entre "un `ZaynorAuthoritativeResult`
  genuinamente sellado" y "un objeto Python con esa forma, pasado por
  cualquier caller" — exactamente el tipo de distinción que un sello
  criptográfico existe para separar, si efectivamente se verifica en
  cada punto de uso.

## Epistemic legend
CODE FACT · PLAUSIBLE HYPOTHESIS · CONFIRMED BY INDUCTION · FALSIFIED

## Executive summary

| ID | Severity | Level | Módulo | Resultado |
|----|----------|-------|--------|-----------|
| R9-1 | High | CODE FACT + CONFIRMED BY INDUCTION → fix aplicado | `agents/mentor.py` | `chat_checked` recibía un parámetro `seal` que nunca se verificaba contra `result` — un `result` forjado junto a un `seal` real pero de otro resultado pasaba el chequeo de narrativa sin ninguna alarma. |

## Findings

### R9-1 — `seal` en `chat_checked` era decorativo — nunca se verificaba

**Bucket:** vulnerabilidad real de frontera de autoridad — exactamente la
clase de problema que CLAUDE.md §5.1 y AGENTS.md existen para prevenir
("un hash prueba integridad, no verdad — pero sólo si alguien
efectivamente lo chequea").

- **Surprise / expectation violada:** `Mentor.chat_checked(question, *,
  audience, result, seal, contexts=())` acepta un `seal: AuthoritySeal`
  como parámetro obligatorio — la firma por sí sola comunica "esto valida
  que `result` está realmente sellado." Pero el cuerpo del método era:
  ```python
  narration = self.chat(question, audience=audience, contexts=contexts)
  return check_narrative(result, narration)
  ```
  `check_narrative` (en `authority_guard.py`, ya auditado en rondas
  anteriores) confía en `result` tal como se le pasa — no re-verifica
  ningún seal internamente, por diseño (esa responsabilidad es de quien
  construye/recibe el `ZaynorAuthoritativeResult`, no de un chequeador de
  narrativa genérico). `chat_checked` era exactamente ese punto de
  responsabilidad, y no la ejercía: el parámetro `seal` se recibía y
  nunca se tocaba.
- **Abducción:** el patrón correcto YA existe en el mismo repo —
  `ConsultTools.__init__` llama `verify_authoritative_result(package,
  seal)` antes de exponer cualquier vista, y
  `AuthorizedFacts.from_sealed_result` hace lo mismo. `chat_checked` fue
  escrito imitando la firma de esos dos (recibe `result` + `seal`) pero
  sin copiar el paso de verificación que les da sentido.
- **Causal chain:**
  ```
  caller construye/recibe un `result` no verificado (podría venir de
  cualquier lado: un bug, una deserialización, un intento de forjar)
      ↓
  llama chat_checked(result=result_no_verificado, seal=seal_real_de_OTRO_result)
      ↓
  chat_checked nunca compara seal contra result
      ↓
  check_narrative(result_no_verificado, narración) — evalúa la narración
      CONTRA EL RESULT FORJADO, no contra la verdad sellada real
      ↓
  GuardResult.suspicious = False para una narración que coincide con
  el result forjado (p.ej. "El resultado es MALICE" cuando lo sellado
  real dice ABSTAIN)
  ```
- **Deducción:** si `result` y `seal` no se corresponden, `chat_checked`
  debe fallar (rechazar la llamada), no simplemente proceder a chequear
  la narrativa contra lo que sea que `result` diga.
- **Induction (antes del fix):**
  ```python
  real_result = ZaynorAuthoritativeResult(..., verdict="ABSTAIN", ...)
  real_seal = seal_authoritative_result(real_result)
  forged_result = ZaynorAuthoritativeResult(..., verdict="MALICE", ...)  # objeto distinto

  checked = Mentor(FakeClient("The result is MALICE.")).chat_checked(
      "...", audience=Audience.JUNIOR, result=forged_result, seal=real_seal,
  )
  # checked.suspicious == False
  # checked.safe_narration == checked.original_narration  (sin cambios)
  ```
  Confirmado: la narrativa forjada pasa limpia, sin ninguna señal de
  alarma, porque nada comparó `forged_result` contra `real_seal`.
- **Fix aplicado:** `chat_checked` ahora llama
  `verify_authoritative_result(result, seal)` (mismo helper ya usado por
  `ConsultTools`/`AuthorizedFacts`) como primera línea del método, antes
  de generar o chequear cualquier narrativa. Un `result`/`seal` que no se
  corresponden levantan `SealError` inmediatamente.
- **Induction (después del fix):** mismo script, ahora levanta
  `SealError("authoritative result seal mismatch")` en vez de devolver un
  `GuardResult` silenciosamente aprobado. Test de regresión:
  `tests/test_mentor_checked.py::
  test_checked_chat_rejects_a_result_not_bound_to_the_given_seal`.
- **Threat-model precondition:** ninguna especial más allá de "un caller
  de `chat_checked` recibe o construye un `result` sin haberlo verificado
  él mismo primero" — dado que `chat_checked` es exactamente el punto de
  la API diseñado para aceptar `result`+`seal` juntos, ese es el
  precondition que la propia función existe para cerrar, no algo externo
  a su responsabilidad.

## Lo que Codex hizo bien (confirmado, no se re-litiga)

- `chat_checked` reutiliza `check_narrative` en vez de reimplementar
  chequeo de alucinaciones — no hay una segunda ruta de verificación de
  narrativa más débil.
- El docstring original ya advertía correctamente "Callers must use
  `safe_narration`... The raw completion remains available only as
  diagnostic data" — la disciplina de separar narración cruda de
  narración segura estaba bien encaminada; sólo faltaba la verificación
  de seal que le da sentido a aceptar `seal` como parámetro.
- Los dos tests originales (claim no soportado / claim preservado) cubren
  correctamente el comportamiento de `check_narrative` en sí — el gap
  estaba específicamente en la ausencia de un tercer caso (seal no
  correspondiente), no en lo que ya estaba probado.

## Discarded (non-exploitable) vectors

Ninguno para esta ronda — el único vector investigado (seal sin
verificar) resultó ser un hallazgo real, no una hipótesis descartada.

## Recommendations (fuera de alcance de este cambio — sólo registro)

- Ninguna pendiente de esta ronda — R9-1 quedó cerrado con fix y test de
  regresión.
