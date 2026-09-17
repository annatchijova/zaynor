# Auditoría de 710578c — "security: remediate confirmed Arena audit findings"
## Round 16
**Fecha:** 2026-09-17
**Origen:** Anna: revisar el commit de seguridad de Codex contra la suite
completa + pruebas reales de CLI/casos, "fijate del test de Codex, el
agente a veces no se da cuenta".

## Metodología

Lectura completa del diff de `710578c` (14 archivos), evaluado archivo por
archivo con abducción/refutación antes de aceptar cada cambio como correcto.
Luego: suite completa, pipeline real `case → freeze → analyze → audit` contra
el motor vendorizado, y `chat`/`serve` reales contra un Ollama local de
verdad (no mockeado) para confirmar que nada de esto rompió el trabajo de la
ronda 15.

## Hallazgo confirmado y corregido: dos tests de `hmac_chain.py` rotos por su propio fix

**Firstness.** `pytest tests/` fallaba en `test_invalid_hex_key_falls_back_to_file`
y `test_resolves_key_from_file` con
`ValueError: HMAC key file must not be readable by group or other users`.

**Secondness.** `resolve_hmac_key()` ahora rechaza (correctamente, es el fix
de 710578c) un archivo de clave con `mode & 0o077 != 0` — legible por grupo
u otros. Los dos tests crean su archivo temporal con `key_file.write_bytes(...)`
sin fijar el modo explícitamente. Bajo el umask de este entorno (`0o002`),
el archivo resultante queda en `0o664` — legible por grupo — disparando el
`ValueError` nuevo. No es un bug del código de producción: es que el fix de
permisos se agregó sin actualizar estos dos tests preexistentes (no forman
parte del diff de 710578c) para que reflejen la nueva exigencia.

**Thirdness.** Un endurecimiento de seguridad que cambia una precondición
(“cualquier archivo” → “archivo con permisos estrictos”) rompe silenciosamente
cualquier test que construya esa precondición con los defaults del sistema en
vez de fijarla explícitamente. El umask del entorno de CI/desarrollo no está
garantizado — por eso el `test_hmac_key_file_must_not_be_group_or_world_readable`
que Codex SÍ agregó fija `chmod(0o640)` explícito (para forzar el caso
inseguro), pero los dos tests preexistentes que querían el caso SEGURO
confiaban en el umask del sistema para lograrlo, y en este umask no alcanza.

**Fix:** agregado `key_file.chmod(0o600)` explícito en ambos tests, después
de `write_bytes`. Confirmado: `tests/test_hmac_chain.py` 5/5 pasan; suite
completa 238/238.

## Verificado, sin hallazgos: refutación de tres hipótesis

- **SHA de GitHub Actions pineados incorrectamente** (`.github/workflows/pages.yml`):
  verificados los 4 pines (`checkout`, `configure-pages`, `upload-pages-artifact`,
  `deploy-pages`) contra la API real de GitHub (`GET /repos/<owner>/<repo>/git/refs/tags/<tag>`)
  — los 4 SHA coinciden exactamente con el tag que dicen representar. Hipótesis
  refutada: no hay riesgo de cadena de suministro acá.
- **`check_structured_output` ahora exige campos obligatorios y podría romper
  un caller real**: `grep` confirma que la única invocación de esta función
  fuera de sus propios tests es la exportación en `agents/__init__.py` — no
  hay ningún caller de producción todavía. El endurecimiento (antes varios
  campos eran opcionales vía `if key in presented`, permitiendo que un agente
  omitiera silenciosamente `unknowns`/`hypotheses`/`fractures` y pasara la
  validación igual) es seguro de aplicar sin romper nada existente.
- **`case_freezer.py`'s nuevo `evidence_dir.chmod(0o500)` rompe `analyze`**:
  refutada por la corrida real end-to-end (`freeze → analyze → audit`, ver
  abajo) — el directorio de evidencia sigue siendo legible/ejecutable
  (necesario para listar/leer sus archivos), solo pierde el bit de escritura,
  que es la intención.

## Observación, no corregida — merece una decisión explícita

`audit_log.py::verify_with_report`, líneas 204-208:

```python
else:
    if key is None:
        caveats.append("entry_hmac present but not verified (no key supplied)")
    if saw_any_missing_hmac:
        return False, "chain mixes HMAC and non-HMAC entries"
```

Este `return False` para una cadena mixta (algunas entradas con `entry_hmac`,
otras sin) se ejecuta **incluso cuando `key is None`** — es decir, verificar
SIN clave una cadena que en algún momento se firmó con HMAC y luego no (o
viceversa: un log honesto que empezó sin `ZAYNOR_HMAC_KEY` configurada y
después se le configuró una) ahora falla duro, no como caveat.

El nombre del test que Codex escribió (`test_entries_without_hmac_fail_when_a_key_is_supplied`)
sugiere que la intención era "solo falla si se dio una clave" — pero el
código no lo condiciona a eso para este chequeo específico. No hay ningún
test que cubra "cadena mixta, verificada SIN clave" para confirmar cuál de
los dos comportamientos es el intencional.

No lo cambié: es defendible en cualquiera de las dos direcciones (fail-closed
en una inconsistencia estructural es razonable incluso sin clave — un log
mixto es sospechoso lo sepas verificar criptográficamente o no), y es un
archivo que Codex sigue tocando activamente. Queda para que lo decidan:
¿"cadena mixta" debería ser caveat cuando no hay clave para verificar nada, o
falla siempre? Si la respuesta es "siempre falla", falta un test que lo
documente explícitamente.

## Pruebas reales, no simuladas

- `case → freeze → analyze → audit` contra `vendor/vigia_engine/`, sin
  `--engine-repo`: `overall: VERIFIED`, veredicto `ABSTAIN` (consistente con
  el escenario demo, que no dispara señales). El cambio `NOISE → UNKNOWN` en
  `zaynor_mode1_executor.py` no afectó este caso (no llega a `NOISE`).
- `zaynor models`: contra el Ollama real de esta máquina, lista
  `hermes3:8b`, `gemma3:27b`, `deepseek-r1:8b` ya instalados — coincide
  exactamente con el catálogo sugerido de la ronda 15.
- `zaynor chat --model llava:latest`, pregunta real, sin mock: narración
  correcta ("el veredicto es ABSTAIN"), `claims_hallucinated: 0`.
- `zaynor serve --model hermes3:8b`: servidor real levantado, `POST
  /v1/chat/completions` real contra Ollama. La respuesta del modelo en este
  caso no coincidió con ningún patrón de reclamo verificable y el guard la
  reemplazó por `[CLAIM NOT VERIFIED]` — comportamiento preexistente de
  `hallucination_guard.py` (no tocado en esta ronda ni en la de Codex), falla
  cerrado correctamente ante una respuesta no interpretable, no es un hallazgo
  nuevo.

## Estado final

238/238 tests pasan. Pipeline completo confirmado funcionando de punta a
punta con Ollama real. Un hallazgo confirmado y corregido (tests de
`hmac_chain.py`); una observación de diseño sin resolver, documentada para
decisión explícita; tres hipótesis de riesgo formuladas y refutadas por
evidencia directa (API de GitHub, grep de callers, corrida real).
