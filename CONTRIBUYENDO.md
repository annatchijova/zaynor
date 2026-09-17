# Contribuyendo a ZAYNOR

*[Read this in English](CONTRIBUTING.md)*

Gracias por querer trabajar en ZAYNOR. Es un proyecto chico y enfocado —
esta guía es intencionalmente corta.

## Antes de empezar

- ZAYNOR integra el motor determinista de VIGÍA (`vendor/vigia_engine/`)
  en vez de reimplementarlo — ver `AGENTS.md` §2.1. Si tu cambio toca algo
  bajo `vendor/`, necesita una razón documentada; la suposición por
  defecto es que la lógica propia de VIGÍA no es tuya para reescribir.
- Nada de floats en el camino de decisión (`CLAUDE.md` §5.2). Cualquier
  ratio, peso, o valor que alimente un resultado sellado usa
  `fractions.Fraction`.
- El LLM nunca decide un veredicto (`CLAUDE.md` §5.1). Si tu cambio deja
  que un modelo influya en un finding, un puntaje o un sello, la
  arquitectura está mal — no es un problema de implementación.

## Flujo de trabajo

1. Leé el archivo real antes de parchearlo — no asumas qué hace una
   función por su nombre ni por memoria de una versión anterior.
2. Un cambio enfocado por commit. Explicá *por qué*, no solo qué.
3. Corré la suite completa antes de proponer un cambio:
   ```bash
   python3 -m pytest tests/ -q
   ```
4. Si tocás `src/zaynor/report.py`, `audit_log.py`, o cualquier cosa
   sellada/hasheada, agregá un test que falle si tu cambio rompe
   determinismo o evidencia de manipulación — no solo un test del camino
   feliz.
5. Nada de `git rebase`, nada de `git push --force`, nada de aplastar
   historial. Ver `CLAUDE.md` §2 para la disciplina de git completa que
   sigue este repo.

## Agregar un caso a `casos/`

Los casos vienen del propio corpus de VIGÍA (incidentes reales y
públicamente documentados, o el corpus canónico de vectores de
intencionalidad) — ver `casos/README.md` para qué hay y por qué. Un caso
nuevo debería ser salida real de VIGÍA, no contenido inventado; si lo que
estás agregando es un fixture sintético, va en su propio directorio
claramente etiquetado (ver `casos-samuel/` como convención), no mezclado
en `casos/`.

## Reportar un problema de seguridad

Ver `SEGURIDAD.md` — no abras un issue público para una vulnerabilidad.

## Código de conducta

Ver `CODIGO_DE_CONDUCTA.md`.
