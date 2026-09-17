# Contribuyendo a ZAYNOR

*[Read this in English](CONTRIBUTING.md)*

Gracias por querer trabajar en ZAYNOR. ZAYNOR crece desde VIGÍA como un
sistema forense grande y útil, con un compromiso de mantenimiento a largo
plazo. Las contribuciones deben ayudar a preservar esa utilidad a medida que
el proyecto evoluciona.

## Antes de empezar

- ZAYNOR integra el motor determinista de VIGÍA (`vendor/vigia_engine/`)
  en vez de reimplementarlo — ver `AGENTS.md` §2.1. Si tu cambio toca algo
  bajo `vendor/`, necesita una razón documentada; la suposición por
  defecto es que la lógica propia de VIGÍA no es tuya para reescribir.
- No toques el scorer ni su contrato de decisión. Los cambios al scorer
  requieren una decisión arquitectónica documentada y aprobada explícitamente.
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
3. Proponé tests con cada cambio. Deben cubrir el comportamiento esperado,
   límites, casos negativos y casos adversariales relevantes. Una pull request
   sin propuesta de tests está incompleta.
4. Corré la suite completa antes de proponer un cambio:
   ```bash
   python3 -m pytest tests/ -q
   ```
5. Si tocás `src/zaynor/report.py`, `audit_log.py`, o cualquier cosa
   sellada/hasheada, agregá un test que falle si tu cambio rompe
   determinismo o evidencia de manipulación — no solo un test del camino
   feliz.
6. Nada de `git rebase`, nada de `git push --force`, nada de aplastar
   historial. Ver `CLAUDE.md` §2 para la disciplina de git completa que
   sigue este repo.

## Agregar casos y cobertura adversarial

Los casos deben estar documentados y ser trazables. El corpus debe incluir
casos adversariales, break, benignos, falsos positivos (FP) y falsos negativos
(FN), no solamente detecciones exitosas. Incluí fuentes autorizadas y
documentadas como NIST, Digital Corpora, DFRWS, DEF CON DFIR CTF y otros
repositorios o datasets expresamente autorizados.

Un caso nuevo debe ser salida reproducible de VIGÍA/ZAYNOR, no evidencia
inventada. Los fixtures sintéticos sirven para tests, pero deben estar
claramente etiquetados y separados de los casos reales. Documentá la fuente,
la autorización, el comportamiento esperado y la categoría del caso.

## Reportar un problema de seguridad

Para vulnerabilidades de seguridad, escribí a `anna.tchijova@icloud.com`; no
abras un issue público ni dependas de un flujo público de security advisories.

## Código de conducta

Ver `CODIGO_DE_CONDUCTA.md`.
