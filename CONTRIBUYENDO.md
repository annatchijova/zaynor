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
3. Escribí los commits en formato [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):
   `<tipo>[alcance opcional][!]: <descripción en imperativo>` — con alguno
   de `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `perf`,
   `ci`, `build`, `security`, `revert` (la lista completa la aplica
   `scripts/commitlint.py` — `ALLOWED_TYPES` es la fuente de verdad). Ejemplos:
   `feat(core): add new evidence profile`,
   `fix(telemetry): correct OTel span naming`.
   El hook `commit-msg` (`scripts/commitlint.py`, instalado con
   `./scripts/install-hooks.sh`) rechaza los encabezados que no conforman;
   los pocos encabezados previos a la regla que deja pasar están listados
   en `.commitlint-allowlist`. Los encabezados `Merge ...` / `Revert ...`
   pasan sin cambios.
4. Proponé tests con cada cambio. Deben cubrir el comportamiento esperado,
   límites, casos negativos y casos adversariales relevantes. Una pull request
   sin propuesta de tests está incompleta.
5. Mantené la documentación sincronizada con el código. Cambiar un archivo
   que un documento contrata (la CLI, la API, los agentes, el adaptador de
   VIGÍA, el sello, las herramientas MCP, el frontend, las herramientas de
   SDLC) exige actualizar ese documento en el mismo cambio. Qué partes del
   código contratan qué docs está en `DOCS_MAP` de `scripts/docs_check.py`
   — la fuente de verdad; ampliala cuando agregues una parte que tenga
   contrato documental. La aplicación es mecánica:
   - el hook `pre-push` corre `scripts/docs_check.py` sobre el rango
     empujado (instalado con `./scripts/install-hooks.sh`);
   - CI corre la misma compuerta en cada PR y en cada push directo a
     `main` (job `docs-sync`).
   Una regla se puede eximir de forma deliberada con el trailer de commit
   en el párrafo final del mensaje — `Docs-Waiver: <rule-id> <razón>` —
   por regla, visible en el historial, nunca silenciosa. Solo cuenta un
   trailer en posición de trailer: una línea ilustrativa `Docs-Waiver:`
   dentro del cuerpo o de un bloque de código no es una exención. Corré
   la compuerta localmente cuando quieras:
   ```bash
   python3 scripts/docs_check.py --base origin/main   # diff de la rama vs main
   python3 scripts/docs_check.py --staged             # lo que hay staged
   ```
6. Configurá las compuertas locales una vez por clon:
   ```bash
   pip install -e ".[dev]" && pip install pre-commit
   ./scripts/install-hooks.sh   # commit-msg (commitlint) + pre-push (bloqueo de force-push + docs-sync)
   pre-commit install           # higiene de espacios/EOF/YAML/TOML/JSON
   ```
   Si clonaste antes de que aterrizara una actualización de hooks, corré
   `./scripts/install-hooks.sh --force` para tomarla (si no, sigue el hook
   viejo y solo la compuerta de CI aplica el chequeo nuevo).
   Y corré la suite de verificación antes de proponer un cambio:
   ```bash
   python3 -m pytest tests/ -q
   ruff check src tools tests scripts conftest.py
   ```
   `black --check src tests scripts conftest.py` y `mypy src/zaynor/` son
   consultivos (el árbol es anterior al formateo; 20 notas preexistentes de
   mypy están registradas en `pyproject.toml [tool.mypy]`). Mantené el
   estilo circundante en los archivos que toques y corregí las notas nuevas
   de mypy ahí, pero ninguno de los dos bloquea una fusión.
7. Si tocás `src/zaynor/report.py`, `audit_log.py`, o cualquier cosa
   sellada/hasheada, agregá un test que falle si tu cambio rompe
   determinismo o evidencia de manipulación — no solo un test del camino
   feliz.
8. Nada de `git rebase`, nada de `git push --force`, nada de aplastar
   historial. Ver `CLAUDE.md` §2 para la disciplina de git completa que
   sigue este repo. (El hook `pre-push` aplica el veto al force-push de
   forma mecánica.)

## Releases (SemVer + Keep a Changelog)

- El versionado sigue [SemVer](https://semver.org/spec/v2.0.0.html):
  `MAJOR` rompe la interfaz pública o la semántica de evidencia (superficie
  del CLI, contrato del resultado sellado, formato de manifest/sello);
  `MINOR` agrega funcionalidad compatible (comandos, roles, perfiles de
  evidencia, anotaciones de frameworks); `PATCH` corrige bugs o docs.
- Cada cambio visible para el usuario suma una entrada bajo
  `CHANGELOG.md` `## [Unreleased]`, agrupada en `Added` / `Changed` /
  `Fixed` / `Security` / `Removed`, según [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
- La persona mantenedora corta un release moviendo las entradas de
  `Unreleased` bajo un encabezado `## [x.y.z] - YYYY-MM-DD`, subiendo
  `version` en `pyproject.toml` y etiquetando `vX.Y.Z`.

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
