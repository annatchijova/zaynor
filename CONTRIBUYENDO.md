# Contribuir a ZAYNOR

*[Read this in English](CONTRIBUTING.md)*

ZAYNOR acepta contribuciones de código, tests, documentación, casos forenses,
integraciones y validación adversarial.

Antes de cambiar el sistema, entendé una frontera:

> **La IA puede investigar y explicar. Sólo la ruta determinista de evidencia
> puede cambiar el estado forense autoritativo.**

Una contribución no está terminada sólo porque funciona una vez. Debe
preservar los límites de autoridad, provenance, reproducibilidad y
auditabilidad.

## Invariantes arquitectónicos

Los cambios deben preservar estas propiedades salvo que una decisión
arquitectónica explícita cambie el contrato.

### VIGÍA es dueño de la semántica determinista de decisión

ZAYNOR integra el motor VIGÍA vendorizado en `vendor/vigia_engine/`; no
mantiene una reimplementación independiente del scorer de VIGÍA.

No modifiques silenciosamente el comportamiento del scorer vendorizado. Los
cambios de semántica de VIGÍA pertenecen al upstream y requieren una
actualización explícita del contrato de integración de ZAYNOR.

### La IA no tiene autoridad sobre el veredicto

Un LLM o agente puede investigar, derivar, adquirir dentro de su policy o
explicar un resultado verificado. No puede crear ni modificar un finding,
puntaje, veredicto, sello o threshold de decisión autoritativo.

Ningún rol de agente de IA registrado tiene `MUTATE` ni `AUTHORIZE`.

Ver [`AGENTS.md`](AGENTS.md) y
[`src/zaynor/agents/README.md`](src/zaynor/agents/README.md).

### La aritmética autoritativa es reproducible

No introduzcas coma flotante binaria en scoring autoritativo, hashing,
canonicalización ni estado sellado. Las representaciones numéricas exactas y
canónicas, como `Fraction`, `Decimal` y enteros, se usan según el contrato
correspondiente.

### La evidencia son datos no confiables

El contenido de la evidencia nunca debe convertirse en instrucciones ni
capabilities.

Los collectors producen observaciones y provenance. Las salidas de MCP y
tools son inputs no confiables. La evidencia nueva debe volver por la ruta de
análisis determinista antes de poder afectar una conclusión autoritativa.

### La provenance sobrevive a las transformaciones

No descartes silenciosamente la identidad de la fuente, información de
custodia, hashes, relaciones de dependencia, incertidumbre ni la distinción
entre evidencia real y sintética.

## Cómo hacer un cambio

1. **Leé primero la implementación actual.** No infieras el comportamiento
   por el nombre de un archivo, documentación vieja o una versión anterior.
2. **Mantené el cambio enfocado.** Preferí una preocupación coherente por
   commit y explicá por qué hace falta.
3. **Usá Conventional Commits.**

   ```text
   feat(core): add evidence profile
   fix(telemetry): correct OTel span naming
   security(mcp): reject unauthorized capability
   docs(install): document local Ollama setup
   ```

   Los tipos permitidos y su enforcement viven en
   [`scripts/commitlint.py`](scripts/commitlint.py).
4. **Testeá los cambios de comportamiento.** Cubrí el comportamiento
   esperado y los casos negativos, de borde y adversariales relevantes. Las
   correcciones sensibles a seguridad o autoridad deben incluir un test de
   regresión que demuestre el fallo anterior.
5. **Actualizá la documentación contratada junto con el código.** Las
   relaciones entre documentación y código son verificadas por
   `scripts/docs_check.py`. Si un componente nuevo establece un contrato
   documental, actualizá `DOCS_MAP`.
6. **No reescribas el historial compartido.** Force-pushes, rebases del
   historial compartido y squashes silenciosos no forman parte del flujo de
   este repositorio.

## Configuración de desarrollo

```bash
python3 -m venv .venv
source .venv/bin/activate

pip install -e ".[dev]"
pip install pre-commit

./scripts/install-hooks.sh
pre-commit install
```

Antes de proponer un cambio de código:

```bash
python3 -m pytest tests/ -q
ruff check src tools tests scripts conftest.py
git diff --check
```

`black --check` y `mypy` son actualmente consultivos, no gates de merge.
Mantené el estilo circundante y no introduzcas nuevos errores de tipos en el
código que toques.

Los hooks instalados aplican reglas de mensajes de commit, sincronización de
documentación y seguridad del historial. CI repite los gates del repositorio
de forma independiente. Ver [`scripts/`](scripts/) y los workflows de CI para
la implementación actual de esos gates.

## Cambios sensibles a seguridad y autoridad

Los cambios que involucren cualquiera de estos elementos requieren revisión
adicional:

- integración o scoring de VIGÍA;
- `result.json` / `result.seal.json`;
- canonicalización, hashes, HMACs o audit chains;
- freeze o custodia de evidencia;
- límites de filesystem y paths;
- capabilities MCP o permisos de agentes;
- límites de Ollama/modelos;
- hallucination guards o authority guards.

Para estos cambios, incluí un test de regresión que falle cuando se viola la
propiedad de seguridad relevante. Un camino feliz exitoso no alcanza.

Ver [`SEGURIDAD.md`](SEGURIDAD.md) y [`docs/red-team/`](docs/red-team/).

## Agregar casos forenses

Los casos son unidades de evaluación, no ejemplos inventados para que el motor
parezca exitoso.

Cada caso nuevo debe identificar:

- si la evidencia es real o sintética;
- fuente y provenance;
- autorización o licencia cuando corresponda;
- comportamiento esperado;
- categoría del caso;
- información suficiente para reproducir el resultado de ZAYNOR/VIGÍA.

La evidencia real debe provenir de fuentes documentadas y autorizadas. Entre
las fuentes existentes hay datasets y desafíos forenses públicos como Digital
Corpora y DFRWS.

Los fixtures sintéticos son bienvenidos para regresión, adversarial, BREAK,
falsos positivos y falsos negativos, pero deben estar claramente etiquetados y
mantenerse distinguibles de la evidencia forense real.

Ver [`casos/README.md`](casos/README.md).

## Documentación

Si cambiás comportamiento, empezá por el documento más cercano a ese contrato:

- [`README.md`](README.md) — modelo del producto y frontera de autoridad;
- [`INSTALL.md`](INSTALL.md) — instalación y operación;
- [`GUIA_PERITOS.md`](GUIA_PERITOS.md) — flujo forense reproducible;
- [`AGENTS.md`](AGENTS.md) — contratos de integración y agentes;
- [`src/zaynor/agents/README.md`](src/zaynor/agents/README.md) — roles y capabilities;
- [`docs/mcp-locales.md`](docs/mcp-locales.md) — superficie MCP;
- [`docs/demo-lab/README.md`](docs/demo-lab/README.md) — laboratorio DFIR/AIOps;
- [`docs/technical-details.md`](docs/technical-details.md) — detalles de implementación;
- [`SEGURIDAD.md`](SEGURIDAD.md) — límites y reportes de seguridad.

## Releases

ZAYNOR sigue [Semantic Versioning](https://semver.org/) y mantiene
[`CHANGELOG.md`](CHANGELOG.md) con la estructura de Keep a Changelog.

Los cambios incompatibles en interfaces públicas, semántica de evidencia,
formatos de sellos u otros contratos autoritativos persistidos requieren
especial cuidado: la compatibilidad también es comportamiento forense, no
solamente ergonomía de API.

La preparación de releases y el versionado son responsabilidad de las
personas mantenedoras.

## Reportar vulnerabilidades

No reportes vulnerabilidades con detalles de exploits en issues públicas.

Seguí [`SEGURIDAD.md`](SEGURIDAD.md) para reportes y divulgación privada.

## Código de conducta

La participación en el proyecto se rige por
[`CODIGO_DE_CONDUCTA.md`](CODIGO_DE_CONDUCTA.md).
