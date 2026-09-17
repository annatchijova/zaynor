# Detalle técnico de Zaynor

Este documento concentra los contratos técnicos que no conviene mezclar con
la explicación general del README. El objetivo es que las fórmulas, los
esquemas y los límites de autoridad tengan una referencia estable y revisable.

## Frontera de autoridad

El comando `zaynor analyze` produce el resultado autoritativo y su sello:

- `result.json`: resultado canónico del motor determinista;
- `result.seal.json`: sello criptográfico del resultado;
- `zaynor audit`: verifica la correspondencia entre ambos y los artefactos del
  caso.

El chat y la API deben cargar y verificar ambos archivos antes de invocar a
Ollama. Ninguna salida del modelo puede escribir, recalcular, modificar o
reemplazar el veredicto. La narración se valida contra el resultado verificado
y se degrada de forma segura si contiene una afirmación autoritativa que no
está respaldada.

## Flujo de datos

```text
case evidence
  -> frozen snapshot and manifest
  -> deterministic VIGÍA scorer
  -> canonical authoritative result
  -> cryptographic seal
  -> verified chat context
  -> local Ollama narration
  -> hallucination guard
```

Los MCP, el contexto de frameworks y la memoria de investigación son
superficies auxiliares. Pueden aportar observaciones y trazas, pero no tienen
autoridad para cambiar el resultado sellado.

## Aritmética exacta

El camino del scorer debe conservar aritmética exacta con `fractions.Fraction`.
Los valores de entrada se normalizan en los límites del motor y no deben
convertirse a `float` durante la composición del score, la aplicación de
umbrales o la producción de confianza. La serialización pública debe seguir el
esquema autoritativo existente.

Las fórmulas exactas del scorer, sus constantes, umbrales y ejemplos
reproducibles se incorporarán aquí a partir de la especificación canónica que
entregue el equipo. Hasta entonces, este documento no redefine ni sustituye
el contrato implementado por VIGÍA.

## Roles y seguridad

Los roles tienen capabilities explícitas y tool allowlists independientes.
MENTOR narra resultados sellados; INVESTIGATOR consulta evidencia mediante
operaciones acotadas; FLEET_COMMANDER mantiene hipótesis y tareas;
DETECTION_ENGINEER prepara reglas candidatas; DISPATCHER expone catálogos; y
CONSULT contextualiza el resultado. Los roles fuera de alcance no implican
recolección en vivo.

Toda entrada proveniente de evidencia, memoria, tickets o respuestas de un LLM
se trata como datos no confiables. Path traversal, symlink escapes, cambios
TOCTOU, herramientas no autorizadas y escrituras fuera de contrato deben
fallar cerradamente.

## Referencias de implementación

- [`src/zaynor/agents/README.md`](../src/zaynor/agents/README.md): estado real
  de wiring de agentes.
- [`docs/mcp-locales.md`](./mcp-locales.md): MCP, herramientas y allowlists.
- [`AGENTS.md`](../AGENTS.md): contratos de integración y autoridad.
- [`docs/implementation-plan.en.md`](./implementation-plan.en.md): matriz de
  capacidades y límites de integración.
