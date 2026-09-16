# Zaynor

*[Read this in English](./README.en.md)*

> Estado: en desarrollo activo para un hackathon (48 h). Este README es
> provisorio y se va a actualizar a medida que el proyecto tome forma.

Sistema híbrido de defensa para investigar incidentes ya declarados: toma
evidencia congelada, construye y contrasta hipótesis con un motor matemático
determinista, y usa IA local para decidir nuevas investigaciones y producir
reportes para distintos públicos, para el desafío "Inteligencia artificial
para la defensa de redes e infraestructura".

## Qué es

Zaynor empieza cuando ocurre un incidente y ya hay evidencia recolectada; la
declaración del incidente y la adquisición quedan fuera de este repo. Sobre
la evidencia congelada, el investigador mantiene hipótesis y preguntas usando
la tríada de Peirce: abducción para proponer explicaciones, deducción para
derivar qué las distinguiría e inducción para contrastarlas con evidencia.
Las evidencias discriminantes y las fracturas alimentan el motor matemático
determinista, que calcula score y nivel de confianza y asigna el veredicto
VIGÍA: `MALICE`, `ABSTAIN`, `UNKNOWN`, `BENIGN` o `SUSPICION`. El veredicto no
lo decide el LLM.

Después de ese paso autoritativo, la IA puede decidir qué investigar a
continuación —en un loop acotado, parecido al de ANNACONDA— usando únicamente
operaciones de lectura permitidas. La evidencia nueva vuelve a pasar por el
motor determinista antes de modificar el resultado. El LLM también narra el
resultado sellado: copia el formato de reportes de Forge tal cual —Markdown,
PDF y HTML— y ofrece un chat con LLM para analistas junior; la vista y el flujo de investigación para
analistas senior conservan hipótesis, fracturas, score, confianza,
alternativas y trazabilidad.

El principio arquitectónico central:

> La IA puede decidir qué investigar. El motor matemático determinista decide
> qué sostiene la evidencia.

## Por qué es un híbrido

El proyecto cubre el flujo post-incidente:

```
INCIDENTE DECLARADO + EVIDENCIA RECOLECTADA (externos a Zaynor)
   -> evidencia congelada (manifest + SHA-256, case_id inmutable)
   -> hipótesis Peirce: abducción -> deducción -> inducción
   -> evidencia discriminante / fracturas
   -> motor matemático determinista VIGÍA
   -> MALICE | ABSTAIN | UNKNOWN | BENIGN | SUSPICION + score/confianza
   -> hash chain + resultado autoritativo sellado
   -> IA decide investigación adicional acotada (opcional, read-only)
   -> nueva evidencia -> VIGÍA / reanálisis determinista
   -> reporte Forge (.md/.pdf/.html) + chat local para analistas
```

La separación es intencional: el motor determinista sostiene los veredictos,
los scores, la confianza, las fracturas, la trazabilidad y el hash chain; la
IA propone próximos pasos de investigación y traduce resultados ya sellados
para humanos. Una propuesta del LLM nunca cambia por sí sola el veredicto.

## Requisitos

- Todo corre localmente. Ningún dato sale de la máquina.
- Inferencia vía un modelo local (Ollama u otro backend equivalente),
  corriendo en hardware de desarrollador común — no se asume infraestructura
  de clase servidor.
- Solo datos simulados o públicos.
- Interfaces previstas: CLI, frontend local, API y chat con Ollama; MCP puede
  exponer herramientas de investigación read-only.

## Referencias de diseño

Ningún proyecto externo se reutiliza como dependencia — Zaynor es un
prototipo chico y propio. Estas son las ideas concretas que sí se tomaron de
otros proyectos, para que se entienda de dónde vienen:

- **VIGÍA** — motor forense matemático determinista, score, confianza,
  veredictos cuadripartitos y sellado del resultado antes de que cualquier
  LLM lo vea; también aporta el modelo de sandbox read-only.
- **ANNACONDA** — el patrón de guardia contra alucinaciones: la narrativa
  del LLM solo puede citar hechos ya autorizados por el motor determinista,
  nunca inventar uno nuevo, y el loop acotado para decidir qué investigar.
- **Forge** — formato de reporte para analistas copiado tal cual: Markdown,
  PDF y HTML, más la separación entre el flujo explicativo junior y el
  análisis profundo senior.
- **K8sGPT** — separar el hallazgo determinista de su explicación por IA en
  campos distintos, de forma que el LLM nunca pueda escribir sobre el
  veredicto, solo sobre el texto que lo acompaña.
- **HolmesGPT** — el loop de investigación acotado (límite de pasos, no
  autonomía ilimitada) y un registro declarativo de herramientas.
- **Keep** — la idea de separar identidad de evento, fingerprint de alerta
  e identidad de incidente en vez de una sola noción de "hash".

## Estructura del repositorio

Los contratos de trabajo están en `AGENTS.md`, `docs/SANDBOX.md` y
`SYSTEM_PROMPT--ZAYNOR.md`. El límite del worker en `src/zaynor/sandbox.py`
mantiene la inspección de evidencia acotada; no parsea ni ejecuta contenido de
artefactos dentro del proceso API.

El catálogo de skills está en `docs/skills/` y está acotado al pipeline local de
DFIR y detección de este proyecto.

## Licencia

Apache License 2.0 — ver [`LICENSE`](./LICENSE).
