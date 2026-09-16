# Zaynor

*[Read this in English](./README.en.md)*

> Estado: en desarrollo activo para un hackathon (48 h). Este README es
> provisorio y se va a actualizar a medida que el proyecto tome forma.

Investigador forense post-incidente asistido por un LLM local, para el
desafío "Inteligencia artificial para la defensa de redes e infraestructura".

## Qué es

Zaynor reconstruye un incidente de seguridad simulado a partir de evidencia
heterogénea (logs, eventos de autenticación, procesos, red, metadatos de
archivos). Un LLM que corre localmente decide qué evidencia inspeccionar,
propone y descarta hipótesis, y narra la reconstrucción — pero **nunca
decide por sí solo qué es un hallazgo confirmado**. Esa autoridad la tiene
una capa determinista que exige corroboración por al menos dos fuentes
independientes antes de sellar cualquier cosa como `CORROBORATED`.

El principio arquitectónico central:

> La IA decide qué investigar. La IA no decide qué es verdad.

## Por qué es un híbrido

El proyecto cubre el ciclo completo de un incidente, no solo la mitad
post-incidente:

```
telemetría (sintética) -> detección -> correlación/triage -> INCIDENTE
   -> recolección de evidencia -> investigación local -> hipótesis/RCA
   -> finding respaldado -> respuesta/prevención -> postmortem
```

Las primeras tres etapas se resuelven con un motor chico y determinista
(stream sintético, una regla de detección, una regla de correlación) — nada
de eBPF, agentes por nodo, ni un stack de monitoreo de producción. El peso
real del proyecto, y donde vive la IA sustantiva, está a partir del
incidente: ahí es donde el LLM local investiga y donde el ledger determinista
tiene la última palabra.

## Requisitos

- Todo corre localmente. Ningún dato sale de la máquina.
- Inferencia vía un modelo local (Ollama u otro backend equivalente),
  corriendo en hardware de desarrollador común — no se asume infraestructura
  de clase servidor.
- Solo datos simulados o públicos.

## Estructura del repositorio

En construcción — ver `AGENTS.md` para el contrato de trabajo (flujo de
git/PR, el límite determinista/LLM, disciplina de edición) mientras el código
todavía no existe.

## Licencia

Apache License 2.0 — ver [`LICENSE`](./LICENSE).
