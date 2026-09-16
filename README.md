# Zaynor

*[Read this in English](./README.en.md)*

> Estado: en desarrollo activo para un hackathon (48 h). Este README es
> provisorio y se va a actualizar a medida que el proyecto tome forma.

Sistema híbrido de defensa: detección y correlación sobre un replay
determinista de telemetría sintética que alimenta una investigación forense
post-incidente asistida por un LLM local, para el desafío "Inteligencia
artificial para la defensa de redes e infraestructura".

## Qué es

Zaynor cubre el incidente de punta a punta, no solo la mitad post-mortem:
un frente liviano y determinista detecta y correlaciona señales sobre un
replay de telemetría sintética (no telemetría en vivo real) hasta que algo
se convierte en un incidente — ahí la evidencia queda congelada (manifest +
SHA-256, case ID inmutable) y arranca la parte profunda: un LLM local que
decide qué evidencia inspeccionar, propone hipótesis y narra la
reconstrucción. El LLM nunca propone un veredicto directamente — propone una
*claim* con predicados verificables ("el evento X tiene el campo Y = Z"), y
una capa determinista vuelve a consultar cada predicado directamente contra
la evidencia congelada antes de sellar cualquier cosa como `CORROBORATED`.
Es la misma filosofía que ANNACONDA (recolección/correlación determinista
primero, LLM narra después, nunca al revés) llevada a un caso post-incidente
en vez de solo en vivo.

El principio arquitectónico central:

> La IA decide qué investigar. La IA no decide qué es verdad.

## Por qué es un híbrido

El proyecto cubre el ciclo completo de un incidente, no solo la mitad
post-incidente:

```
replay determinista de telemetría sintética -> detección -> correlación/triage
   -> INCIDENTE DECLARADO (evidencia congelada: manifest + SHA-256)
   -> recolección de evidencia -> investigación local -> hipótesis/RCA
   -> finding respaldado -> respuesta propuesta (no ejecutada) -> postmortem
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
