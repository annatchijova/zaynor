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
la evidencia congelada y verifica los requisitos de procedencia e
independencia definidos por la regla antes de promover la claim a
`CORROBORATED`. El modelo puede investigar y proponer; la autoridad sobre
los findings permanece fuera del LLM y se deriva de reglas explícitas
aplicadas a evidencia congelada (ver "Referencias de diseño" más abajo para
qué se tomó de qué proyecto).

El principio arquitectónico central:

> La IA decide qué investigar. La IA no decide qué es verdad.

## Por qué es un híbrido

El proyecto cubre el ciclo completo de un incidente, no solo la mitad
post-incidente:

```
replay determinista de telemetría sintética -> detección -> correlación/triage
   -> INCIDENTE DECLARADO (evidencia congelada: manifest + SHA-256)
   -> acceso a evidencia congelada (pre-recolectada; adquisición fuera de alcance)
   -> investigación local -> hipótesis/RCA
   -> finding respaldado -> respuesta propuesta (no ejecutada) -> postmortem
```

Las primeras tres etapas se resuelven con un motor chico y determinista
(stream sintético, una regla de detección, una regla de correlación) — nada
de eBPF, agentes por nodo, ni un stack de monitoreo de producción. El peso
real del proyecto, y donde vive la IA sustantiva, está a partir del
incidente: ahí es donde el LLM local investiga, el gate determinista
controla qué claims pueden adquirir estado autoritativo, y el ledger
conserva los findings resultantes de forma auditable.

## Requisitos

- Todo corre localmente. Ningún dato sale de la máquina.
- Inferencia vía un modelo local (Ollama u otro backend equivalente),
  corriendo en hardware de desarrollador común — no se asume infraestructura
  de clase servidor.
- Solo datos simulados o públicos.

## Referencias de diseño

Ningún proyecto externo se reutiliza como dependencia — Zaynor es un
prototipo chico y propio. Estas son las ideas concretas que sí se tomaron de
otros proyectos, para que se entienda de dónde vienen:

- **VIGÍA** — sandbox de solo lectura sobre evidencia (hash antes de leer,
  confinamiento de paths), y el principio de sellar un resultado
  determinista antes de que cualquier LLM lo vea.
- **ANNACONDA** — el patrón de guardia contra alucinaciones: la narrativa
  del LLM solo puede citar hechos ya autorizados por el motor determinista,
  nunca inventar uno nuevo.
- **K8sGPT** — separar el hallazgo determinista de su explicación por IA en
  campos distintos, de forma que el LLM nunca pueda escribir sobre el
  veredicto, solo sobre el texto que lo acompaña.
- **HolmesGPT** — el loop de investigación acotado (límite de pasos, no
  autonomía ilimitada) y un registro declarativo de herramientas.
- **Keep** — la idea de separar identidad de evento, fingerprint de alerta
  e identidad de incidente en vez de una sola noción de "hash".

## Estructura del repositorio

Los contratos de trabajo están en `AGENTS.md`, `docs/SANDBOX.md` y
`SYSTEM_PROMPT--ZAYNOR.md`. El primer slice implementado es el límite del
worker en `zaynor/sandbox.py`; no parsea ni ejecuta contenido de artefactos.

El catálogo de skills está en `docs/skills/` y está acotado al pipeline local de
DFIR y detección de este proyecto.

## Licencia

Apache License 2.0 — ver [`LICENSE`](./LICENSE).
