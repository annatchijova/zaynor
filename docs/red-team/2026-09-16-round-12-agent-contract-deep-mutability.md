# Red Team — contratos agentic de ZAYNOR
## Ronda 12

**Fecha:** 2026-09-16
**Método:** Abducción → deducción → inducción + red-team auditing
**Alcance:** cambios posteriores a las rondas de Claude sobre CLI, casos JSON,
runner y mentor; contratos de propuesta, observación y sesión.
**Fuera de alcance:** cambios concurrentes de Claude en `adapter.py`, `cli.py`,
`frozen_snapshot.py` y sus tests.

## Amenaza

El atacante puede controlar o influir en un payload devuelto por una herramienta,
un handler MCP, una propuesta del LLM o un objeto mutable pasado por una capa
de integración. No puede modificar el código ni el sello autoritativo base.

## Leyenda epistemológica

`CODE FACT` · `PLAUSIBLE HYPOTHESIS` · `CONFIRMED BY INDUCTION` · `FALSIFIED`

## Incidente

Una `ObservationEnvelope` se declaraba `frozen=True` y exponía un
`payload_sha256`. La sesión también se describía como ledger inmutable.

## Evidencia

Antes del fix, una reproducción mínima mostró:

```text
crear ObservationEnvelope(payload={"nested": {"x": 1}})
mutar observation.payload["nested"]["x"] = 9
payload_sha256 permanece calculado sobre x=1
as_dict() expone x=9
```

La reconstrucción estricta posterior rechazaba el objeto con
`payload_sha256 does not match payload`. Por lo tanto, el objeto vivo podía
estar inconsistente aunque hubiera sido construido originalmente de forma
válida.

## Hipótesis y discriminantes

### H1 — Falsa alarma por copia superficial del input

La mutación sólo podría afectar al diccionario original del caller y no al
objeto almacenado.

**Discriminante:** mutar el input después de construir la observación y luego
leer el payload del objeto.

**Resultado:** `FALSIFIED`. El objeto retenía referencias mutables anidadas.

### H2 — La dataclass frozen protege suficientemente el contrato

`frozen=True` podría impedir toda mutación relevante.

**Discriminante:** mutar un mapping anidado a través de `observation.payload`.

**Resultado:** `FALSIFIED`. `frozen=True` sólo protege la asignación del
atributo, no el contenido de `dict`/`list` anidados.

### H3 — El hash detecta la mutación antes de que se use el payload

El hash almacenado podría invalidar automáticamente el objeto en el momento
de la mutación.

**Discriminante:** observar el objeto inmediatamente después de mutarlo y
comparar payload contra `payload_sha256`.

**Resultado:** `FALSIFIED`. El hash era un string inmutable y no se
recalculaba ni bloqueaba el acceso.

## Veredicto

**RT-12 — Media — CONFIRMED BY INDUCTION — vulnerabilidad de integridad de
estado en contratos agentic.**

La mutabilidad profunda podía romper la correspondencia entre observación y
hash, contaminar una sesión transportada y causar fallos tardíos de
deserialización. No permitía cambiar el resultado autoritativo base, pero
violaba el invariante declarado de observaciones/sesiones inmutables.

## Fractura causal

```text
payload JSON mutable
        ↓
dataclass frozen sólo superficialmente
        ↓
referencia anidada queda expuesta
        ↓
payload cambia después del hash
        ↓
payload_sha256 deja de describir el objeto vivo
        ↓
sesión y transporte dejan de ser autoconsistentes
```

## Remediación aplicada

- Copia recursiva al entrar al contrato.
- Mappings convertidos a `MappingProxyType`.
- Listas/tuplas convertidas a tuplas inmutables.
- Proyección de transporte convertida nuevamente a JSON ordinario.
- Revalidación de hash sobre la representación canónica.
- Regresión que intenta mutar tanto el input original como el objeto
  construido.

## Evidencia posterior al fix

```text
25 pruebas relacionadas: PASS
py_compile: PASS
git diff --check: PASS
```

La regresión confirma que modificar el input original no cambia el contrato y
que modificar el payload interno falla con `TypeError`.

## Vectores descartados

| Vector | Resultado | Motivo |
|---|---|---|
| Mutar el diccionario original después de construir el contrato | Confirmado antes del fix; corregido | Existía aliasing profundo |
| Cambiar un campo de la dataclass con asignación directa | Falsificado | `frozen=True` ya lo bloqueaba |
| Cambiar `payload_sha256` con asignación directa | Falsificado | `frozen=True` ya lo bloqueaba |
| Promover la observación a finding o verdict | Falsificado en esta ronda | El contrato no contiene autoridad epistemológica |

## Pendientes fuera de esta ronda

- Red team de la composición completa con los cambios concurrentes de Claude.
- Integridad y semántica de las cadenas de auditoría.
- Provider real de nuevos bytes y reanálisis posterior.
