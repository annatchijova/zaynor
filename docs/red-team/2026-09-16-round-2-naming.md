# Ronda Red Team 2 — identidad de módulos de ZAYNOR

**Base:** `25f5096` (local, antes de la remediación).  
**Alcance:** nombres de módulos propios de este repositorio y sus imports/tests.
Las referencias a `vigia_agent.py`, `vigia/` y `/home/labestiadevigia/vigia-repo`
son componentes externos de la integración y no se renombran desde ZAYNOR.

## Hallazgo 1 — El código propio expone módulos con identidad del sistema externo

**Severidad:** Media (contrato, mantenibilidad y frontera de autoridad).  
**Nivel:** `CONFIRMED BY INDUCTION` para el incumplimiento de naming; `CODE FACT`
para cada ubicación.

El repositorio ZAYNOR contiene módulos propios llamados:

- `src/zaynor/vigia_mode1_executor.py` (nombre anterior)
- `src/zaynor/vigia_mcp_client.py` (nombre anterior)

y tests con el mismo prefijo. Esto hace que un consumidor pueda importar la
integración como si fuera un módulo nativo de VIGÍA y oculta qué parte es
propiedad de ZAYNOR y qué parte es el engine externo. El contrato pedido es que
los módulos del repo se identifiquen como ZAYNOR; el nombre externo sólo debe
aparecer en el adapter, el proceso invocado y la documentación de integración.

**Predicción:** un inventario de módulos propios de `src/zaynor` no debe
contener nombres de módulo con prefijo `vigia`; todas las referencias internas
deben resolver bajo nombres `zaynor_*`.

**Criterio de cierre:** no hay módulo propio importable con nombre `vigia_*`, y
la suite completa continúa pasando con los imports nuevos. Las referencias al
ejecutable externo `vigia_agent.py` permanecen explícitamente marcadas como
externas.

## Riesgo de la corrección

El rename puede romper consumidores que importen los nombres antiguos. No se
agregan aliases `vigia_*`, porque eso mantendría exactamente la identidad que
este hallazgo exige eliminar. El cambio requiere actualizar todos los tests y
documentos internos en la misma transacción.

## No es un hallazgo

No se considera bug que el executor invoque `vigia_agent.py`, ni que los campos
del bundle externo se llamen `vigia_agent_version`: son nombres del sistema
integrado y conservarlos mantiene la trazabilidad de la frontera. Tampoco se
renombra el checkout externo `vigia-repo`.
