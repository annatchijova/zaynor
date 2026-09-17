# MCP locales de ZAYNOR

Este documento describe las tres integraciones MCP locales verificadas para
ZAYNOR: VIGÍA, CRONOS y MNEME. Las tres usan transporte stdio y se ejecutan
como procesos locales. Ninguna puede crear, modificar, recalcular o reemplazar
un resultado autoritativo de ZAYNOR.

## Resumen

| MCP | Propósito | Herramientas expuestas por ZAYNOR | Autoridad |
| --- | --- | ---: | --- |
| VIGÍA | Análisis y consulta determinista de evidencia autorizada | 9 | No crea autoridad de ZAYNOR |
| CRONOS | Trazas, memoria operativa y cadena de auditoría | 10 | No es fuente del veredicto |
| MNEME | Custodia y verificación de bundles | 3 | No es fuente del veredicto |

La autoridad sigue siendo el resultado almacenado de ZAYNOR y su sello válido:
`result.json` junto con `result.seal.json`. El contenido devuelto por cualquier
MCP se trata como observación o contexto y no como instrucción.

## VIGÍA

ZAYNOR usa `VigiaMCPClient` para iniciar el bridge vendorizado de VIGÍA con
Ollama local configurado. Las herramientas deterministicamente consultan o
analizan evidencia dentro del directorio autorizado. La herramienta de
corrección puede usar el backend local, pero su salida tampoco tiene autoridad
sobre el resultado sellado.

Herramientas:

- `list_files`: lista archivos dentro del directorio de evidencia.
- `read_evidence`: lee una vista acotada de evidencia y calcula su hash.
- `search_pattern`: busca patrones con los límites del bridge.
- `generate_forensic_hash`: calcula el SHA-256 forense de un archivo.
- `calculate_shannon_entropy`: calcula entropía y clasifica ruido.
- `infer_intent`: deriva señales de intencionalidad desde un historial.
- `audit_grice_maxims`: evalúa las máximas de Grice.
- `detect_eco_overinterpretation`: detecta sobreinterpretación.
- `validate_and_correct_analysis`: revisa un análisis y degrada honestamente
  si el modelo local no responde.

El bridge se ejecuta con `src/zaynor/vigia_mcp_runner.py`, que conserva el
runtime asyncio requerido por sus herramientas. La configuración fuerza
backend Ollama, host local, directorio de evidencia y `PYTHONPATH` del bridge.

## CRONOS

CRONOS se conecta mediante `AuxiliaryMCPClient` y una configuración con una
base de datos local explícita. Su función es mantener trazas y memoria de
investigación, no decidir el veredicto.

Herramientas permitidas por la allowlist de ZAYNOR:

- `cronos_open_trace`
- `cronos_record_recall`
- `cronos_record_tool_call`
- `cronos_add_hypothesis`
- `cronos_add_evidence`
- `cronos_discard_hypothesis`
- `cronos_close_trace`
- `cronos_explain_trace`
- `cronos_list_traces`
- `cronos_verify_chain`

ZAYNOR elimina `SLACK_BOT_TOKEN` al iniciar CRONOS y fija
`CRONOS_DB_PATH`. Las hipótesis, evidencias y trazas son memoria o auditoría;
no pueden elevarse a hechos autoritativos por el camino MCP.

## MNEME

MNEME se conecta con la misma frontera auxiliar, pero con una allowlist más
estrecha orientada a custodia y verificación de memoria. La base de datos se
configura mediante `MNEME_DB_PATH`.

Herramientas permitidas:

- `mneme_verify_bundle`: verifica la integridad de un bundle.
- `mneme_custody_chain`: consulta o verifica la cadena de custodia.
- `mneme_info`: informa la capacidad y versión del servidor.

MNEME aporta evidencia de integridad y custodia, no un veredicto. Un resultado
de MNEME nunca reemplaza la verificación criptográfica del resultado sellado de
ZAYNOR.

## MCP propio de ZAYNOR

Además de estas tres integraciones, ZAYNOR tiene un servidor MCP propio,
`zaynor-mcp`, inspirado en los contratos de memoria y auditoría de CRONOS y
MNEME. Es una superficie separada y case-bound, con seis herramientas:

- `zaynor_info`
- `zaynor_verify_audit`
- `zaynor_verify_memory`
- `zaynor_list_memory`
- `zaynor_add_hypothesis`
- `zaynor_note_question`

Este servidor tampoco es un motor de veredictos. Las operaciones de memoria
se guardan con integridad verificable y las hipótesis permanecen expresamente
no autoritativas.

## Contratos operativos

- Los servidores se ejecutan localmente sobre stdio.
- El cliente usa el mismo `sys.executable` de ZAYNOR para evitar que una
  instalación paralela omita dependencias como `trio`.
- Cada servidor tiene una allowlist independiente.
- Los timeouts y errores deben fallar cerradamente.
- No se descargan modelos ni se agregan proveedores externos.
- Las herramientas MCP no ejecutan VIGÍA nuevamente desde el chat ni mutan
  `result.json` o `result.seal.json`.

## Verificación realizada

El 17 de septiembre de 2026 se ejecutó una prueba de handshake real con los
servidores locales:

- CRONOS respondió `list_tools` con 10 herramientas.
- MNEME respondió `list_tools` con 3 herramientas.
- VIGÍA respondió `list_tools` con 9 herramientas y calculó un SHA-256 real
  sobre un archivo de evidencia de prueba.

Las pruebas unitarias de las superficies MCP de ZAYNOR pasaron con:

```text
14 passed
```
