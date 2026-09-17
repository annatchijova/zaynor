# Draft de red team — invariantes generales de ZAYNOR

## Estado del documento

**Fecha:** 2026-09-17  
**Estado:** DRAFT — no representa una aprobación del worktree actual  
**Base:** `main @ a0a7009`, con cambios adicionales sin commit en el worktree  
**Método:** red-team adversarial + cacería de invariantes  
**Alcance:** API, Ollama, OpenWebUI, dependencias y MCP

Este documento distingue lo que ya existía en ZAYNOR de lo que pertenece al
trabajo sin commit de Claude. Los cambios sin commit no se consideran parte de
la API aprobada hasta que tengan tests, revisión y commit propio.

## Threat model

- El atacante puede enviar requests a la API si el operador la expone fuera de
  localhost.
- El atacante puede controlar preguntas, mensajes y contenido de propuestas de
  investigación.
- Un proceso MCP local puede bloquearse, devolver un catálogo inesperado o
  devolver datos hostiles.
- Un servicio Ollama local puede estar caído, defectuoso o comprometido.
- El atacante no puede modificar el código, el kernel ni el resultado sellado
  desde el modelo.
- La firma o sello no certifica que el veredicto original sea verdadero; sólo
  certifica la integridad de los bytes sellados.

## Leyenda epistemológica

`CODE FACT` = observable directamente en el código.  
`PLAUSIBLE HYPOTHESIS` = mecanismo plausible todavía no demostrado mediante
inducción.  
`CONFIRMED BY INDUCTION` = predicción ejecutada y observada.  
`FALSIFIED` = el experimento no produjo el efecto predicho.

## Resumen ejecutivo

| ID | Severidad | Nivel | Dependencia | Hallazgo |
| --- | --- | --- | --- | --- |
| R21-01 | Alta condicional | CODE FACT | Preexistente | API sin autenticación si se escucha fuera de localhost |
| R21-02 | Media | CONFIRMED BY INDUCTION | Preexistente | `VigiaMCPClient` puede quedar esperando sin deadline propio |
| R21-03 | Media | CODE FACT | Claude, sin commit | Estado de investigación persistido sin escritura atómica ni sello propio |
| R21-04 | Media | PLAUSIBLE HYPOTHESIS | Claude, sin commit | Tool real ejecutado antes de persistencia durable |
| R21-05 | Media | CODE FACT | Preexistente | Ollama carga respuestas sin límite de bytes |
| R21-06 | Baja/Media | CODE FACT | Preexistente | Dependencias Python sin lockfile reproducible |
| R21-07 | Media condicional | CODE FACT | Preexistente | Cliente VIGÍA no impone allowlist propia |

## Hallazgos

### R21-01 — Exposición del backend sin autenticación

**Nivel:** CODE FACT  
**Bucket:** vulnerabilidad condicional / threat-model dependent  
**Dependencia:** preexistente

`zaynor serve` escucha en `127.0.0.1` por defecto, pero acepta
`--host 0.0.0.0`. La API no valida API keys ni headers de autorización. Bajo el
threat model en que el operador expone el servidor en una interfaz accesible,
un cliente puede consultar casos, resultados, auditoría, evidencia y usar el
chat local.

**Invariante:**

```text
servidor expuesto fuera de localhost => existe autenticación efectiva
```

La primera parte es opcional en la configuración; la segunda no existe. El
default local reduce la exposición, pero no protege una ejecución explícita con
host no-loopback.

**Recomendación:** antes de soportar despliegue no-local, agregar autenticación
explícita o rechazar hosts no-loopback. Requiere decisión de producto; no se
arregla con CORS.

### R21-02 — Espera indefinida en el cliente MCP de VIGÍA

**Nivel:** CONFIRMED BY INDUCTION  
**Bucket:** vulnerabilidad de disponibilidad  
**Dependencia:** preexistente

`src/zaynor/zaynor_mcp_client.py` espera directamente en `initialize`,
`list_tools` y `call_tool`. La prueba real del bridge vendorizado quedó
bloqueada durante más de 20 segundos en inicialización cuando el transporte no
respondió.

**Invariante:**

```text
MCP local no responde => ZAYNOR recupera control dentro de un deadline
```

La configuración auxiliar de CRONOS/MNEME sí tiene timeout, pero el cliente
VIGÍA no comparte todavía ese control.

**Recomendación:** agregar timeout configurable también a VIGÍA, cerrar el
subproceso al vencer y devolver un error seguro. El bridge no debe cambiar de
backend asyncio sólo para ocultar este problema.

### R21-03 — Ledger de investigación sin escritura atómica ni integridad propia

**Nivel:** CODE FACT  
**Bucket:** brecha de integridad arquitectónica  
**Dependencia:** cambios sin commit de Claude

La nueva implementación en `src/zaynor/api.py` guarda el estado mediante
`Path.write_text()` directo en `_save_investigation_state()`. El objeto
`InvestigationSession` valida la forma y los hashes de payload, pero el archivo
envolvente que asocia la sesión con timestamps no tiene una cadena o digest
propio.

**Invariante:**

```text
observación ejecutada => ledger persistido completo, durable y verificable
```

Un crash durante la escritura puede dejar JSON truncado. La carga posterior
captura el error y vuelve silenciosamente a una sesión nueva, lo que convierte
la pérdida de memoria en un estado aparentemente limpio.

**Recomendación:** usar escritura temporal + `fsync` + `os.replace`, verificar
el wrapper completo y distinguir `CORRUPTED` de `NOT_STARTED`; no resetear un
ledger corrupto silenciosamente.

### R21-04 — Efecto MCP antes de persistencia durable

**Nivel:** PLAUSIBLE HYPOTHESIS  
**Bucket:** composición / atomicidad  
**Dependencia:** cambios sin commit de Claude

La ruta de propuestas ejecuta `investigator.propose_and_execute()`, que puede
llamar al tool real, y recién después escribe `investigation.json`.

**Invariante:**

```text
tool observado y auditado => observación recuperable en el ledger
```

Si la llamada al MCP termina correctamente y la escritura local falla, el
efecto real queda en la auditoría del bridge pero el estado de investigación de
ZAYNOR no registra la observación. El efecto actual es determinista y de
lectura, por lo que esto no altera por sí solo el veredicto; sí rompe la
reconstrucción del turno.

**Inducción pendiente:** inyectar fallo entre el retorno del handler y
`_save_investigation_state`, y comprobar si el siguiente GET puede distinguir
`lost-after-tool` de `NOT_STARTED`.

### R21-05 — Respuesta de Ollama sin límite de tamaño

**Nivel:** CODE FACT  
**Bucket:** resource exhaustion  
**Dependencia:** preexistente

`OllamaClient.generate()` usa `response.read()` completo y
`list_available_models()` hace lo mismo con `/api/tags`. No hay límite de bytes
antes de parsear JSON.

**Invariante:**

```text
respuesta local defectuosa => memoria y tiempo del proceso permanecen acotados
```

El impacto requiere controlar o comprometer el servicio local, por lo que no
se etiqueta como explotación remota de Ollama. Sigue siendo un límite de
robustez necesario para un backend que falla cerrado.

### R21-06 — Resolución no reproducible de dependencias

**Nivel:** CODE FACT  
**Bucket:** supply-chain hygiene  
**Dependencia:** preexistente

`pyproject.toml` declara rangos para `mcp`, `trio` y dependencias opcionales,
pero el repositorio no contiene lockfile Python ni instalación con hashes.
`pyproject.toml` expresa una solicitud; no prueba qué árbol transitorio se
ejecutará en CI, notebook o despliegue.

**Recomendación:** adoptar un lockfile y un modo de instalación bloqueado. La
auditoría debe distinguir manifest, lockfile, instalado y artefacto enviado.

### R21-07 — Allowlist incompleta en el cliente VIGÍA

**Nivel:** CODE FACT   
**Bucket:** trust-boundary dependent  
**Dependencia:** preexistente

`VigiaMCPClient.call_tool()` acepta el nombre que reciba y no verifica una
allowlist propia. Hoy `InvestigatorToolAdapter` y `authorize_tool()` acotan el
camino usado por el agente, pero otro consumidor que use directamente el
cliente puede invocar cualquier tool publicada por el bridge configurado.

**Recomendación:** declarar la allowlist en la configuración del cliente o
separar explícitamente el cliente general del adapter autorizado. La severidad
depende de quién pueda construir y llamar el cliente.

## Invariantes comprobados

- El request OpenAI no puede seleccionar un `model` arbitrario.
- `stream=true` se rechaza; no se simula streaming.
- La respuesta expone `zaynor-forensic` y no el modelo interno de Ollama.
- Ollama sólo acepta hosts loopback.
- El chat verifica el sello antes de invocar Ollama.
- `/cases` informa `NOT_CHECKED` y no infiere `VERIFIED` por presencia de
  archivos.
- CRONOS y MNEME tienen allowlists separadas.
- Las tres pruebas de handshake MCP reales pasaron en un entorno con Trio:
  CRONOS 10 tools, MNEME 3 tools y VIGÍA 9 tools.

## Vectores descartados

| Vector | Resultado | Evidencia |
| --- | --- | --- |
| `stream=true` usado para obtener respuesta falsa | FALSIFIED | API devuelve rechazo estructurado |
| `req.model` distinto ejecutado silenciosamente | FALSIFIED | API rechaza `unsupported_model` |
| Presencia de `result.json` presentada como verificación | FALSIFIED | `/cases` devuelve `NOT_CHECKED` |
| CRONOS con side effect Slack desde ZAYNOR | FALSIFIED | el cliente elimina `SLACK_BOT_TOKEN` |
| MCP auxiliar puede modificar directamente el resultado sellado | FALSIFIED | no existe write path al resultado/seal |

## Tests y comandos ejecutados

```text
env PYTHONPATH=src pytest -q tests/test_ollama_client_transport.py \
  tests/test_authority_seal.py tests/test_hallucination_guard.py \
  tests/test_auxiliary_mcp_client.py tests/test_zaynor_mcp_config_security.py \
  tests/test_zaynor_mcp_server.py
14 passed
```

Pruebas reales de MCP, ejecutadas con un entorno temporal que contiene las
dependencias declaradas:

```text
CRONOS READY — 10 tools
MNEME READY — 3 tools
VIGÍA READY — 9 tools; generate_forensic_hash devolvió un SHA-256 real
```

La suite API completa no se pudo declarar verde: el test HTTP con
`TestClient` queda bloqueado en el worktree actual. Ese worktree contiene
cambios sin commit de Claude y debe volver a auditarse después de que termine
esa modificación.

## Próximo orden de trabajo

1. Claude debe terminar y commitear la ruta de investigación.
2. Red team de persistencia atómica, concurrencia y corrupción de ledger.
3. Añadir deadline al cliente VIGÍA.
4. Acotar respuestas de Ollama.
5. Decidir autenticación para cualquier bind no-loopback.
6. Añadir lockfile y revisar el árbol transitorio instalado.
