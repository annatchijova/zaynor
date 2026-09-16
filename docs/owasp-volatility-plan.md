# Plan de integración: OWASP y Volatility en ZAYNOR

## Objetivo

Agregar contexto de seguridad de aplicaciones y análisis de memoria sin crear
un segundo motor de veredictos. ZAYNOR seguirá teniendo una sola autoridad
forense determinista; OWASP y Volatility aportarán contexto, observaciones o
artefactos derivados.

```text
evidencia congelada
        ↓
herramienta DFIR (Volatility u otra)
        ↓
observación/artefacto derivado con provenance
        ↓
freeze del nuevo material
        ↓
motor determinista autoritativo
        ↓
resultado sellado
        ↓
OWASP / MITRE / NIST / D3FEND como contexto
```

## OWASP

OWASP no decide si un incidente es `MALICE`, `SUSPICION`, `BENIGN`, `ABSTAIN`
o `UNKNOWN`. Se incorpora como una capa de contextualización y como fuente de
requisitos verificables para el backend, la API y el frontend.

### Orden de implementación

1. **OWASP API Security Top 10:** mapear riesgos de autenticación,
   autorización, consumo de recursos, inventario y exposición de datos de la
   API de ZAYNOR.
2. **OWASP ASVS:** convertir controles aplicables en una checklist versionada
   para la API y el frontend.
3. **OWASP Top 10:** usarlo como vocabulario sencillo para la demo y para la
   explicación al analista junior.

Cada mapping debe conservar:

```text
framework = OWASP
version
category
mapping_status = candidate | supported | not_applicable | unknown
justification
evidence_refs
```

Un mapping no puede modificar un finding, promover un veredicto ni completar
un `UNKNOWN`. Si no hay evidencia suficiente, el estado del mapping también
debe permanecer explícitamente incierto.

### Controles mínimos para la API

- autenticación y autorización por recurso, no sólo por endpoint;
- allowlist de herramientas y capacidades antes de invocar MCP;
- límites de tamaño, tiempo, pasos y memoria para entradas y respuestas;
- validación estricta de JSON y rechazo de campos autoritativos generados por
  el LLM;
- protección contra path traversal, TOCTOU y symlinks en evidencia;
- no exposición de secretos, prompts internos, rutas locales o contenido de
  otros casos;
- logs con provenance, hash de argumentos y resultado de la policy;
- degradación visible ante Ollama, MCP o proveedor DFIR no disponible.

## Volatility

Volatility es una herramienta de análisis de memoria. Su salida es una
observación o un artefacto derivado, nunca un veredicto. La UI debe decir:

> Volatility observó este proceso, módulo o conexión en la imagen de memoria.

No debe decir:

> Volatility determinó que hubo malware.

### Contrato de un artefacto derivado

```text
artifact_id
case_id
source_artifact_ref
tool = volatility
tool_version
plugin
arguments_digest
input_sha256
output_sha256
content
provenance
lineage_id
```

El contenido de Volatility entra como `UNTRUSTED` y con
`instruction_authority = NONE`. Puede contener texto que intente manipular al
LLM; ese texto se conserva como dato y no como instrucción.

### Orden de adquisición

1. Identificar y congelar la imagen original.
2. Calcular y registrar su hash antes de analizarla.
3. Ejecutar el plugin permitido en un entorno aislado y con límites.
4. Registrar versión, plugin, argumentos, input hash, output hash y errores.
5. Congelar el resultado derivado como nueva evidencia vinculada al artefacto
   original.
6. Reanalizar con el motor determinista sólo cuando exista un provider real de
   nuevos bytes/artefactos y la policy lo permita.

La primera integración puede quedarse honestamente en:

```text
resultado sellado
    → Ollama propone una pregunta
    → policy autoriza READ/DERIVE
    → Volatility produce observación
    → sesión registra observación
    → sin cambio autoritativo todavía
```

No se debe simular `collect_window`, inventar una recolección ni convertir la
salida de un plugin directamente en un finding.

## Compatibilidad de casos

Los casos autocontenidos ricos con `artifacts[]`, `type`, `source`, `content`,
`metadata` y `expected_verdict` requieren un adaptador específico. No deben
tratarse como un `telemetry.jsonl` de ZAYNOR ni envolverse ciegamente en una
carpeta genérica.

La compatibilidad pendiente se implementará así:

```text
caso autocontenido
    → validación de schema y case_id
    → materialización controlada de artifacts
    → manifest + hashes + lineage
    → snapshot congelado
    → motor determinista
    → resultado ZAYNOR sellado
```

El campo `expected_verdict` sirve para fixtures y evaluación; no es evidencia
ni puede imponer el resultado producido por el motor.

## Fases y criterios de cierre

### Fase 1 — contratos y mappings

- agregar schema versionado para mappings OWASP;
- mantener MITRE/NIST/D3FEND como annotations no autoritativas;
- agregar tests de que ningún mapping cambia verdict o finding state.

### Fase 2 — provider Volatility read/derive

- allowlist explícita de plugins;
- parámetros tipados y límites de recursos;
- imagen y resultados confinados al caso;
- provenance completa y hashes deterministas;
- tests de path traversal, symlink, plugin no permitido, output truncado y
  error visible.

### Fase 3 — casos autocontenidos

- validar el formato rico real;
- congelar cada artifact con `lineage_id` estable;
- probar que modificar el JSON original después del freeze no altera el
  snapshot;
- probar que el bundle de salida no se acepta como evidencia de entrada.

### Fase 4 — reanálisis y demo

Sólo después de disponer de un provider real de nuevos artefactos:

```text
observación
    → nuevo artifact
    → freeze
    → reanálisis determinista
    → resultado anterior + resultado nuevo
    → sellos y provenance
```

El LLM puede decidir qué preguntar; la policy decide qué puede ejecutarse; la
herramienta describe lo observado; el motor determinista decide qué soporta la
evidencia.

## Fuera de alcance

- modificar el motor forense externo o sus plugins;
- portar su inferencia a ZAYNOR;
- permitir shell o plugins arbitrarios elegidos por el LLM;
- usar OWASP para alterar veredictos;
- usar Volatility como clasificador de malware;
- aceptar `expected_verdict` como verdad;
- sumar otro comando CLI antes de cerrar la compatibilidad de casos.

## Definición de terminado

El bloque está terminado cuando una demo puede mostrar, de forma reproducible:

1. un caso rico validado y congelado;
2. una observación de Volatility con hashes y provenance;
3. un mapping OWASP explicativo que no cambia la autoridad;
4. un intento de prompt injection tratado como dato;
5. un plugin o parámetro no permitido rechazado;
6. ausencia de provider de reanálisis degradada visiblemente, sin inventar un
   nuevo finding.
