# Arquitectura de ZAYNOR para frontend

Este documento explica las capas del sistema en lenguaje simple para construir
el diagrama de arquitectura y las vistas de junior y senior.

## Idea central

```text
herramientas observan
        ↓
VIGÍA razona y decide
        ↓
ZAYNOR valida y sella
        ↓
frameworks contextualizan
        ↓
ANNACONDA investiga y explica
```

> ANNACONDA tiene autonomía investigativa, pero no autoridad epistemológica.

El LLM puede decidir qué conviene preguntar o investigar. La policy decide qué
puede hacer. Las herramientas observan. VIGÍA determina qué soporta la
evidencia.

## Capas y responsabilidades

### Herramientas DFIR: observan o derivan evidencia

Ejemplos: Volatility analiza imágenes de memoria; Registry, MFT, Prefetch,
AmCache y ShimCache analizan disco; parsers de PCAP analizan tráfico; browser,
USB, EVTX y filesystem aportan artefactos; SIFT puede funcionar como entorno
reproducible de herramientas.

Estas herramientas no deciden si algo fue malicioso. Producen observaciones o
artefactos derivados con:

```text
artifact · tool · tool_version · input_hash · output_hash
configuration · case_id · provenance
```

En la UI debe decirse “Volatility encontró este proceso en memoria”, no
“Volatility determinó que hubo malware”.

### VIGÍA: motor determinista autoritativo

VIGÍA recibe evidencia congelada y produce el significado autoritativo:

```text
MALICE | SUSPICION | BENIGN | ABSTAIN | UNKNOWN
```

También produce findings, hipótesis, timeline, fracturas, evidencias
discriminantes, confidence, provenance y referencias a los artefactos.

El resultado se sella. Ningún LLM, framework o herramienta externa puede
modificarlo.

### Frontera ZAYNOR: validación y sello

ZAYNOR verifica `case_id`, manifest, conjunto exacto de evidencia, hashes,
provenance, referencias, contrato de findings e integridad. Después genera el
paquete autoritativo sellado.

El sello prueba qué bytes y qué resultado fueron preservados; no convierte una
inferencia incorrecta en verdad.

## Contexto de frameworks

Estos frameworks explican o contextualizan el resultado. No lo crean ni lo
promueven.

### MITRE ATT&CK

Describe el comportamiento adversario que puede corresponder a un finding.

```text
Finding: SUSPICION
Technique: T1070.006 — Timestomp
Mapping status: candidate
Justification: timestamp inconsistente
```

ATT&CK no debe convertir `SUSPICION` en `MALICE`.

### MITRE D3FEND

Describe controles defensivos para detectar, bloquear o reducir un
comportamiento.

```text
ATT&CK: T1070.006
D3FEND: monitoreo de integridad y correlación temporal
```

D3FEND es recomendación defensiva, no evidencia.

### NIST

Organiza el proceso de respuesta:

```text
Detect → Respond → Recover
```

Ayuda a mostrar acciones como preservar evidencia, contener un host, recolectar
memoria, erradicar persistencia, recuperar el servicio y validar la
recuperación.

### Sigma

Una regla Sigma generada es una propuesta de detección. Debe mostrar estado
`candidate` o `draft` hasta que un analista la revise y valide.

## ANNACONDA: control plane agentic

ANNACONDA funciona con Ollama local y MCP. Coordina la investigación, pero no
es un segundo motor de veredictos.

```text
LLM decide WHAT TO ASK
policy decide WHAT IT MAY DO
tools determine WHAT THEY OBSERVED
VIGÍA determine WHAT THE EVIDENCE SUPPORTS
human decide WHETHER TO AUTHORIZE consequential actions
```

Roles previstos: dispatcher, endpoint hunter, persistence hunter, threat
intel, detection engineer, investigator, fleet commander y mentor.

La policy distingue:

```text
READ · DERIVE · ACQUIRE · MUTATE · AUTHORIZE
```

Ningún agente autoriza findings ni muta el resultado sellado. `ACQUIRE`
requiere aprobación humana externa.

## Flujo completo

```text
                    ┌──────────────────────┐
                    │        VIGÍA         │
                    │ deterministic engine │
                    └──────────┬───────────┘
                               │
                    authoritative result
                               │
                               ▼
                    ZAYNOR validation + seal
                               │
              ┌────────────────┴────────────────┐
              │                                 │
              ▼                                 ▼
       HUMAN INTERFACE                    ANNACONDA + Ollama
       junior / senior                         │
       reports / CLI                           ▼
                                      investigation proposal
                                                   │
                                      capability/policy gate
                                                   │
                         ┌─────────────────────────┴──────────────┐
                         ▼                                        ▼
                   READ / DERIVE                              ACQUIRE
                   local DFIR tools                    human approval required
                   Volatility, etc.                    Velociraptor, etc.
                         │                                        │
                         └────────────────┬───────────────────────┘
                                          ▼
                                   NEW EVIDENCE
                                          │
                                   freeze + provenance
                                          │
                                          ▼
                                        VIGÍA
                                          ↺
```

## Qué muestra el frontend

El catálogo de casos del frontend se alimenta de bundles sellados derivados
del corpus canónico de ZAYNOR/VIGÍA. Incluye los casos públicos de `casos/`,
casos adversariales, falsos positivos y falsos negativos seleccionados del
corpus de VIGÍA. Cada workspace puede mostrar el veredicto, evidencia,
provenance, auditoría y contexto de técnicas MITRE ATT&CK cuando el bundle o
la metadata canónica las declara.

Los indicadores MITRE y el contexto NIST se presentan como enriquecimiento de
investigación: no son findings adicionales, no recalculan scores y no cambian
el resultado autoritativo ni su sello. La UI debe distinguir siempre entre el
resultado firmado y el contexto de framework.

### Vista autoritativa

Debe ser la capa más visible:

```text
Verdict: SUSPICION
Case ID: INC-2026-001
Confidence: ...
Evidence set hash: ...
Finding IDs: ...
Custody chain: verified
```

Estos campos vienen del resultado sellado.

### Vista analítica

Muestra observaciones, timeline, hipótesis, fracturas, evidencias
discriminantes, evidence refs y unknowns.

### Vista contextual

Muestra, sin alterar el resultado: MITRE ATT&CK, D3FEND, NIST, Sigma candidate
y acciones defensivas propuestas.

## Junior y senior

### Junior

El mentor explica qué significa cada estado, qué es una técnica ATT&CK, por qué
se necesita memoria u otro artefacto, qué significa `UNKNOWN` o `ABSTAIN`, y qué
se observó frente a lo que todavía es inferencia.

### Senior

La vista técnica permite preguntar qué evidencia sostiene el finding, qué
lineage tiene, qué hipótesis rival fue descartada, de qué artefacto depende el
resultado, qué cambia en un análisis leave-one-out y qué acción defensiva
corresponde.

## Regla de oro para el diagrama

Si una tarjeta puede cambiar el veredicto, pertenece a VIGÍA. Si sólo explica,
contextualiza, recomienda o propone una investigación, pertenece a ZAYNOR o
ANNACONDA.

Volatility, SIFT, MITRE, D3FEND, NIST y el LLM aportan información. Sólo VIGÍA
produce el significado autoritativo.
