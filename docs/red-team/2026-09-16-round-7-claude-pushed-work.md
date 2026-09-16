# Auditoría red-team — trabajo de Claude ya pusheado
## Red Team Round 7

**Fecha:** 2026-09-16  
**Base auditada:** `main` @ `c77c17d`  
**Método:** Red-Team Auditing + Audit Before Patch + Agent Trust Boundaries + Deterministic Core.  
**Alcance:** cambios de Claude ya presentes en `main`, más las superficies que éstos conectan. No se modificaron archivos durante esta auditoría. Al finalizar aparecieron cambios concurrentes sin commit de Claude en `response_actions.py`, `sigma_candidate.py` y `tests/test_sigma_candidate.py`; esos cambios quedan fuera de esta revisión y no fueron tocados.

## Modelo de amenaza y leyenda epistemológica

El atacante puede influir en artefactos, valores que llegan a propuestas, bundles malformados y contenido que consume el agente. No se asume que pueda modificar el código fuente del motor determinista. Se audita especialmente la frontera entre evidencia congelada, resultado autoritativo, recomendaciones y texto generado por LLM.

**CODE FACT**: observado directamente en el código.  
**PLAUSIBLE HYPOTHESIS**: mecanismo posible, todavía no demostrado.  
**CONFIRMED BY INDUCTION**: reproducido con una ejecución o caso mínimo.  
**FALSIFIED**: el experimento no produjo el comportamiento sospechado.

## Resumen ejecutivo

| ID | Severidad | Nivel | Módulo | Hallazgo |
|---|---|---|---|---|
| RT-01 | Medium | CODE FACT + CONFIRMED BY INDUCTION | `sigma_candidate.py` | El renderizador manual podía producir YAML inválido o alterar su estructura mediante valores hostiles. Claude dejó un fix concurrente sin commit, fuera de esta ronda. |
| RT-02 | Medium | CODE FACT + CONFIRMED BY INDUCTION | `response_actions.py` | Una acción acepta `EvidenceRef` que no está ligada a finding, caso ni manifest. |
| RT-03 | Medium/High | CODE FACT + CONFIRMED BY INDUCTION | `zaynor_mode1_executor.py` | Un `artifact_id` del bundle se transforma en referencia autoritativa sin validar pertenencia al manifest congelado. |
| RT-04 | Medium | CODE FACT | `tools.py` | `generate_forensic_hash` valida una ruta y luego vuelve a abrirla por nombre: queda una ruta TOCTOU distinta de `read_evidence`. |
| RT-05 | Medium/High | CODE FACT | `zaynor_mcp_client.py` | `extra_env` puede sobrescribir las restricciones de Ollama local, evidencia, backend y `PYTHONPATH`. |
| RT-06 | Low/Medium | CODE FACT + PLAUSIBLE HYPOTHESIS | `agents/policy.py` | `human_approved: bool` sigue sin identidad, alcance, argumentos ni expiración. |
| RT-07 | Medium | CODE FACT + FRACTURE | `d3fend_enrichment.py` | `HIGH_CONFIDENCE` no tiene una cadena de verificación suficiente para relaciones D3FEND que MITRE presenta como inferidas/experimentales. |
| RT-08 | Medium | CODE FACT | API pública | Persisten nombres públicos `Vigia*`/`vigia_*` en módulos ZAYNOR, pese a la convención de no llamar así a los módulos propios. |
| RT-09 | Medium | PLAUSIBLE HYPOTHESIS | Volatility | Sólo se probó resolución de `vol3 -h`; falta demostrar análisis completo de un dump real, plugins y trazabilidad. |

## Hallazgos

### RT-01 — Renderizado YAML inseguro

**Incidente:** un título, tag o valor de detección contiene `:`, saltos de línea o indicadores YAML.  
**Evidencia:** `to_yaml_text()` interpolaba valores sin escape.  
**Hipótesis:** un consumidor puede rechazar la regla o interpretar campos inyectados.  
**Discriminante:** se reprodujo con `title="bad: title\\nforged: yes"`; `yaml.safe_load` rechazó el resultado. También se observó que una variante podía crear una clave superior no presente en el objeto.  
**Fractura:** la marca `CANDIDATE` impide presentarla como regla validada, pero no evita YAML corrupto.  
**Veredicto:** **CONFIRMADO POR INDUCCIÓN — MEDIO**. Claude está corrigiendo este punto en cambios concurrentes; no se auditó aún el fix.

### RT-02 — Acción defensiva con evidencia no vinculada

**Incidente:** el sistema propone containment/eradication citando un artefacto inventado.  
**Evidencia:** `ResponseAction.__post_init__()` sólo exige que la tupla no esté vacía.  
**Hipótesis:** cualquier caller puede presentar una acción como evidence-backed sin que la referencia exista en el caso.  
**Discriminante:** `EvidenceRef("fabricated", "not-bound-to-any-result")` fue aceptado y serializado.  
**Fractura:** la acción no se ejecuta automáticamente y requiere aprobación humana.  
**Veredicto:** **CONFIRMADO POR INDUCCIÓN — MEDIO**.

### RT-03 — El finding no prueba que sus refs pertenezcan al snapshot

**Incidente:** una señal del bundle contiene un `artifact_id` que no pertenece al manifest congelado.  
**Evidencia:** `_signal_evidence_ref()` copia el `artifact_id` directamente a `EvidenceRef`; `translate_mode1_bundle()` no recibe ni consulta `CaseManifest`.  
**Hipótesis:** la referencia puede parecer autoritativa aunque el artefacto no esté dentro del conjunto autorizado.  
**Discriminante:** un bundle mínimo con `artifact_id="NOT-IN-MANIFEST"` produjo un `AuthoritativeFinding` con esa referencia.  
**Fractura:** el camino productivo valida el hash del snapshot y el sidecar del bundle; eso no valida la correspondencia individual entre refs y manifest.  
**Veredicto:** **CONFIRMADO POR INDUCCIÓN — MEDIO/ALTO**, condicionado a bundle malformado, engine comprometido o caller que use el traductor sin la validación completa.

### RT-04 — Ruta MCP de hashing con ventana TOCTOU

**Incidente:** `generate_forensic_hash()` valida el path mediante `PathGuard` y después llama a `sha256_file(os.path.abspath(path))`.  
**Evidencia:** [`src/zaynor/tools.py`](../../src/zaynor/tools.py), líneas 241–245; no usa `safe_open()` ni un descriptor ya abierto.  
**Hipótesis:** entre validación y lectura se puede reemplazar el archivo o cambiar el objetivo de la ruta.  
**Discriminante:** la secuencia check-then-open está presente de forma determinista; no se agregó todavía una carrera artificial para no interferir con Claude.  
**Fractura:** `read_evidence()` sí usa apertura segura y verificación posterior; el problema está en esta función hermana.  
**Veredicto:** **CODE FACT — MEDIO**. El bypass es estructural; falta una inducción de carrera para medir explotabilidad práctica.

### RT-05 — `extra_env` puede desactivar el aislamiento declarado

**Incidente:** la configuración MCP declara Ollama local y elimina credenciales cloud, pero luego aplica `env.update(self.extra_env)`.  
**Evidencia:** [`src/zaynor/zaynor_mcp_client.py`](../../src/zaynor/zaynor_mcp_client.py), líneas 72–87. El caller puede sobrescribir `VIGIA_LLM_BACKEND`, `VIGIA_OLLAMA_HOST`, `VIGIA_EVIDENCE_DIR`, `PYTHONPATH` o reintroducir credenciales. `ollama_host` tampoco se valida en `VigiaMCPConfig`.  
**Hipótesis:** una configuración influenciada por usuario o archivo externo puede dirigir el bridge a otro backend o código.  
**Discriminante:** inspección directa confirma el orden de las escrituras; falta demostrar quién controla `VigiaMCPConfig` en producción.  
**Fractura:** si la configuración se construye exclusivamente dentro de código confiable, el riesgo se reduce a mala configuración.  
**Veredicto:** **CODE FACT + HIPÓTESIS CONDICIONAL — MEDIO/ALTO**.

### RT-06 — Booleano de aprobación sin identidad

**Incidente:** cualquier caller interno que invoque `authorize_tool(..., human_approved=True)` satisface el gate de capacidades que requieren aprobación.  
**Evidencia:** [`src/zaynor/agents/policy.py`](../../src/zaynor/agents/policy.py), línea 33; [`runtime.py`](../../src/zaynor/agents/runtime.py), línea 38.  
**Hipótesis:** un scheduler, retry o integración futura puede convertirse accidentalmente en autoridad humana.  
**Discriminante:** no se encontró caller productivo actual que abuse del booleano.  
**Fractura:** Claude ya lo documentó como deuda y el modelo actual no permite al LLM setearlo directamente.  
**Veredicto:** **CODE FACT / HIPÓTESIS FUTURA — BAJO/MEDIO**, no bypass confirmado.

### RT-07 — Confianza D3FEND sin provenance suficiente

**Incidente:** algunas relaciones se serializan como `HIGH_CONFIDENCE`.  
**Evidencia:** [`src/zaynor/d3fend_enrichment.py`](../../src/zaynor/d3fend_enrichment.py), por ejemplo `T1550.002 → D3-MFA`. El sitio oficial de MITRE describe las relaciones ofensivas de D3FEND como inferidas y experimentales.  
**Hipótesis:** un analista puede interpretar la etiqueta como validación oficial o como equivalencia causal.  
**Discriminante:** la propia documentación del módulo no contiene una fuente concreta por relación ni una verificación reproducible del crosswalk.  
**Fractura:** D3FEND está correctamente separado del veredicto, score, hipótesis y evidencia autoritativos.  
**Veredicto:** **FRACTURA EPISTÉMICA — MEDIO**, no bypass de autoridad.

### RT-08 — Incumplimiento de nombres propios del repositorio

**Incidente:** módulos y API públicas de ZAYNOR siguen usando `VigiaAdapter`, `VigiaExecutor`, `run_vigia_mode1`, `VigiaMCPClient` y equivalentes.  
**Evidencia:** búsqueda global en `src/zaynor`.  
**Hipótesis:** el naming puede hacer que consumidores o diagramas confundan el boundary propio con el engine externo.  
**Discriminante:** las clases y funciones existen literalmente; no es una inferencia.  
**Fractura:** las referencias al repositorio externo pueden permanecer en documentación o configuración; el problema son los nombres públicos de módulos propios.  
**Veredicto:** **CODE FACT — MEDIO**, pendiente de una ronda dedicada de renombrado coordinado.

### RT-09 — Volatility aún no tiene prueba forense end-to-end

**Incidente:** el alias permite ejecutar `vol3 -h`, pero eso no prueba que el dump sea leído, que los plugins funcionen ni que sus señales lleguen al finding.  
**Evidencia:** `tests/test_memory_forensics_readiness.py` verifica ayuda/resolución; el informe de Claude declara explícitamente que el dump real queda pendiente.  
**Hipótesis:** puede existir otro fallo de plugin, perfil, permisos, formato o traducción que vuelva a degradar el resultado a cero señales.  
**Discriminante:** ejecutar un dump real con resultado esperado y verificar la cadena dump → señal → evidencia → resultado.  
**Fractura:** no hay evidencia suficiente para afirmar que falla.  
**Veredicto:** **HIPÓTESIS ABIERTA — NO CONFIRMADA**.

## Vectores falsificados

- No se confirmó ejecución automática de response actions.
- No se confirmó un bypass productivo de `human_approved=True`.
- No se confirmó ejecución de código desde el contenido de evidencia mediante el alias de Volatility.
- No se confirmó que Volatility falle con un dump real; sólo se comprobó la ausencia de esa prueba.

## Estado de pruebas

Los tests específicos de las áreas de Claude pasaron **38/38**. La suite completa colecciona **115 tests**, pero la corrida total no terminó dentro de la ventana de 30 segundos usada para esta auditoría, por lo que no se presenta como suite completa verificada.

## Orden recomendado para la remediación conjunta

1. Ligar `EvidenceRef` de acciones, Sigma y findings al `case_id`/manifest/result seal.
2. Unificar hashing MCP con descriptor seguro y regresión TOCTOU.
3. Hacer inmutables las variables de seguridad del entorno MCP y validar host/backend.
4. Reemplazar la aprobación booleana por un grant ligado a caso, capacidad, argumentos, identidad y expiración.
5. Resolver el naming `Vigia*` en una migración coordinada sin romper el boundary externo.
6. Ejecutar prueba real de Volatility y clasificar explícitamente cualquier degradación.
