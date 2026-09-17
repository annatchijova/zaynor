# Vendorización de un subconjunto curado de las herramientas MCP de VIGÍA (Mode 2)
## Round 17
**Fecha:** 2026-09-17
**Origen:** Anna, tras confirmar que MCP en ZAYNOR ya corre 100% sobre
Ollama local (`BoundedInvestigator` + `OllamaClient`, sin Claude en el
medio, con `ANTHROPIC_API_KEY`/`GOOGLE_CLOUD_*` explícitamente borrados del
subproceso): "eso es más fácil... pongamos más herramientas, no todas las
de vigía". Instrucción explícita: vendorizar solo 9 de las 22 tools de
`vigia_sift_bridge.py`, dejando fuera honeytokens/countermeasures, tools de
imagen/documento, tools de sistema en vivo (proceso/red), y las de
narración/utilidad ya cubiertas por la infraestructura propia de ZAYNOR.

## Por qué esto NO fue una simple repetición del método de la ronda 14

El motor Mode 1 (`vigia_agent.py`) es un pipeline de módulos razonablemente
independientes — trazar su dependencia real con `runpy`/`sys.modules` fue
directo. `vigia_sift_bridge.py` es distinto: **un solo archivo de 4038
líneas**, con 22 herramientas definidas como funciones a nivel de módulo
que comparten estado y helpers de módulo (auditoría, saneamiento de paths,
manejo de honeytokens, cuarentena de evidencia malformada) — no hay 22
módulos separados que trazar, hay 22 funciones entrelazadas en un único
namespace.

**Consecuencia práctica:** "vendorizar 9 de 22 tools" no es "copiar 9
archivos" — es extraer, verbatim, el cuerpo exacto de esas 9 funciones más
el subconjunto REAL de helpers de módulo que ellas (no las 13 excluidas)
referencian. Se determinó por análisis estático de identificadores sobre
los cuerpos extraídos (no por adivinar): cada nombre `_prefijo`/constante
usado dentro de los 9 cuerpos se verificó contra las definiciones de nivel
de módulo del archivo completo, y solo esos se incluyeron.

## Herramientas incluidas y por qué

`generate_forensic_hash`, `read_evidence`, `list_files`, `search_pattern`,
`infer_intent`, `audit_grice_maxims`, `detect_eco_overinterpretation`,
`validate_and_correct_analysis`, `calculate_shannon_entropy` — instrucción
explícita de Anna.

## Deliberadamente excluidas, y por qué

- `activate_honey_token`/`deactivate_honey_token` (como tools expuestas):
  countermeasures activas, fuera del alcance actual de ZAYNOR (investigación
  read-only). **Importante:** `read_evidence` SÍ depende internamente de
  `_deactivate_honey_token_impl`/`_sweep_expired_honey_tokens`/
  `_honey_meta_path` — ese es su comportamiento real y auditado (retiro
  perezoso de tokens vencidos al leer evidencia), así que esos tres
  helpers SÍ se vendorizaron como soporte interno, sin exponer las dos
  tools de activación/desactivación como llamables por el cliente MCP.
  Excluir la lógica interna habría sido reimplementar `read_evidence` con
  un comportamiento distinto al real — exactamente lo que AGENTS.md 2.1
  prohíbe.
- `vision_intent_audit`/`analyze_image_layers`/`audit_image_metadata`/
  `detect_document_geometry`/`ocr_semantic_validator`: requieren
  `vigia.tools.vision_audit`/`document_integrity` (CLIP, PIL) — fuera del
  alcance actual de evidencia que ZAYNOR analiza.
- `mount_sift_evidence`: montaje de imágenes de disco, fuera de alcance.
- `audit_network`/`list_processes`/`detect_habit_incongruence`: telemetría
  de sistema EN VIVO — ZAYNOR analiza evidencia ya congelada, nunca un
  sistema corriendo.
- `analyze_stylometry`/`calculate_human_entropy`/`detect_human_jitter`/
  `reason_with_llm`: `reason_with_llm` es la propia herramienta de
  narración de VIGÍA — ZAYNOR ya tiene su narrador propio
  (`agents/mentor.py` + `OllamaClient`, con el guard anti-alucinación
  encima); duplicarla habría sido exactamente la "basura improvisada" que
  Anna pidió no construir, en la dirección opuesta (duplicar lo que ya
  existe, en vez de reusar).
- `reload_phonetic_dict`/`get_phonetic_dict_stats`: utilidad operativa, no
  necesaria para este alcance.
- `trust_fusion_analysis`/`cross_artifact_analysis`/
  `analyze_document_register`/`analyze_document_entanglement`/
  `compare_paired_bundles`: módulos de enriquecimiento opcionales, gateados
  por flags en VIGÍA — quedan fuera de esta ronda.

## Qué se vendorizó, en concreto

- `vendor/vigia_engine/vigia/vigia_sift_bridge_min.py` (nuevo): ensamblado
  por extracción programática (AST, no regex — el primer intento con
  regex sobre-capturaba contenido entre funciones, ver "Lección" abajo) de:
  header/licencia, imports curados, `_verify_stdlib_integrity`, `mcp =
  FastMCP(...)`, constantes de seguridad, `_audit_argument_value`/
  `_audit_argument_summary`/`_audit_mcp_entry`/`_register_mcp_tool`,
  `_sanitize_path_local`, `_sanitize_text`/`_sanitize_text_list`,
  `_utcnow`, resolución de `EVIDENCE_BASE_DIR`/`WORK_BASE_DIR`/
  `_HONEY_TOKEN_DIR`/`_PURGATORY_DIR`/`_MOUNT_ROOT`, `_word_search`, el
  prompt vault (`_load_system_brain`/`SYSTEM_PROMPT_PEIRCE`), los alias
  `RUSSIAN_PHONETIC_MAP`/`HIGH_RISK_PHONETIC`, `_IntegrityViolation`/
  `_quarantine_malformed_evidence`, los tres helpers internos de
  honeytoken usados por `read_evidence`, y las 9 tools completas
  (decoradores + cuerpo, byte-idéntico al original). Un `__main__` mínimo
  (`mcp.run()`) reemplaza el arranque completo de VIGÍA (verificación de
  proceso padre, KASSANDRA_SALT, transporte) — esas verificaciones son
  hardening de Mode 2 standalone que ZAYNOR no ejercita (siempre lanza el
  bridge él mismo, siempre stdio, nunca HTTP/SSE); omitidas, no
  reimplementadas con lógica distinta.
- `vendor/vigia_engine/vigia/phonetic_loader.py` (nuevo, sin modificar):
  autocontenido, sin imports internos de `vigia.*` más allá de stdlib.
- `vendor/vigia_engine/vigia/config.py` (nuevo, sin modificar): expone
  `CONFIG`/`LLMBackend`, resuelve el backend LLM vía `VIGIA_LLM_BACKEND`
  (que `VigiaMCPConfig.server_params()` ya fuerza a `"ollama"`).
- `vendor/vigia_engine/vigia/data/system_prompt_peirce.md` (nuevo, sin
  modificar): prompt Peirce que `_load_system_brain()` carga.
- `vendor/vigia_engine/phonetic_dict.json` (nuevo, sin modificar): el
  diccionario fonético real (994 líneas, 81 entradas, 22 de alto riesgo) —
  copiado a la ruta exacta que `phonetic_loader.py` resuelve como
  candidato 3 (`_HERE.parent / "phonetic_dict.json"`), la misma que usa el
  repo real de VIGÍA hoy (`vigia/security/`, `vigia/config.py`, etc. ya
  estaban vendorizados desde la ronda 14 — Mode 1 los necesitaba también).

## Cómo se conecta

`VigiaMCPConfig` (`src/zaynor/zaynor_mcp_client.py`):
- `vigia_repo_path` pasa de campo obligatorio a
  `field(default_factory=_default_vendored_vigia_path)` — mismo patrón que
  `cli.py::_default_engine_repo()` para Mode 1: bundleado con el repo, no
  una ruta de una máquina específica, así que dejó de aplicar la razón
  original para no defaultearlo.
- Nuevo campo `bridge_relative_path: str = "vigia/vigia_sift_bridge_min.py"`
  — el bridge vendorizado usa un nombre de archivo deliberadamente
  DISTINTO al real (`vigia_sift_bridge.py`) para que nunca se confundan:
  quien pase un checkout externo real debe pasar también
  `bridge_relative_path="vigia/vigia_sift_bridge.py"` explícitamente para
  obtener las 22 tools completas.
- `server_params()` usa `self.vigia_repo_path / self.bridge_relative_path`
  en vez del path hardcodeado anterior.
- `evidence_dir` sigue sin default (no hay uno razonable).

## Verificación real, sin mocks

Cada una de las 9 tools se llamó de verdad a través de
`VigiaMCPClient`/`VigiaMCPConfig` con sus defaults (bridge vendorizado,
subproceso real, protocolo MCP real sobre stdio):

- `generate_forensic_hash`: SHA-256 real, coincide con el hash calculado
  independientemente sobre el mismo archivo.
- `read_evidence`: preview de contenido correcto, hash calculado
  atómicamente durante la lectura, coincide.
- `list_files`: listado real, confinado a `VIGIA_EVIDENCE_DIR`; confirmado
  que un intento de listar `/etc` es bloqueado/reportado como error (la
  confinación de paths de VIGÍA, ejercida a través del cliente, no una
  garantía propia de ZAYNOR).
- `search_pattern`: grep real vía `safe_grep`, encuentra la coincidencia
  esperada.
- `calculate_shannon_entropy`: cálculo real, veredicto NOISE para texto de
  baja entropía.
- `infer_intent`: cadena Peirce completa (Firstness/Secondness/Thirdness)
  generada correctamente a partir de un `message_history` real.
- `audit_grice_maxims`: análisis real de máximas de Grice sobre un mensaje
  de prueba, veredicto NOISE con las 5 máximas evaluadas.
- `detect_eco_overinterpretation`: análisis real, veredicto
  NORMAL_DISTRIBUTION.
- `validate_and_correct_analysis`: confirmado que intenta invocar
  `LLMBackend().reason(...)` (que resuelve a Ollama local, forzado por
  `VigiaMCPConfig`) — en esta corrida particular el backend no respondió a
  tiempo con el modelo default (`deepseek-r1:8b`) y la función degradó
  honestamente (`"error": "LLM returned empty response"`,
  `"backend_warn": "DEGRADED: ..."`), sin caerse — comportamiento correcto
  de VIGÍA documentado como tal, no un defecto de esta vendorización.

`tests/test_zaynor_mcp_client.py` (5 tests) y
`tests/test_investigator_tools.py` (6 tests, incluida la clase antes
gateada por `skipif`) migrados al mismo patrón de la ronda 14 —
`VigiaMCPConfig(evidence_dir=...)` sin `vigia_repo_path` explícito, usando
el default vendorizado — y ejecutados de verdad, no solo importados.
11/11 pasan.

## Lección: extracción por AST, no por regex

Un primer intento de extraer el span de cada tool con una regex
("desde `@_register_mcp_tool` hasta el próximo `@_register_mcp_tool`")
sobre-capturó: dos tools (`list_files`, `detect_eco_overinterpretation`)
tienen bloques de comentarios y definiciones de módulo (la clase
`_IntegrityViolation`, las constantes de honeytoken) intercalados
*entre* el `return` real de la función y el próximo decorador — la regex
los incluyó como si fueran parte del cuerpo de la tool anterior, generando
un archivo con `SyntaxError` (`'{' was never closed`) al incluir un
fragmento de un diccionario truncado. Se corrigió parseando el archivo real
con `ast` y usando `node.end_lineno` de cada `AsyncFunctionDef` — el mismo
principio que llevó a preferir tracing dinámico sobre análisis estático en
la ronda 14: no asumir la forma del código fuente, verificarla.

## Estado final

232 → +11 tests reales (5 + 6), todos pasan. Suite completa: 231 passed,
14 skipped, 2 failed — los 14 skips y 2 fallos son enteramente del trabajo
en curso de Codex sobre `vendored_engine.py` (Mode 1, bug de resolución de
path no relacionado con esta ronda, no tocado aquí). Nada de lo agregado
en esta ronda depende de un repositorio externo de VIGÍA para funcionar.

## Pendiente

- El resto de las 13 tools no vendorizadas queda documentado arriba con su
  razón; si el alcance de ZAYNOR crece hacia telemetría en vivo,
  documentos/imágenes, o countermeasures activas, se repite este mismo
  método (extracción AST + verificación real) para agregarlas.
- `bridge_relative_path` no tiene todavía un CLI/config-loader que lo
  exponga como flag — hoy es un valor de `VigiaMCPConfig` que cualquier
  invocador programático puede pasar, pero no hay un `--bridge-path` en
  ningún comando; agregarlo si/cuando se construya un comando de
  investigación interactiva análogo a `zaynor chat`/`zaynor serve`.
