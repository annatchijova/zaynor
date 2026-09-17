# ZAYNOR — Limitaciones conocidas

**Versión:** post-vendorización del motor (ronda 14) + auditoría de KASSANDRA/hashes (esta sesión)
**Aplica a:** `github.com/annatchijova/zaynor`

> ZAYNOR no pretende ser infalible — pretende ser **auditable**. Estas
> limitaciones se documentan a propósito, como parte del estándar Daubert
> de falsabilidad: un sistema que no puede nombrar sus propios modos de
> falla no merece confianza en un expediente. Formato adaptado del propio
> `KNOWN_LIMITATIONS.md` de VIGÍA — mismo espíritu, alcance de ZAYNOR.

---

## Cómo leer este documento

Cada entrada describe:

- **Qué** hace mal o no hace ZAYNOR todavía
- **Por qué** — la causa técnica real, verificada, no supuesta
- **Implicancia forense** — qué significa para un caso real
- **Workaround**, si existe, o declaración explícita de que no hay ninguno

Las marcadas **[EN PROGRESO]** tienen un fix identificado, en curso por
otro agente en este mismo repo al momento de escribir esto. Las marcadas
**[DECISIÓN DE DISEÑO]** son intencionales, no bugs.

---

## Parte I — Motor y verificación

### L-001 — Bug de empaquetado: resolución de ruta del motor vendorizado

**Afecta:** `zaynor analyze` sin `--engine-repo` explícito | **Estado: [EN PROGRESO]**

**Descripción:** `src/zaynor/vendored_engine.py::VENDORED_ENGINE_PATH` resuelve
a `<repo>/src/vendor/vigia_engine` en vez de `<repo>/vendor/vigia_engine` — un
nivel de directorio de más. `zaynor analyze` sin `--engine-repo` falla con
`vigia_agent.py not found`.

**Causa raíz:** cambios en curso a `pyproject.toml`
(`[tool.setuptools.packages.find]` con `where = ["src", "."]`) para que
`vendor/` se instale como paquete propio junto a `zaynor` — la resolución de
ruta en `vendored_engine.py` no se actualizó en el mismo commit.

**Implicancia forense:** ninguna sobre el resultado — el motor sigue siendo
el mismo, byte a byte, una vez apuntado correctamente. Es una molestia
operativa, no un problema de integridad.

**Workaround:** pasar `--engine-repo vendor/vigia_engine` explícito (ver
`GUIA_PERITOS.md`). Se puede sacar una vez que el empaquetado quede resuelto.

---

### L-002 — Verificación EBS v1 tope en Level 2, no Level 3

**Afecta:** `vendor/vigia_engine/forensics/verify_ebs_v1.py --strict` | **Estado: real, no resuelto**

**Descripción:** El bundle EBS v1 que produce `scripts/build_ebs_bundle.py`
pasa 9/11 chequeos (`PASS`, Level 2 — Cryptographically valid), pero nunca
llega a Level 3 (Fully compliant).

**Causa raíz:** los 2 chequeos que faltan (`R4_ENGINE_ATTESTATION`,
`R5_ECL_BINDING`) requieren atestación criptográfica del motor (árbol fuente
pineado + manifiesto de dependencias) y anclaje de un External Constraint
Layer — funcionalidad real de VIGÍA que ZAYNOR no cablea todavía.

**Implicancia forense:** el bundle es matemáticamente consistente y
verificable de forma independiente (Level 2 ya es una garantía real), pero
no se puede probar criptográficamente que salió exactamente del árbol de
código atestado — solo que tiene el formato correcto (confirmado por
lectura de `verify_ebs_v1.py`, comentario R4 explícito sobre este límite).

**Workaround:** ninguno todavía. No usar `--strict` — fallará siempre hasta
que se cablee la atestación de motor.

---

### L-003 — El verificador EBS v1 solo aplica al Camino A (casos JSON)

**Afecta:** `scripts/build_ebs_bundle.py` sobre evidencia de imagen forense | **Estado: [DECISIÓN DE DISEÑO], documentada**

**Descripción:** `build_ebs_bundle.py` llama a `vigia_scorer._vigia_score()`
directo, que espera un caso con esquema ForensicBundle (`artifacts`,
`temporal_violations`, etc.). El Camino B (evidencia de imagen: registro,
prefetch, navegador...) pasa por `SIFTOrchestrator`, que arma un bundle de
formato distinto — el que devuelve la CLI de Mode 1 directamente
(`agent_verdict`/`pipeline_results`/`audit_trail`), no el EBS v1 estándar.

**Causa raíz:** son dos rutas de ingestión genuinamente distintas dentro de
VIGÍA mismo — confirmado leyendo `vigia_scorer.py` y `sift_orchestrator.py`
por separado.

**Implicancia forense:** para el Camino B, la única verificación
independiente disponible hoy es `zaynor audit` (capa propia de ZAYNOR:
manifest, snapshot, sello). No hay forma de correr `verify_ebs_v1.py` sobre
evidencia de imagen sin construir antes ese puente — no existe todavía.

**Workaround:** ninguno. Usar `zaynor audit` para el Camino B.

---

## Parte II — Agentes e investigación

### L-004 — Solo 9 de las 22 herramientas MCP de VIGÍA están vendorizadas

**Afecta:** `zaynor_mcp_client.py` / investigación con herramientas | **Estado: [DECISIÓN DE DISEÑO]**

**Descripción:** se vendorizó (ronda 17) un subconjunto curado:
`generate_forensic_hash`, `read_evidence`, `list_files`, `search_pattern`,
`infer_intent`, `audit_grice_maxims`, `detect_eco_overinterpretation`,
`validate_and_correct_analysis`, `calculate_shannon_entropy`.

**Causa raíz:** decisión explícita, no limitación técnica — se excluyeron
deliberadamente: honeytokens/contramedidas (`activate_honey_token` y par),
herramientas de visión/documento (fuera del alcance actual de ZAYNOR),
telemetría de sistema en vivo (`audit_network`, `list_processes`,
`detect_habit_incongruence` — ZAYNOR analiza evidencia ya congelada, no
telemetría en vivo), y `reason_with_llm` (ZAYNOR tiene su propio narrador
Ollama, no hace falta duplicar).

**Implicancia forense:** ninguna para los casos que ZAYNOR ya cubre. Si se
necesita alguna de las 13 restantes, hay que vendorizarla siguiendo el
mismo método de tracing dinámico (documentado en
`docs/red-team/2026-09-17-round-17-vendored-mcp-tools.md`).

**Workaround:** no aplica — es alcance intencional, no un bug.

---

### L-005 — ENDPOINT_HUNTER / PERSISTENCE_HUNTER fuera de alcance

**Afecta:** roles de agente listados en el README | **Estado: fuera de alcance por diseño**

**Descripción:** estos dos roles no tienen implementación real.

**Causa raíz:** requerirían un backend de recolección en vivo (tipo EDR)
que ZAYNOR no tiene ni pretende tener — VIGÍA (y por lo tanto ZAYNOR)
analiza evidencia ya congelada, nunca telemetría en vivo de un endpoint.

**Implicancia forense:** ZAYNOR no sirve para respuesta a incidentes en
tiempo real — es una herramienta post-incidente. Esto está en el propio
posicionamiento del producto, no es un descuido.

**Workaround:** ninguno — cambiaría el producto de raíz.

---

### L-006 — THREAT_INTEL fuera de alcance por ahora

**Afecta:** enriquecimiento con inteligencia de amenazas externa | **Estado: evaluado, no incorporado**

**Descripción:** existe una implementación portátil (enriquecimiento vía
VirusTotal/GTI, con degradación honesta si falta la API key) evaluada
durante esta sesión, pero no conectada al pipeline.

**Causa raíz:** implica una dependencia de red externa — decisión de
producto pendiente, no una limitación técnica de la implementación en sí.

**Implicancia forense:** los veredictos de ZAYNOR no se enriquecen hoy con
reputación externa de indicadores (hashes, IPs, dominios).

**Workaround:** ninguno todavía — pendiente de decisión.

---

### L-007 — Mode 1 no tiene el escalón INTENT — topea en SUSPICION

**Afecta:** todos los veredictos que pasan por `zaynor analyze` | **Estado: heredado de VIGÍA, [DECISIÓN DE DISEÑO]**

**Descripción:** el motor determinista de Mode 1 (`vigia_agent.py`) no
emite `INTENT` — casos que calificarían como INTENT quedan topeados en
`SUSPICION` por el propio pipeline de scoring de VIGÍA.

**Causa raíz:** documentado en el propio `CLAUDE.md` de VIGÍA: "Mode 1 has
no INTENT rung in its deterministic motor". Solo Mode 2 (Claude Code +
MCP, con el protocolo de refutación completo) puede emitir INTENT.

**Implicancia forense:** un caso analizado solo por `zaynor analyze`
(Camino A o B) nunca va a decir "INTENT" — el techo es SUSPICION salvo que
el patrón sea tan claro que el motor lo suba directo a MALICE.

**Workaround:** ninguno dentro de Mode 1 — es correcto por diseño, no un
bug a arreglar.

---

## Parte III — Narración y guardas

### L-008 — El narrador puede devolver `[CLAIM NOT VERIFIED]` sin más detalle

**Afecta:** `zaynor chat` / `zaynor serve` | **Estado: real, comportamiento preexistente de `hallucination_guard.py`**

**Descripción:** si la respuesta del modelo no calza con ningún patrón de
reclamo extraíble (`extract_claims`), la narración segura se reemplaza
íntegra por `[CLAIM NOT VERIFIED]` — observado real contra `hermes3:8b`
respondiendo en español a una pregunta en español.

**Causa raíz:** el extractor de reclamos es conservador a propósito (falla
cerrado ante ambigüedad) — no intenta adivinar qué quiso decir el modelo si
no matchea la forma esperada.

**Implicancia forense:** una narración legítima pero con una forma
inesperada puede leerse como "vacía" para el usuario final, sin indicar por
qué. No es una alucinación real — es el guard siendo demasiado
conservador.

**Workaround:** usar `--json` (CLI) para ver el diagnóstico completo de
`GuardResult`, o preguntar en inglés / con frases más directas.

---

### L-009 — `zaynor chat`/`zaynor serve` fijan audiencia SENIOR siempre

**Afecta:** `src/zaynor/api.py::chat_completions` | **Estado: real, no resuelto**

**Descripción:** no hay forma de que un mensaje de OpenWebUI pida
`Audience.JUNIOR` — la API siempre narra en modo senior.

**Causa raíz:** el contrato de mensaje (`{"case_id", "question"}`) no tiene
un campo para audiencia; agregarlo quedó fuera de esta ronda.

**Implicancia forense:** ninguna sobre la integridad del resultado — es
solo un límite de UX. `zaynor chat` en terminal sí soporta `--audience`.

**Workaround:** usar la CLI (`zaynor chat --audience junior`) en vez de la
API cuando se necesite el modo junior.

---

### L-010 — `ReadOnlyToolRegistry` está probado pero no conectado a un pipeline real

**Afecta:** `src/zaynor/tools.py` | **Estado: real, código sin caller de producción**

**Descripción:** existe una implementación completa y testeada (hash de
evidencia, lectura acotada, grep con sandbox, todo auditado con
`AuditLog`), pero ningún comando de la CLI ni investigador la instancia
todavía — solo se ejerce desde `tests/test_tools_readonly.py`.

**Causa raíz:** el investigador acotado (`agents/investigation_runner.py`)
y esta capa de herramientas de solo lectura se construyeron en paralelo,
sin cablear todavía uno con el otro.

**Implicancia forense:** ninguna hoy — no se usa, así que no puede fallar
en un caso real. Es una capacidad lista para conectar, no una que esté
fallando en silencio.

**Workaround:** no aplica — trabajo pendiente, no un bug.

---

### L-011 — Un `rationale` de VIGÍA puede llegar cortado a mitad de oración

**Afecta:** reportes generados sobre casos reales (ej. NITROBA) | **Estado: real, contenido de VIGÍA no editado por ZAYNOR**

**Descripción:** el campo `rationale` de un finding puede terminar en medio
de una frase (observado real: "...NOISE would overclaim a", cortado).

**Causa raíz:** es contenido genuino que devuelve el motor de VIGÍA — ZAYNOR
lo muestra tal cual, sin completar ni editar (mostrar una oración inventada
para "completarla" sería peor: inventar contenido no autorizado).

**Implicancia forense:** el reporte puede leerse como incompleto en ese
campo puntual. No afecta el veredicto ni el sello — es únicamente texto
descriptivo.

**Workaround:** ninguno del lado de ZAYNOR — corresponde investigar el
límite de longitud del lado de VIGÍA si se quiere resolver de raíz.

---

## Parte IV — Corpus de casos

### L-012 — El corpus canónico de casos sesga fuerte hacia MALICE

**Afecta:** `casos/case_*.json` (los 5 del corpus canónico v2.4) | **Estado: real, propio del corpus fuente**

**Descripción:** de los 52 casos del corpus canónico de VIGÍA, la enorme
mayoría tiene `expected_verdict: MALICE` — solo uno (`case_008`) es
`SUSPICION`. No hay ningún `NOISE`, `BENIGN` ni `ABSTAIN` entre los 52.

**Causa raíz:** el corpus canónico se diseñó para ejercitar vectores de
intencionalidad maliciosa específicamente — no es una muestra representativa
de tráfico/actividad general.

**Implicancia forense:** una demo armada solo con este corpus sobre-muestrea
casos positivos — no demuestra la capacidad de ZAYNOR de decir "esto es
ruido" o "esto es benigno" tan bien como demuestra detectar malicia. Los 5
casos reales elegidos (NITROBA, Sony, Target, Colonial, Cridex) compensan
parcialmente con variedad de veredicto real (SUSPICION/MALICE).

**Workaround:** para demostrar cobertura completa de la escala de
veredictos, complementar con `scenarios/inc-2026-demo-001` (da `ABSTAIN`)
o con casos propios etiquetados `NOISE`/`BENIGN`.
