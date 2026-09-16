# Informe Red Team Consolidado — integración y trabajo de Claude

**Fecha:** 2026-09-16  
**Método:** Red-Team Auditing + abductive engineering (A–D–I), invariant
hunting, parser/path differential y deterministic core.  
**Alcance:** `25f5096` (EBS scorer y findings), `abe1b98` (evidencia forense
real y allowlists del subprocess), más el estado de integración que consume
esos cambios. El análisis es sobre código propio de ZAYNOR; `vigia_agent.py`,
`vigia-repo` y sus módulos son dependencias externas.

## Modelo de amenaza

El caller puede entregar rutas o evidencia no confiable y el proceso externo
puede fallar o ser inconsistente. No puede modificar el código de ZAYNOR ni
romper SHA-256. Un hash válido acredita bytes, no la veracidad semántica de un
finding ni la independencia de sus fuentes.

## Hallazgos numerados

### 1. TOCTOU de evidencia entre hash y consumo — Alta

**CONFIRMED BY INDUCTION.** `run_vigia_mode1()` calcula el hash antes de lanzar
el subprocess y sólo compara el hash que VIGÍA devuelve contra ese valor. Un
agente de prueba leyó el hash inicial, modificó la evidencia antes de
procesarla y devolvió el hash inicial; el executor aceptó el resultado.

**Invariante:** los bytes hash-read y los bytes consumidos por el análisis deben
ser los mismos. El cierre mínimo es rehashear después del proceso y rechazar
cualquier cambio; el cierre estructural es entregar una snapshot/descriptor
inmutable al consumidor.

### 2. Evidencia fuera de una raíz autorizada — Media/Alta

**CODE FACT; impacto condicionado al caller.** El executor acepta cualquier
`evidence_path` existente. `PathGuard` no interviene en esta entrada. El
commit `abe1b98` además exporta esa ruta como `VIGIA_ALLOWED_REGISTRY_PATHS` y
`VIGIA_ALLOWED_DUMP_PATHS`, ampliando las allowlists del proceso externo hasta
la ruta entregada por el caller.

**Invariante:** la evidencia analizada debe estar dentro de la raíz del caso
autorizada y toda allowlist derivada debe ser un subconjunto de ella. El fix
requiere una raíz autorizada explícita, comprobación lexical/symlink antes del
proceso y revalidación posterior.

### 3. `artifact_id` no demuestra `lineage_id` — Alta

**CODE FACT + CONFIRMED BY INDUCTION.** Para EBS, el traductor usa el mismo
valor como `artifact` y `lineage_id`. Para imágenes reales usa `artifact_type`
como lineage. Esto distingue archivos en algunos casos, pero no prueba
collector, adquisición común ni independencia. Dos señales duplicadas producen
dos refs con el mismo id sin deduplicación ni gate de independencia.

**Invariante:** un `EvidenceRef` debe conservar lineage de procedencia
verificado; no debe fabricarse desde un identificador de artefacto.

### 4. Finding `BENIGN` con señales y veredicto `NOISE` — Media

**CONFIRMED BY INDUCTION.** El fixture EBS produce tres señales reales, pero
VIGÍA devuelve `NOISE`. La traducción crea un finding con estado `BENIGN` y
las tres referencias. El mapping `NOISE → BENIGN` y la existencia del finding
no fueron justificados como el mismo contrato semántico.

**Invariante:** señal, veredicto compuesto y estado autoritativo deben tener
una tabla de traducción explícita; evidencia sospechosa no debe ser presentada
como benignidad sólo por presencia de un finding.

### 5. El EBS derivado no contiene predicados revalidables — Alta

**CONFIRMED BY INDUCTION.** Se puede modificar el JSONL original después de
crear `evidence.json` y el resultado sigue citando `auth:E001`, `fs:E006` y
`net:E005`. El EBS contiene descripciones y pesos generados por el scorer, no
una prueba independiente que el gate vuelva a leer del caso congelado.

**Invariante:** el gate debe reconsultar los campos tipados del caso congelado;
un artefacto derivado no puede convertirse por sí solo en corroboración.

### 6. Scorer fixture-specific con cobertura parcial — Media funcional

**CODE FACT.** El scorer usa listas hardcodeadas de dispositivos y `next()`
para tomar sólo el primer login, primer timestomp y primer egress. Registros
posteriores que también satisfacen la regla quedan fuera. Registros JSON
válidos que no son objetos pueden producir `AttributeError`.

### 7. Escritura derivada no atómica y parent symlink — Media

**CONFIRMED BY INDUCTION.** `write_ebs_evidence()` protege sólo el symlink del
archivo final; un parent symlink permite escribir fuera de la raíz lógica.
Además usa `write_text()` directo, sin reemplazo atómico.

### 8. “Raw score no es dial” no prueba toda la regla del motor — Hipótesis

**PLAUSIBLE HYPOTHESIS.** El experimento de subir un score individual y
observar `NOISE` prueba sólo ese caso. No demuestra universalmente que todo
resultado distinto de `NOISE` necesite la misma forma de corroboración.

### 9. Cobertura de tests no portable — Media de verificación

**CODE FACT.** Las pruebas de imagen real se saltean si falta un path absoluto
local. La suite propia puede estar verde sin ejecutar esa integración; la
afirmación de `62/62` no fue reproducible porque el test MCP bloquea en este
entorno.

### 10. Naming de módulos propios — Cerrado

La ronda anterior fue remediada: los módulos propios son `zaynor_*`. Las
referencias restantes a `VIGÍA`/`vigia_agent.py` describen la dependencia
externa y no son nombres de módulos ZAYNOR.

### 11. Exactitud numérica — Parcialmente cerrado

Los pesos del scorer usan `Fraction` y el metadata temporal de `PathGuard` usa
Fraction exacta desde `st_mtime_ns`. Los floats restantes son temporales
operacionales del sandbox o entradas de display/auditoría, no valores que
decidan un finding. No se observó un float en el camino de scoring/hash.

## Controles que sí resistieron

- `PathGuard` rechazó `..`, symlinks intermedios, paths fuera del allowlist y
  reemplazo entre validación y apertura.
- El executor validó sidecar, hash de bundle, exit code y veredicto.
- Los nombres de módulos propios ya no usan `vigia_*`.

## Prioridad de corrección

1. Raíz autorizada + rehash post-ejecución para cerrar TOCTOU y path boundary.
2. Predicados revalidables desde el manifest; no elevar EBS derivado como
   evidencia independiente.
3. Tabla de estados y lineage verificada.
4. Scorer robusto ante registros múltiples/malformados y writer atómico.
5. CI reproducible para las pruebas de integración real.
