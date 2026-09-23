# ZAYNOR — auditoría de Code Scanning

**Fecha:** 2026-09-23  
**Base auditada:** `main` @ `591083e961c76c4d6405782a78d06687bdda3940`  
**Fuente inicial:** [GitHub Code Scanning](https://github.com/annatchijova/zaynor/security/code-scanning)  
**Método:** `attack-surface-triage` + `red-team-auditing` + revisión de código actual  
**Estado:** informe previo a remediación; no se aplicaron fixes en esta ronda.

## Resumen ejecutivo

GitHub muestra **25 alertas CodeQL abiertas**. El número de alertas no equivale
al número de vulnerabilidades: 21 son variaciones del mismo patrón de path
injection detectado en rutas que ya tienen controles de path o que son inputs
locales deliberados del CLI.

La auditoría deja dos áreas para confirmar/remediar, y varias alertas que no
sobreviven como vulnerabilidad demostrada en el HEAD actual:

| ID | Alertas | Nivel actual | Clasificación | Conclusión |
|---|---:|---|---|---|
| A1 | 23–24 | CONFIRMED BY INDUCTION (payload) | exposición de detalles de excepción | `compute_case_audit()` devuelve al payload un path interno capturado desde una excepción; los endpoints de overview/audit exponen ese reporte. |
| A2 | 25 | CODE FACT / PLAUSIBLE | temporary file inseguro | `tempfile.mktemp()` existe en un script de demostración; es una carrera local, no un RCE demostrado del servidor. |
| A3 | 1–21 | CODE FACT / no confirmado como bypass remoto | path injection | El scanner ve paths derivados de datos; los consumidores revisados validan `case_id`, symlinks, `..`, tipo y tamaño, o son rutas elegidas explícitamente por el operador local. |
| A4 | 22 | CODE FACT / FALSO POSITIVO SEMÁNTICO | sanitización URL | La alerta trata `gmail.com` dentro de un nombre de cuenta Android como URL sanitization; el valor se usa como señal forense, no para validar una URL. |

## Ledger individual de las 25 alertas

La siguiente tabla no agrupa decisiones: cada número del dashboard tiene una
revisión propia. “No confirmado” significa que el scanner encontró un flujo de
datos, pero la prueba del impacto de seguridad no sobrevivió al boundary
observado; no significa que el warning de CodeQL haya sido ignorado.

| Alerta | Ubicación reportada | Revisión individual | Decisión actual |
|---:|---|---|---|
| 1 | `api.py:682` columna 12 | `case_id` llega a `cases_root / case_id`; la ruta sólo se usa después de `_SAFE_CASE_ID.fullmatch()`. | No confirmado como traversal remoto. |
| 2 | `api.py:682` columna 41 | Segundo flujo a la misma expresión `case_dir`; la ruta permanece bajo el mismo guard de `case_id` y se rechaza si es symlink/no-directory. | No confirmado como traversal remoto. |
| 3 | `audit_log.py:105` | `_reject_symlink(path)` recibe un `Path` derivado del log, pero sólo inspecciona el objeto; no abre una ruta atacante. | No confirmado; guard observado. |
| 4 | `audit_log.py:119` | `_reject_oversized(path)` hace `stat()` después de los callers que construyen/validan el log; el límite evita DoS de parseo, no es un sink de lectura arbitraria remoto. | No confirmado como path injection explotable. |
| 5 | `audit_log.py:283` | `load_entries()` vuelve a rechazar symlink antes de `exists()`/lectura; el caller API valida el identificador. | No confirmado. |
| 6 | `audit_log.py:287` | El `open()` está precedido por `_reject_symlink` y `_reject_oversized`; no se demostró control remoto del path fuera del case autorizado. | No confirmado. |
| 7 | `audit_log.py:320` | `verify_with_report()` aplica el mismo rechazo de symlink antes de leer. | No confirmado. |
| 8 | `audit_log.py:332` | El `open()` de verificación sólo ocurre después de existencia, symlink y límite de tamaño. | No confirmado. |
| 9 | `audit_log.py:380` | El sidecar `.tail` se deriva del log ya validado y también pasa por `_reject_symlink`. | No confirmado. |
| 10 | `audit_log.py:385` | `tail_path.read_text()` está detrás del mismo guard; el parser no recibe un path HTTP arbitrario. | No confirmado. |
| 11 | `cli.py:55` | `_fixture_path()` acepta un path explícito del operador local, rechaza symlinks y resuelve un archivo regular. | Input local intencional; no vulnerabilidad remota demostrada. |
| 12 | `cli.py:56` | `stat()` opera sobre el path resuelto y el archivo está limitado a `_MAX_FIXTURE_BYTES`. | No confirmado como bypass; hardening existente. |
| 13 | `cli.py:59` | La condición `is_file()` impide convertir un directorio en fixture; el path sigue siendo una selección local del CLI. | No confirmado. |
| 14 | `cli.py:254` | El manifest se lee mediante `_fixture_path()` desde un `case_dir` ya seleccionado/validado; no acepta un path HTTP independiente. | No confirmado. |
| 15 | `frozen_snapshot.py:52` | `_inventory(root)` recorre `root`, pero sus callers pasan `evidence_dir` después de validarlo como directorio no symlink. | No confirmado en el flujo alcanzable. |
| 16 | `frozen_snapshot.py:63` | `evidence_dir.is_dir()` y `is_symlink()` son precisamente el guard de frontera antes de inspeccionar entries. | No confirmado; guard observado. |
| 17 | `frozen_snapshot.py:63` | Segundo flujo hacia el mismo guard de `evidence_dir`; no agrega una ruta de ataque distinta. | No confirmado. |
| 18 | `frozen_snapshot.py:74` | `path = evidence_dir / relative` se ejecuta después de rechazar paths absolutos y componentes `..`. | No confirmado como traversal. |
| 19 | `frozen_snapshot.py:74` | Segundo flujo al mismo `path`; además se rechazan symlinks y archivos no regulares. | No confirmado. |
| 20 | `frozen_snapshot.py:76` | `stat()`/`sha256_file()` sólo verifican el archivo manifestado, tras validación de path, tamaño y symlink. | No confirmado. |
| 21 | `hash_utils.py:22` | `sha256_file()` es una primitive genérica que acepta `Path`; sus callers auditados le pasan paths ya validados. | Hardening potencial, no vulnerabilidad remota demostrada. |
| 22 | `android_forensics.py:777` | CodeQL ve `gmail.com` dentro de `name.lower()` como substring URL; aquí `name` es el nombre de una cuenta Android y la comparación es detección forense. | Falso positivo semántico. |
| 23 | `api.py:650–663` ← source `cli.py:605–606` | `compute_case_audit()` captura `str(exc)` en `report["error"]`; `get_case()` devuelve el reporte de auditoría. Experimento controlado observó un path `/tmp/.../manifest.json` en ese campo. | Confirmado como exposición de detalle interno; no se observó stack trace completo ni secreto. |
| 24 | `api.py:673` ← source `cli.py:605–606` | El mismo `report["error"]` llega a `_audit_status_payload()` desde `get_case_audit()`. Es un segundo sink HTTP del mismo defecto, no un hallazgo independiente. | Confirmado como misma clase; corregir junto con 23. |
| 25 | `audit_chain.py:174` | `tempfile.mktemp()` separa nombrar y crear la base SQLite; existe una ventana de carrera para otro proceso local con acceso al directorio. | Code fact; candidato de hardening local, impacto remoto no demostrado. |

## Threat model

El atacante puede enviar `case_id`, preguntas y requests a la API pública, y
puede suministrar evidencia/cases si la instalación le concede acceso a ese
flujo. No puede modificar el código, el filesystem del servidor fuera de los
inputs autorizados, la imagen desplegada ni los secretos del operador.

El CLI también acepta paths del operador. Un path arbitrario elegido por el
propietario de la máquina no es automáticamente una vulnerabilidad remota:
para clasificarlo como tal habría que demostrar que un atacante remoto puede
controlar ese argumento o que el proceso cruza una frontera de privilegios.

## A1 — detalles de excepciones en respuestas

**Alertas:** [23](https://github.com/annatchijova/zaynor/security/code-scanning/23),
[24](https://github.com/annatchijova/zaynor/security/code-scanning/24).  
**Nivel:** CODE FACT; PLAUSIBLE HYPOTHESIS de impacto informativo.  
**Bucket:** vulnerabilidad potencial de information exposure, no todavía una
demostración de acceso a secretos.

### Evidencia

En `src/zaynor/api.py`, `/cases/{case_id}/evidence` construye un mensaje con
`f"... {exc}"` cuando falla la revalidación del snapshot. El endpoint de
descarga de reportes hace lo mismo para `ReportError`. El texto puede incluir
nombres de paths, nombres relativos de evidencia y detalles internos del
renderer.

La API tiene una ruta positiva importante: el handler genérico de errores y
la ruta de narración ya convierten excepciones inesperadas en mensajes
genéricos. Por eso no corresponde afirmar que hay stack trace completo o
secrets expuestos sin ejecutar cada ruta.

### Predicción y siguiente prueba

Predicción: una entrada que fuerce `FrozenSnapshotError` o `ReportError`
produce un body HTTP que contiene el detalle interno. La prueba debe usar un
case de fixture controlado, comparar el body observado con el mensaje
genérico esperado y repetirla con un path sensible simulado.

La inducción confirma el detalle en el payload de auditoría. No se ejecutó aún
un servidor HTTP completo ni se demostró exposición de secretos; el alcance
confirmado es información de filesystem/implementación.

### Fix completo

Las respuestas públicas deben conservar códigos estables y mensajes seguros;
los detalles completos deben ir sólo al log estructurado con request ID. La
corrección debe cubrir todos los `ApiError(..., str(exc), ...)`, no sólo los
dos lugares que CodeQL reportó.

## A2 — nombre temporal predecible

**Alerta:** [25](https://github.com/annatchijova/zaynor/security/code-scanning/25).  
**Nivel:** CODE FACT; PLAUSIBLE HYPOTHESIS de carrera local.  
**Bucket:** vulnerabilidad potencial en tooling, no incidente del servidor.

`docs/skills/tamper-evident-audit-chain/scripts/audit_chain.py` usa
`tempfile.mktemp(suffix=".db")` en su bloque `__main__` y luego abre SQLite
con ese path. `mktemp()` separa la elección del nombre de la creación: otro
proceso con acceso al mismo directorio podría crear o reemplazar el archivo
entre ambas operaciones.

El bloque es un demo/manual script, no una ruta importada por la API según la
superficie revisada. Por eso el impacto demostrado es local y acotado. La
remediación correcta es `NamedTemporaryFile(delete=False)` o `TemporaryDirectory`
con creación exclusiva y cleanup, más una prueba de carrera si el script se
considera operativo.

## A3 — las 21 alertas de path injection

### Observaciones del scanner

Los reportes apuntan a:

- `src/zaynor/api.py`: paths derivados de `case_id`.
- `src/zaynor/audit_log.py`: paths derivados de casos y logs.
- `src/zaynor/cli.py`: paths de fixtures, roots, casos y reportes.
- `src/zaynor/frozen_snapshot.py`: paths derivados de entries del manifest.
- `src/zaynor/hash_utils.py`: `sha256_file(path)`.

### Controles observados

- La API valida `case_id` con `_SAFE_CASE_ID` antes de construir paths.
- El CLI valida el mismo identificador en `analyze` y `audit`, y
  `case_freezer.freeze_case` también lo valida.
- `_fixture_path` y `_directory_path` rechazan componentes symlink, exigen
  archivo/directorio regular y aplican límites donde corresponde.
- `_validated_entries` rechaza paths absolutos, `..`, symlinks, entries
  faltantes y discrepancias de tamaño/hash; además compara el inventario
  completo.
- `AuditLog` rechaza symlinks y limita el tamaño del log antes de parsearlo.

### Clasificación

En esas rutas, el salto desde “dato usado para formar un path” hasta
“path traversal explotable por un atacante remoto” **no quedó confirmado**:
la revisión del flujo encontró guards de frontera en los consumidores
relevantes. La
alertas son útiles como recordatorio de que `Path(user_value)` es sensible,
pero no justifican 21 fixes puntuales ni severidades independientes.

`sha256_file()` sigue siendo una primitive de filesystem que acepta un path
arbitrario por diseño; sus callers revisados le pasan paths ya validados. Si
la función se expone en una herramienta MCP o endpoint con un path controlado
por red, la clasificación cambia y debe volver a probarse.

## A4 — sanitización URL

**Alerta:** [22](https://github.com/annatchijova/zaynor/security/code-scanning/22).  
El finding reporta `vendor/vigia_engine/vigia/sift/android_forensics.py:777` y
describe `gmail.com` como substring de una URL sanitizada. En el HEAD actual,
esa ubicación es `"gmail.com" in name.lower()` al extraer cuentas Android.
`name` es un dato forense y la comparación intencionalmente busca cuentas
Gmail; no decide si una URL es segura ni habilita una navegación. La alerta es
un falso positivo semántico del modelado de CodeQL y no debe recibir un fix
de sanitización URL.

## Vectores descartados durante esta ronda

| Vector | Resultado | Motivo |
|---|---|---|
| `../` en API `case_id` | No confirmado en la prueba de boundary | regex `_SAFE_CASE_ID` bloquea separadores y caracteres fuera del conjunto permitido. |
| symlink en evidencia o log | No confirmado en rutas revisadas | hay checks explícitos antes de leer/escribir y revalidación del inventario. |
| path absoluto/`..` dentro del manifest | No confirmado | `_validated_entries` lo rechaza antes de `sha256_file` o snapshot. |
| stack trace genérico desde narración | No confirmado como exposición directa | el handler captura excepciones inesperadas y devuelve `internal server error`; debe probarse por endpoint, no generalizarse. |
| URL sanitization en la línea alertada | Falso positivo semántico | el código actual trata un nombre de cuenta como señal forense, no como URL. |

## Cobertura no realizada

- No se probaron endpoints desplegados ni se usaron credenciales de usuario.
- No se ejecutó una corrida CodeQL nueva contra `591083e`.
- No se pudo consultar Secret Scanning porque GitHub reporta esa función
  deshabilitada para el repositorio.
- No se auditó todavía la superficie completa de `vigia-repo` ni `annaconda`;
  eso queda para la comparación posterior, antes de copiar cualquier fix.
- El working tree local de ZAYNOR ya tenía modificaciones y archivos no
  trackeados preexistentes; este informe no los incorpora ni los evalúa como
  parte de un diff propio.

## Orden recomendado antes de resolver

1. Reproducir A1 con TestClient/fixture y enumerar todos los lugares donde un
   `ApiError` expone `str(exc)`.
2. Reemplazar `mktemp()` en el script y agregar regresor sólo si el script se
   considera soportado.
3. Ejecutar CodeQL nuevamente contra el HEAD actual para retirar alertas stale
   y confirmar si queda algún path injection sin guard.
4. Comparar luego las primitives y callers equivalentes en `vigia-repo` y
   `annaconda`; la comparación debe preservar el nivel epistemológico y no
   convertir una similitud textual en una vulnerabilidad confirmada.
