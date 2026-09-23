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
| A1 | 23–24 | CODE FACT / PLAUSIBLE | exposición de detalles de excepción | Hay respuestas que interpolan `str(exc)`; impacto demostrado todavía no medido con una instancia HTTP completa. |
| A2 | 25 | CODE FACT / PLAUSIBLE | temporary file inseguro | `tempfile.mktemp()` existe en un script de demostración; es una carrera local, no un RCE demostrado del servidor. |
| A3 | 1–21 | CODE FACT / no confirmado como bypass remoto | path injection | El scanner ve paths derivados de datos; los consumidores revisados validan `case_id`, symlinks, `..`, tipo y tamaño, o son rutas elegidas explícitamente por el operador local. |
| A4 | 22 | FALSIFIED para la ubicación actual | sanitización URL | La ubicación reportada no corresponde al código URL esperado en el HEAD actual; requiere una nueva corrida CodeQL antes de actuar. |

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

**No se ejecutó aún la inducción HTTP completa; el nivel queda limitado a
CODE FACT / PLAUSIBLE.**

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
El finding reporta `vendor/vigia_engine/vigia/sift/android_forensics.py:777`.
En el HEAD actual, esa ubicación corresponde a una comparación de
`"gmail.com" in name.lower()` al extraer cuentas Android, no a una validación
de URL. La instancia es stale o el reporte quedó asociado a una revisión
distinta. No se debe parchear esa línea a ciegas; primero hay que generar un
nuevo análisis CodeQL contra el commit actual.

## Vectores descartados durante esta ronda

| Vector | Resultado | Motivo |
|---|---|---|
| `../` en API `case_id` | No confirmado en la prueba de boundary | regex `_SAFE_CASE_ID` bloquea separadores y caracteres fuera del conjunto permitido. |
| symlink en evidencia o log | No confirmado en rutas revisadas | hay checks explícitos antes de leer/escribir y revalidación del inventario. |
| path absoluto/`..` dentro del manifest | No confirmado | `_validated_entries` lo rechaza antes de `sha256_file` o snapshot. |
| stack trace genérico desde narración | No confirmado como exposición directa | el handler captura excepciones inesperadas y devuelve `internal server error`; debe probarse por endpoint, no generalizarse. |
| URL sanitization en la línea alertada | Stale en el HEAD actual | el código actual de esa línea no procesa URLs. |

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
