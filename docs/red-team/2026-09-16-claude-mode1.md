# Informe Red Team — commits locales de Claude

**Fecha:** 2026-09-16  
**Método:** abductive engineering (abducción → deducción → inducción) + red-team auditing  
**Alcance:** únicamente `eb027a0` (`vigia_mode1_executor.py` y sus tests) y `27fa9ab` (matriz/documentación de Phase 0). No se auditaron ni modificaron ramas o worktrees de otros autores.  
**Base auditada:** `main` @ `27fa9ab`, local y todavía no publicado en `origin/main`.

## Modelo de amenaza

El atacante puede controlar valores entregados por la API local, incluyendo el
archivo de salida, o provocar que el proceso externo entregue un bundle
malformado o inconsistente. No puede modificar el código de ZAYNOR, romper
SHA-256 ni alterar el kernel. Cuando se habla de bundle falso, el precondicionante
es que VIGÍA o el canal entre procesos esté defectuoso o comprometido; no se
afirma que un atacante que sólo controla la evidencia pueda falsificar el hash.

## Leyenda epistemológica

`CODE FACT` = observable leyendo el código; `PLAUSIBLE HYPOTHESIS` = mecanismo
posible aún no ejecutado; `CONFIRMED BY INDUCTION` = predicción ejecutada y
observada; `FALSIFIED` = el experimento no produjo el efecto predicho.

## Resumen ejecutivo

| ID | Severidad demostrada | Nivel | Área | Hallazgo |
|---|---|---|---|---|
| RT-CLAUDE-001 | Alta si el destino es controlable por un usuario no confiable | CONFIRMED BY INDUCTION | salida | Se siguen symlinks al copiar el bundle y se puede sobrescribir otro archivo accesible. |
| RT-CLAUDE-002 | Media/Alta | CONFIRMED BY INDUCTION | integridad | El sidecar y `evidence_sha256` no se verifican antes de aceptar el resultado. |
| RT-CLAUDE-003 | Media | CONFIRMED BY INDUCTION | autoridad | Exit code y `agent_verdict` pueden contradecirse y ambos se aceptan. |
| RT-CLAUDE-004 | Media | CONFIRMED BY INDUCTION | determinismo | El timestamp de ejecución entra en el resultado autoritativo. |
| RT-CLAUDE-005 | Media | CONFIRMED BY INDUCTION | contrato | Se aceptan veredictos arbitrarios y estados de VIGÍA que no son el contrato canónico de ZAYNOR. |
| RT-CLAUDE-006 | Media | CONFIRMED BY INDUCTION | recursos | stdout/stderr se acumulan sin límite. |
| RT-CLAUDE-007 | Baja/Media | CONFIRMED BY INDUCTION | errores | Un timeout escapa como `subprocess.TimeoutExpired`, fuera del contrato `Mode1ExecutionError`. |
| RT-CLAUDE-008 | Media como bloqueo funcional | CODE FACT + ejecución real | traducción | El traductor siempre devuelve cero findings; la ejecución observada sólo produjo `ABSTAIN`, `0 signals` y `NO_ARTIFACTS`. |
| RT-CLAUDE-009 | Media como debilidad de verificación | CODE FACT | tests | La integración se saltea si no existe un path absoluto local de VIGÍA. |

## Hallazgos

### RT-CLAUDE-001 — El destino de salida no está confinado ni protegido contra symlinks

**Bucket:** vulnerabilidad.  
**Nivel:** `CONFIRMED BY INDUCTION` bajo el modelo donde el atacante puede
controlar `output_path` o preparar ese path.

**Impacto:** el proceso puede sobrescribir un archivo elegido por el atacante
con los permisos del proceso que ejecuta ZAYNOR.

**Abducción:** la copia final usa `shutil.copy2(internal_output, output_path)`
sin comprobar que el destino sea un archivo regular ni que no sea un symlink.

**Predicción:** si `output_path` apunta mediante symlink a `target`, ejecutar
Mode 1 debe modificar `target`.

**Inducción:** se ejecutó un agente de prueba aislado que produjo un bundle
válido y se apuntó la salida a un symlink. `target` fue sobrescrito.

**Invariante:** la salida sólo debe escribirse en el archivo regular autorizado
por el caller, sin seguir enlaces ni escapar el destino permitido.

**Corrección completa:** validar la política de destino y crear/reemplazar el
archivo de forma segura, rechazando symlinks en toda la ruta relevante.

### RT-CLAUDE-002 — Se acepta una afirmación de integridad sin verificarla

**Bucket:** vulnerabilidad de frontera de confianza.  
**Nivel:** `CONFIRMED BY INDUCTION` bajo el modelo donde el bundle o el canal
externo puede ser incorrecto o manipulado.

**Impacto:** ZAYNOR puede trasladar a su resultado autoritativo un hash de
evidencia falso o un sidecar incorrecto.

**Predicción:** un agente que escriba `evidence_sha256: "not-the-evidence"` y
un sidecar incorrecto debe ser aceptado.

**Inducción:** ambos valores fueron aceptados; el executor no calcula el hash
del contenido, no compara el sidecar con los bytes y tampoco exige sidecar.

**Invariante:** el hash reportado debe ser el hash calculado sobre exactamente
la evidencia congelada, y el sidecar debe coincidir con el bundle copiado.

**Corrección completa:** verificar el manifiesto de caso contra `evidence_dir`,
calcular el digest del bundle, validar estrictamente el formato del sidecar y
rechazar cualquier discrepancia o ausencia.

### RT-CLAUDE-003 — El código de salida no autentica el veredicto del bundle

**Bucket:** vulnerabilidad de autoridad.  
**Nivel:** `CONFIRMED BY INDUCTION` bajo el modelo donde el proceso externo
puede producir una salida inconsistente.

**Predicción:** un proceso que termina con código `0` pero escribe
`agent_verdict: MALICE` debe ser aceptado, aunque el código documenta `0` como
`NOISE`.

**Inducción:** ocurrió exactamente eso. El bundle fue devuelto como válido.

**Invariante:** el veredicto derivado del exit code y el veredicto sellado en
el bundle deben coincidir; cualquier contradicción debe fallar cerrado.

**Corrección completa:** parsear y validar el bundle, derivar el estado desde
una única fuente de autoridad y rechazar contradicciones antes de traducir.

### RT-CLAUDE-004 — El resultado autoritativo no es determinista

**Bucket:** vulnerabilidad de especificación/integridad de decisión.  
**Nivel:** `CONFIRMED BY INDUCTION`.

`translate_mode1_bundle()` copia `analysis_timestamp` a `integrity`. Dos
bundles idénticos salvo por el timestamp generaron resultados autoritativos
distintos. Esto viola el requisito del plan: mismo caso congelado, versión y
configuración deben producir el mismo resultado autoritativo.

**Corrección completa:** excluir campos volátiles del objeto autoritativo o
mantenerlos sólo como metadata operacional fuera de la comparación canónica.

### RT-CLAUDE-005 — El traductor no aplica el contrato canónico de estados

**Bucket:** vulnerabilidad de validación de frontera / contrato.  
**Nivel:** `CONFIRMED BY INDUCTION`.

El traductor aceptó `agent_verdict: BOGUS`. Además, los tests aceptan
`NOISE` e `INTENT`, que pertenecen al vocabulario de VIGÍA pero no al conjunto
canónico de ZAYNOR (`MALICE`, `ABSTAIN`, `UNKNOWN`, `BENIGN`, `SUSPICION`).

**Invariante:** ningún estado externo no validado puede convertirse en autoridad
ZAYNOR; toda traducción debe ser explícita, total y auditable.

**Corrección completa:** implementar una tabla de mapeo cerrada, rechazar
estados desconocidos y mapear `NOISE`/`INTENT` según una decisión de producto
documentada, no por aceptación implícita.

### RT-CLAUDE-006 — Salida de subprocess sin límite

**Bucket:** vulnerabilidad de disponibilidad.  
**Nivel:** `CONFIRMED BY INDUCTION`.

`capture_output=True, text=True` acumuló y aceptó 20 MB de stdout de un agente
de prueba. Un proceso externo que emita salida ilimitada puede consumir memoria
del runner antes de que el bundle sea procesado.

**Corrección completa:** usar pipes limitados o redirección acotada a archivos,
con un límite explícito para logs y terminación controlada al excederlo.

### RT-CLAUDE-007 — Timeout no normalizado

**Bucket:** confiabilidad/error de frontera.  
**Nivel:** `CONFIRMED BY INDUCTION`.

Un agente que duró más que `timeout_seconds` produjo `TimeoutExpired`, no
`Mode1ExecutionError`. El caller que sólo maneja el contrato del módulo puede
fallar inesperadamente.

**Corrección completa:** capturar el timeout, terminar el proceso/grupo y
devolver un `Mode1ExecutionError` con contexto acotado.

### RT-CLAUDE-008 — La traducción elimina toda señal investigable

**Bucket:** incumplimiento funcional del plan, no bypass demostrado.  
**Nivel:** `CODE FACT` corroborado por ejecución real.

`translate_mode1_bundle()` retorna siempre `findings=()`, aunque el bundle
contenga `agent_verdict`, hipótesis o señales. La corrida real contra el fixture
actual produjo `ABSTAIN`, `0 signals` y `caie: NO_ARTIFACTS`; por tanto, la
capacidad de timeline/CAIE/MITRE/razonamiento profundo está trazada como
alcanzable, pero todavía no fue observada con señales reales.

**Corrección completa:** traducir sólo estructuras cuya semántica y referencias
de evidencia estén verificadas, y representar explícitamente capacidades
ausentes como `UNKNOWN` sin declarar Phase 0/Mode 1 suficiente para el caso.

### RT-CLAUDE-009 — La prueba de integración puede quedar omitida

**Bucket:** debilidad de verificación.  
**Nivel:** `CODE FACT`.

El módulo completo está marcado `skipif` cuando no existe
`/home/labestiadevigia/vigia-repo/vigia_agent.py`. En otro entorno, una suite
verde no demostraría la integración real. Esto no prueba un exploit, pero sí
una falsa sensación de cobertura.

## Vectores intentados y límites

| Vector | Resultado | Estado |
|---|---|---|
| Symlink en `output_path` | Sobrescritura observada | Confirmado |
| Sidecar incorrecto | Aceptado | Confirmado |
| Hash de evidencia arbitrario | Trasladado al resultado | Confirmado |
| Exit code/veredicto contradictorios | Aceptados juntos | Confirmado |
| Timestamp variable | Resultado distinto | Confirmado |
| Veredicto `BOGUS` | Aceptado | Confirmado |
| stdout de 20 MB | Aceptado y retenido | Confirmado |
| Timeout | `TimeoutExpired` escapó | Confirmado |
| Modificación del código de ZAYNOR | No intentada | Fuera del modelo |
| Falsificación criptográfica de SHA-256 | No intentada | No necesaria para los hallazgos |

## Orden de remediación

1. Cerrar la frontera de salida y la validación de integridad.
2. Normalizar timeout, límites de stdout/stderr y errores de subprocess.
3. Hacer cerrado y explícito el contrato de veredictos.
4. Separar metadata volátil de la autoridad determinista.
5. Implementar la traducción de señales sólo después de verificar su semántica,
   referencias y lineage; mantener `UNKNOWN` cuando falte evidencia.
6. Convertir la integración real en una prueba reproducible por CI, sin depender
   de un path absoluto local.

**Criterio de cierre:** el bundle sólo cruza la frontera cuando su identidad,
integridad, estado y evidencia están verificados; una repetición determinista
produce el mismo resultado autoritativo; y toda capacidad no observada queda
marcada como `UNKNOWN` sin findings inventados.
