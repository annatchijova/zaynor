# Auditoría de seguridad — ZAYNOR

## Red Team Ronda 18 — defectos locales, invariantes y análisis de variantes

**Fecha:** 2026-09-17
**Método:** Ingeniería abductiva (abducción → deducción → inducción) + Red-Team Auditing + Variant Analysis
**Alcance:** todo el repositorio — `src/zaynor/`, `vendor/vigia_engine/`, `tests/`, `docs/`
**Base:** rama `claude/relaxed-goldberg-2c0gbu` @ commit `aa642767b0b582a686a7929d654c7452b090bc95`
**Intérprete de los experimentos:** Python 3.12.3 (`/usr/bin/python3.12`)
**Punto de restauración:** tag `pre-session-20260917-131017`

> **Nota sobre el idioma.** `CLAUDE.md` §0 pide inglés para todo lo que se commitea. Este informe está
> en español por pedido explícito del mantenedor, con el precedente de `LIMITACIONES_CONOCIDAS.md` y
> `docs/red-team/2026-09-16-es.md`. El mensaje de commit va en inglés, según la regla.

---

## 0. Resumen en una página

Se corrieron 14 experimentos de inducción contra el árbol vivo. El resultado honesto:

- **2 vulnerabilidades confirmadas** en `src/zaynor/path_guard.py`, un archivo que **ninguna de las 17
  rondas previas auditó como objetivo**. La principal permite sustituir evidencia después de la
  validación sin que el chequeo TOCTOU lo detecte, y se demostró end-to-end en la herramienta que
  consume el LLM.
- **2 hallazgos confirmados en el motor vendorizado**, en un archivo con cobertura previa cero, que
  convierten dos etiquetas controladas por el input en palancas medibles del score.
- **6 vectores refutados**, incluidos dos que yo mismo había planteado como hallazgos y uno que
  parecía una contradicción flagrante entre un comentario de invariante y el código.

La tesis central del producto —*el sello es correcto y la IA no toca el camino de decisión*— **resistió
todos los intentos de romperla**. `authority_seal._typed()` rechaza floats con `SealError`, chequea
`bool` antes que `int`, y no se encontró forma de que el narrador altere un valor sellado. Lo que sí
se rompió está aguas arriba del sello: **se puede inducir un veredicto equivocado antes de sellarlo**.
Esa distinción es todo el informe, y se sostiene en cada afirmación de aquí en adelante.

---

## 1. Modelo de amenaza

Ningún hallazgo está confirmado en abstracto. Está confirmado **bajo un perfil de atacante declarado**.

| Perfil | PUEDE | NO PUEDE |
|---|---|---|
| **A — Insider de adquisición** | Redactar o alterar el JSON del caso y sus artefactos **antes** del freeze | Modificar código; tocar nada después del sellado |
| **B — Autor de artefacto** | Escribir el texto dentro de un log, ticket o nota que ZAYNOR ingiere | Tocar campos estructurales del caso |
| **C — Local post-freeze** | Escribir en el filesystem de evidencia durante o después del análisis | Leer la clave HMAC; modificar código |
| **D — Backend LLM hostil** | Devolver output arbitrario desde Ollama | Ejecutar código fuera de lo que ZAYNOR le permita |

**Precondición transversal declarada:** el perito está cansado y confía en lo que la pantalla le
muestra. Un control que solo funciona si el perito audita manualmente cada byte no cuenta como
mitigación.

---

## 2. Leyenda epistémica

| Nivel | Qué significa | Qué lo gana |
|---|---|---|
| `CODE FACT` | Observable directamente en el fuente | Leer el código |
| `HIPÓTESIS PLAUSIBLE` | Abducción con evidencia arquitectónica, **no ejecutada** | Razonar desde el código |
| `CONFIRMADO POR INDUCCIÓN` | Predicción deducida, ejecutada y observada | Experimento reproducible con before/after |
| `REFUTADO` | La predicción se ejecutó y **no** se cumplió | El mismo experimento, en negativo |

Cada hallazgo se clasifica además en exactamente un balde: **vulnerabilidad**, **supuesto del modelo
de amenaza** o **higiene**. Solo el primero lleva severidad propia.

---

## 3. Resumen ejecutivo

| ID | Sev. | Nivel | Balde | Módulo | Hallazgo |
|---|---|---|---|---|---|
| **Z18-01** | Alta | CONFIRMADO POR INDUCCIÓN | vulnerabilidad | `path_guard.py:150-200` | El chequeo TOCTOU solo cubre los primeros 4096 bytes: se sustituye contenido de evidencia sin detección |
| **Z18-02** | Media | CONFIRMADO POR INDUCCIÓN | vulnerabilidad | `path_guard.py:203-240` | `safe_open` no liga el descriptor al inode validado — fix incompleto de la ronda 7 |
| **Z18-03** | Alta | CONFIRMADO POR INDUCCIÓN | vulnerabilidad | `vigia_integration_bridge.py:409-430` | `peirce_layer` y `forensic_anomalies` son palancas de score controladas por el input |
| **Z18-04** | Media | CONFIRMADO POR INDUCCIÓN | vulnerabilidad | `vigia_integration_bridge.py:419-439` | Dos defaults silenciosos divergentes producen un estado que ninguna etiqueta válida genera |
| **Z18-05** | Baja | CONFIRMADO POR INDUCCIÓN | higiene | `vigia_integration_bridge.py:430-439` | Float en el camino de decisión (no en el sello), contra el docstring de `:330-331` |
| **Z18-06** | Baja | CODE FACT | higiene | `vigia_integration_bridge.py:357-360`, `:465-469` | El normalizador fabrica metadata de provenance para artefactos legacy |
| **Z18-07** | Baja | CONFIRMADO POR INDUCCIÓN | higiene | `hmac_chain.py:58` | `.strip()` colapsa claves que difieren solo en whitespace final |

Severidad = impacto sobre la promesa del producto bajo el perfil declarado, no CVSS.

---

## 4. Hallazgos

### Z18-01 — El chequeo TOCTOU verifica 4 KiB de un archivo que lee entero

**Severidad:** Alta · **Nivel:** CONFIRMADO POR INDUCCIÓN · **Balde:** vulnerabilidad
**Perfil:** C (escritura local durante el análisis)
**Ubicación:** `src/zaynor/path_guard.py:150-157` (producción del testigo) y `:195-200` (comparación)
**Alcanzado desde:** `src/zaynor/tools.py:180`, `:219`, `:266`

#### Sorpresa

`PathGuard` declara en su docstring (`path_guard.py:41-47`) que protege contra *"TOCTOU
(time-of-check to time-of-use)"*. `safe_read` lee el archivo **completo**. Pero el testigo con el que
después compara se construye sobre **4096 bytes**:

```python
# path_guard.py:150-155
hash_prefix = ""
if size > 0 and not stat.S_ISDIR(st.st_mode):
    try:
        with abs_path.open("rb") as handle:
            prefix = handle.read(4096)          # <-- solo el prefijo
        hash_prefix = hashlib.sha256(prefix).hexdigest()[:16]
```

`verify_no_toctou` compara inode, size, mtime y ese prefijo. Ninguno de los cuatro observa el
contenido más allá del byte 4096.

#### Abducción — hipótesis rivales, ordenadas por economía de investigación

1. *(benigna, se testeó primero)* El prefijo es solo una optimización y hay otro control aguas abajo
   que cubre el archivo completo — el hash del manifest, o el re-hasheo post-ejecución de
   `zaynor_mode1_executor.py:284`.
2. El prefijo es el único testigo de contenido, y la ventana >4096 bytes es un punto ciego real.

La rival 1 es la que había que matar. Se la mató parcialmente: el re-hasheo post-ejecución de Mode 1
(`C12`, ronda 3 — `zaynor_mode1_executor.py:265-267`) **sí** cubre el árbol de evidencia congelado
durante la corrida del subproceso, pero
**no** cubre las lecturas de `ReadOnlyToolRegistry`, que es la superficie que consume el LLM y la
que este hallazgo ataca. La rival 2 sobrevive.

#### Deducción — predicción escrita antes del experimento

> Editar un byte en el offset 5000 de un archivo de 8192 bytes, preservando tamaño e inode y
> restaurando mtime con `os.utime`, hará que `verify_no_toctou` devuelva `valid=True`. La misma
> edición en el offset 100 será detectada.

#### Inducción — ejecutada

```python
target.write_bytes(b"A" * 8192)
check = guard.validate(str(target))
st_before = target.lstat()
with open(target, "r+b") as fh:
    fh.seek(5000); fh.write(b"EVIL")
os.utime(target, ns=(st_before.st_atime_ns, st_before.st_mtime_ns))
use = guard.verify_no_toctou(str(target), check)
```

```
OBSERVADO: valid=True reason=VALID | inode_same=True content_changed=True
CONTROL  : edit at offset 100 -> valid=False reason=TOCTOU_CONTENT_CHANGED
```

El control es la parte importante: el mecanismo funciona **dentro** de los primeros 4096 bytes, lo
que prueba que el punto ciego es exactamente la ventana y no un error del experimento.

#### Inducción end-to-end — en el borde real del producto

No alcanza con romper el guard: hay que mostrarlo en la herramienta que el LLM y el perito usan. Se
construyó un `auth.log` cuya línea incriminatoria cae después del byte 4096 (un `auth.log` real llega
ahí en algunas decenas de líneas), y se la sustituyó por una exculpatoria de **la misma longitud**:

```
PREDICT: _read_evidence returns success=True with the EXCULPATORY line,
         i.e. the tampered bytes, and no TOCTOU REJECT.

  BEFORE  success=True
          sha256=315f0335dcef1539e50f5a8e843e887b754a5636d3a6b85dd33ceafd358690d1
          incriminating_line_present=True
```

Sustitución bajo perfil C — misma longitud, mismo inode, mtime restaurado:

```
Sep 17 09:14:22 ... sshd[2048]: ACCEPTED publickey for root from 203.0.113.77
                    ->
Sep 17 09:14:22 ... sshd[2048]: FAILED   password for guest from 10.0.0.9
```

El experimento confirma que `ReadOnlyToolRegistry.read_evidence` devuelve `success=True` con los
bytes sustituidos y **sin** `TOCTOU REJECT`, y que la misma edición dentro de los primeros 4096 bytes
sí es rechazada (control). El `sha256` reportado cambia — es el hash de lo que efectivamente se
leyó— pero el control que debía certificar que esos bytes son los validados no dispara.

#### Cadena causal

```
atacante con escritura local (perfil C)
    ↓ edita in-place más allá del offset 4096, misma longitud
inode sin cambios · size sin cambios · mtime restaurado con os.utime
    ↓
hash_prefix (SHA-256 de los primeros 4096 B, truncado a 16 hex) sin cambios
    ↓
verify_no_toctou compara los 4 testigos -> los 4 coinciden
    ↓
safe_read / _read_evidence / _grep_pattern devuelven success=True
    ↓
el LLM y el perito leen evidencia sustituida, marcada como TOCTOU-verificada
```

#### Por qué esto es nuevo (prior art)

Es una **variante residual del fix de la ronda 7, RT-08** (`C25`). Aquel hallazgo era: *"`generate_forensic_hash`
validaba y después re-abría por nombre"*. El fix movió los tres call sites a
`guard.safe_open()` + `guard.verify_no_toctou()` (`tools.py:259,266`), tratando a `PathGuard` como
componente confiable. **`PathGuard` nunca fue auditado como objetivo por ninguna de las 17 rondas.**
El fix es correcto en su nivel y queda anulado en el nivel de abajo: los tres call sites corregidos
heredan el mismo punto ciego.

#### El arreglo ya existe en este repositorio

`src/zaynor/sandbox.py` resuelve el mismo problema bien: `hash_evidence` (`:105`) y `read_evidence`
(`:120`) hashean el **stream completo** en bloques de 1 MiB (`sandbox.py:113` y `:125`), no un
prefijo. Dos
implementaciones del mismo invariante, una correcta y una con punto ciego. La recomendación no es
diseñar nada nuevo: es alinear `verify_no_toctou` con el criterio que `sandbox.py` ya aplica.

---

### Z18-02 — `safe_open` no liga el descriptor al inode que validó

**Severidad:** Media · **Nivel:** CONFIRMADO POR INDUCCIÓN · **Balde:** vulnerabilidad (latente)
**Perfil:** C · **Ubicación:** `src/zaynor/path_guard.py:203-240`

`safe_open` valida, y después **reabre por nombre**:

```python
check = self.validate(path_str)          # :208  — obtiene check.inode
...
fd = os.open(str(p), flags)              # :216  — reabre por nombre
st = os.fstat(fd)
if not stat.S_ISREG(st.st_mode):         # :219  — verifica el TIPO
```

El `fstat` verifica que sea un archivo regular, pero **nunca compara `st.st_ino` contra
`check.inode`**. `O_NOFOLLOW` cubre el último componente del path, no los intermedios ni la identidad
del archivo.

> **Predicción:** sustituir el archivo por otro regular entre `validate()` y `safe_open()` no produce
> excepción y devuelve el contenido sustituido.

```
OBSERVADO: raised=None content=b'SUBSTITUTED' inode_changed=True
```

**Honestidad sobre el impacto.** Por sí solo esto **no** es explotable hoy: los tres call sites de
`tools.py` llaman después a `verify_no_toctou`, que **sí** compara inode y detecta este caso concreto.
El hallazgo se reporta por dos razones: es exactamente la clase de defecto #1 del catálogo de la ronda
7 (*"un guard valida un path y después lo reabre por nombre en vez de usar el descriptor ya abierto"*)
**todavía presente dentro del guard que aquel fix dio por confiable**, y cualquier llamador futuro que
use `safe_open` sin `verify_no_toctou` queda sin protección alguna. Es un fix incompleto, no una brecha
abierta.

**Variante del mismo patrón:** `sandbox.py:88-99` (`_open_confined`) tiene idéntico faltante — abre con
`O_NOFOLLOW`, verifica `S_ISREG`, no liga el inode validado por `_confined_regular_file`.

---

### Z18-03 — `peirce_layer` y `forensic_anomalies` son palancas de score controladas por el input

**Severidad:** Alta · **Nivel:** CONFIRMADO POR INDUCCIÓN · **Balde:** vulnerabilidad
**Perfil:** A (control del JSON del caso antes del freeze)
**Ubicación:** `vendor/vigia_engine/vigia/pipeline/vigia_integration_bridge.py:409-430`

#### Sorpresa

`_normalize_artifact_legacy` deriva el `raw_score` de dos campos que vienen **del JSON del caso**:

```python
anomalies = art.get("forensic_anomalies", [])                                    # :409
n_anomalies = len(anomalies)                                                     # :412
peirce_layer = str(art.get("peirce_layer", "SECONDNESS")).upper()                # :419
peirce_num = _PEIRCE_WEIGHT_NUM.get(peirce_layer, _PEIRCE_WEIGHT_NUM["SECONDNESS"])  # :420
score_num = n_anomalies * peirce_num * 100 + n_flags * _FLAG_BONUS_PER_FLAG * _PEIRCE_WEIGHT_DEN  # :425
art["raw_score"] = round(score_num / denom, 4)                                   # :430
```

Ninguno de los dos campos se contrasta contra la evidencia: son **anotaciones**, y el motor las trata
como medición.

#### Deducción

> Cambiar solo `peirce_layer`, sin tocar un byte de evidencia, cambiará `raw_score`. Quitar entradas
> de `forensic_anomalies` lo cambiará más.

#### Inducción — deltas medidos

Artefacto base: `peirce_layer: THIRDNESS`, dos anomalías.

| Mutación (solo la etiqueta o la lista) | `raw_score` | Δ |
|---|---|---|
| línea base | 0.95 | — |
| `THIRDNESS` → `SECONDNESS` | 0.90 | −0.05 |
| `THIRDNESS` → `FIRSTNESS` | 0.80 | −0.15 |
| 2 anomalías → 1 | 0.50 | −0.45 |
| 2 anomalías → 0 | **0.05** | **−0.90** |

Quitar dos strings de una lista lleva el artefacto de 0.95 a 0.05 — el piso del clamp.

#### Alcanzabilidad — trazada, no supuesta

ZAYNOR no llama al bridge directamente (grep sobre `src/` no encuentra ninguna referencia). La cadena
real es:

```
zaynor_mode1_executor.run_vigia_mode1
  -> subprocess: vigia_agent.py --evidence <caso> --case-id <id>
     -> from sift_orchestrator import SIFTOrchestrator
        -> sift_orchestrator.py:1246  normalize_case_schema(raw_case_data)
```

Y `adapter.py:143 _evidence_path_for_mode1` rutea precisamente un `*.json` suelto hacia ese camino
(ese ruteo es el fix `C30` de la ronda 11). Los `casos/*.json` del repo tienen exactamente esta forma.

#### Precisión de lenguaje — qué se demostró y qué no

Lo demostrado es que **un campo de anotación controlado por el input mueve el input del scoring**, con
deltas medidos. **No se ejecutó el pipeline completo hasta el veredicto sellado**, porque requiere el
binario de Mode 1 corriendo end-to-end. Por lo tanto:

- `raw_score` cambia por relabeling → **CONFIRMADO POR INDUCCIÓN**.
- *"el veredicto sellado cambia"* → **HIPÓTESIS PLAUSIBLE**, no confirmada. Es plausible por la
  magnitud del delta (0.95 → 0.05 cruza cualquier umbral razonable), pero plausible no es confirmado.

Y la formulación correcta, la que resiste a un contrainterrogatorio: **no se manipuló un veredicto
sellado; se envenenó el input del que un veredicto se deriva antes de sellarse.** El sello funciona
perfectamente y certificaría el resultado envenenado con una cadena de custodia impecable.

#### Prior art

La afirmación arquitectónica general —*se puede sellar válidamente un veredicto equivocado; el sello
es integridad, no verdad*— ya está registrada en `docs/red-team/2026-09-17-unified-audit.md`
(F11-architectural). Lo nuevo acá es la instancia concreta y medida: **ningún documento de red-team
menciona `vigia_integration_bridge`, `peirce_layer` ni `forensic_anomalies`.** La razón está
documentada: `AGENTS.md` §2.1 ("nunca parchear VIGÍA") mantuvo esta superficie fuera de alcance. Una
regla de no-modificación es una razón válida para no parchear; no es una razón para no auditar.

---

### Z18-04 — Dos defaults silenciosos divergentes para el mismo concepto

**Severidad:** Media · **Nivel:** CONFIRMADO POR INDUCCIÓN · **Balde:** vulnerabilidad
**Perfil:** A · **Ubicación:** `vigia_integration_bridge.py:419-420` y `:433-439`

Una `peirce_layer` no reconocida se resuelve **dos veces, con criterios distintos**:

```python
peirce_num = _PEIRCE_WEIGHT_NUM.get(peirce_layer, _PEIRCE_WEIGHT_NUM["SECONDNESS"])  # :420 -> 9/10
art["prior_trust"] = {"FIRSTNESS": 0.70, "SECONDNESS": 0.85,
                      "THIRDNESS": 0.90}.get(peirce_layer, 0.75)                      # :439 -> 0.75
```

> **Predicción:** una etiqueta basura será aceptada silenciosamente y tratada como `SECONDNESS`.

```
OBSERVADO: garbage peirce_layer -> accepted, raw_score=0.9  prior_trust=0.75
CONTROL  : SECONDNESS legítimo   -> raw_score=0.9  prior_trust=0.85
```

La predicción se cumplió **a medias, y el matiz es peor que la hipótesis**: la etiqueta inválida hereda
el *peso* de `SECONDNESS` (0.9) pero un `prior_trust` de 0.75 que **ninguna de las tres capas válidas
produce**. Un typo en el JSON del caso no se rechaza: crea una cuarta pseudo-capa sin nombre, con una
combinación de parámetros que el diseño no contempla y que nadie declaró nunca.

Es la clase de defecto #7/#8 del catálogo de rondas previas (*"vocabulario cerrado con default
permisivo"*), aplicada a un vocabulario que además tiene dos tablas desincronizadas.

---

### Z18-05 — Float en el camino de decisión (pero **no** en el sello)

**Severidad:** Baja · **Nivel:** CONFIRMADO POR INDUCCIÓN · **Balde:** higiene
**Ubicación:** `vigia_integration_bridge.py:430` y `:433-439`

```
types: raw_score=float  prior_trust=float
```

Lo que vuelve nítido a este hallazgo es que **el código contradice el docstring de su propia
función**. `_normalize_artifact_legacy` declara en `:330-331`:

> *"raw_score se calcula como entero / denominador para garantizar determinismo bit-a-bit **sin
> floating point**"*

La aritmética del numerador efectivamente es entera y el clamp también (`:425-429`, con `//`). Pero
la última línea, `:430`, hace `round(score_num / denom, 4)` — división verdadera, o sea float — y
`prior_trust` (`:433-439`) es directamente un literal float. La garantía escrita se cumple hasta la
anteúltima línea y se pierde en la última.

`CLAUDE.md` §5.2 es explícito en el mismo sentido: *"No float in the decision path... Floats are
allowed only in the cosmetic narrative layer, never in a value that gets sealed."* Ambos valores
alimentan el scoring, que es el camino de decisión por definición.

**Ahora la parte que un informe inflado omitiría.** Esto **no** rompe el determinismo:

1. El sello **falla cerrado** ante floats. Verificado:
   ```
   authority_seal._typed(0.95)              -> SealError: float is not allowed in the authoritative payload
   authority_seal._typed({'raw_score':0.95}) -> SealError: float is not allowed in the authoritative payload
   ```
   Y `_typed` chequea `bool` **antes** que `int` (`authority_seal.py:34`), tal como §5.2 exige.
2. `int / int` bajo IEEE-754 está exactamente especificado, y `round(x, 4)` es determinista. Mismo
   input → mismo `raw_score`, en esta y en cualquier otra plataforma IEEE-754.

Entonces el hallazgo real es lo que es: una **violación de política y una pérdida de precisión
auditable** en un motor cuyo `_math_utils.py` declara en su propia cabecera que mantiene `Fraction`
internamente y convierte a float solo en el último paso. Acá la conversión ocurre antes de ese último
paso. No es una fractura de determinismo, y decir que lo es sería exactamente el tipo de
sobreafirmación que esta ronda intenta evitar.

---

### Z18-06 — El normalizador fabrica metadata de provenance

**Severidad:** Baja · **Nivel:** CODE FACT · **Balde:** higiene
**Ubicación:** `vigia_integration_bridge.py:357-360` y `:465-469` (el mismo bloque, duplicado en las
dos ramas del normalizador: artefacto ya canónico y artefacto legacy)

Para artefactos legacy sin metadata de adquisición, el normalizador la inyecta. El artefacto de
salida del experimento contiene:

```json
{"acquisition_timestamp": "2020-01-01T00:00:00Z",
 "acquisition_tool": "legacy_converter_v1",
 "examiner_id": "legacy_dataset_converter", ...}
```

El comentario que acompaña al bloque afirma: *"Defensa Daubert: se codifica provenance CONOCIDA, no se
inventa metadato."* El `acquisition_hash` sí es un SHA-256 real del contenido, así que la
afirmación es cierta para ese campo. Pero `acquisition_timestamp: 2020-01-01T00:00:00Z` y
`examiner_id: legacy_dataset_converter` son valores sintéticos con forma de cadena de custodia.

No es una vulnerabilidad: el propósito es evitar que el tier de assurance colapse y bloquee cases
legacy, y está comentado. Se reporta porque un campo llamado `examiner_id` en un artefacto forense
tiene un lector humano esperado, y ese lector no tiene forma de distinguir en pantalla un
`examiner_id` real de este placeholder. Bajo la precondición transversal declarada (perito cansado),
eso importa.

---

### Z18-07 — `.strip()` colapsa claves HMAC distintas

**Severidad:** Baja · **Nivel:** CONFIRMADO POR INDUCCIÓN · **Balde:** higiene
**Ubicación:** `src/zaynor/hmac_chain.py:58`

```
key1=b'supersecretkey'  key2=b'supersecretkey'  equal=True
```

Dos archivos de clave distintos (`supersecretkey` y `supersecretkey\n`) resuelven a la misma clave.
Un archivo de clave compuesto solo por whitespace resuelve a `b""`. Es una conveniencia con costo:
reduce el espacio de claves de forma no obvia para quien las genera. No es explotable — un atacante
que puede leer el archivo de clave ya ganó.

---

## 5. Análisis de variantes

**Invariante en una frase:** *toda lectura de un archivo de evidencia se confina con `PathGuard` y se
re-verifica contra un testigo que cubra el contenido completo.*

Se enumeraron **todos** los sinks de lectura de `src/zaynor/`. Los no-hits se registran, no se omiten.

| Sink | Usa PathGuard | Testigo | Resultado |
|---|---|---|---|
| `tools.py:169` `_read_evidence` | sí + `verify_no_toctou` | prefijo 4 KiB | **HIT — Z18-01** |
| `tools.py:213` `_grep_pattern` | sí + `verify_no_toctou` | prefijo 4 KiB | **HIT — Z18-01** |
| `tools.py:259` `generate_forensic_hash` | sí + `verify_no_toctou` | prefijo 4 KiB | **HIT — Z18-01** (variante residual de RT-08) |
| `path_guard.py:250` `safe_read` | sí (es el propio guard) | prefijo 4 KiB | **HIT — Z18-01** |
| `sandbox.py:108` `hash_evidence` | confinamiento propio | **stream completo** | no-hit — implementación correcta, referencia del arreglo |
| `sandbox.py:88` `_open_confined` | confinamiento propio | sin binding de inode | **HIT parcial — Z18-02 (variante)** |
| `hash_utils.py:22` `sha256_file` | no | n/a | no-hit — se invoca bajo el manifest del freeze, con la evidencia ya `chmod 0o500` (`case_freezer.py:152`, fix `C38`) |
| `frozen_snapshot.py:153` | no | digest del snapshot | no-hit — cubierto por `.zaynor_snapshot_<content_sha256>` (fix `C33`, ronda 13) |
| `zaynor_mode1_executor.py:86/106/132/286` | no | re-hash post-ejecución | no-hit — cubierto por `C12` (`:284`, *"evidence changed while Mode 1 was running"*) |
| `ebs_artifact_scorer.py:129` | no | `_zaynor_source_records_sha256` | no-hit — cubierto por `C14` / `verify_ebs_freshness` |
| `cli.py:383/392` | no | hash del bundle + sidecar | no-hit — cubierto por `C07` |
| `replay.py:38` | no | n/a | no-hit — fixture de demo, fuera del camino autoritativo |
| `audit_log.py:128/219` | no | cadena de hashes propia | no-hit — el log se verifica a sí mismo |

**Lectura del barrido:** 4 hits de la misma familia, todos atribuibles a un único testigo compartido
(`path_guard.py:154`). No es un bug repetido cuatro veces: es un bug en un lugar, heredado por cuatro
llamadores que hicieron lo correcto al confiar en el guard. Arreglar `verify_no_toctou` cierra los
cuatro.

**Segunda familia — defaults silenciosos en vocabulario cerrado** (clase #7/#8 del catálogo previo):
`vigia_integration_bridge.py:419` y `:439` son hits (Z18-04). `zaynor_mode1_executor.py:62,:463`
(`_CANONICAL_VERDICT`) es no-hit: rechaza lo desconocido en lugar de mapearlo a un default benigno —
fue arreglado en los hallazgos `C10`/`C35` y el arreglo se sostiene.

---

## 6. Vectores descartados y refutados

Esta tabla no está vacía a propósito: es la evidencia de que la auditoría fue adversarial y no
confirmatoria. Tres de estas entradas eran hipótesis **mías**, planteadas con confianza y muertas por
el experimento.

| Vector | Resultado | Por qué falló |
|---|---|---|
| **Fuga de etiqueta vía `expected_verdict`** | **REFUTADO** | Mi primera lectura fue *"el comentario de invariante de `:519` se contradice con el código de `:563`"*. Es falso: `:562` lo encierra tras `legacy_benign_reduction`, default `False` (`:505`), y el grep sobre `src/`, `vendor/` y `tests/` no encuentra **ningún** caller que lo pase en `True`. La fuga está en cuarentena y documentada como reproducción histórica. |
| **Symlink colgante evade el chequeo de `path_guard`** | **REFUTADO como vulnerabilidad** | El mecanismo es real: `:93-94` hace `if not parent.exists(): continue`, y `exists()` sigue symlinks, así que un link colgante saltea el `is_symlink()` de `:95`. Pero el resultado observado es `valid=False reason=FILE_NOT_FOUND` — **falla cerrado**. Control: un symlink vivo sí devuelve `SYMLINK_DETECTED_IN_PATH`. CODE FACT sobre el orden del chequeo, impacto de seguridad nulo. |
| **Permisos de la clave HMAC evaluados sobre el symlink** | **REFUTADO** | Un symlink 0777 hacia una clave 0600 es aceptado, pero eso es **correcto**: el kernel ignora los permisos del link, y lo que importa es el target. Control decisivo: con el target en 0666, `resolve_hmac_key()` lanza `ValueError: HMAC key file must not be readable by group or other users`. El control funciona. |
| **`resolve_hmac_key` degrada fail-open ante hex inválido** | **REFUTADO como deshonestidad** | Devuelve `None` en silencio, confirmado. Pero es comportamiento **intencional y testeado** (`test_invalid_hex_key_falls_back_to_file`), y la degradación **sí** se declara en la frontera de verificación: `audit_log.py:281` emite `"hash-only mode: no HMAC anchor on this chain"`. `CLAUDE.md` §5.3 se cumple. Residuo mínimo: no se distingue "clave mal configurada" de "sin clave a propósito". |
| **Float alcanza el payload sellado** | **REFUTADO** | `authority_seal._typed()` lanza `SealError` ante cualquier float, directo o anidado. Falla cerrado. |
| **Colisión de tipos en la canonicalización (`1` vs `"1"` vs `True`)** | **REFUTADO** | El encoder es type-tagged y chequea `bool` antes que `int` (`authority_seal.py:34-35`), exactamente como pide `CLAUDE.md` §5.2. |
| **Tolerancia de mtime de 1 ms como vector independiente** | **REFUTADO** | Subsumido: una edición dentro de los primeros 4096 bytes es detectada por `hash_prefix` aunque el mtime se restaure (control de Z18-01). La tolerancia es defensa en profundidad, no la brecha. |
| **`safe_open` sin binding de inode como brecha abierta** | **DEGRADADO** (ver Z18-02) | Confirmado como CODE FACT y reproducido, pero los tres llamadores actuales lo cubren con `verify_no_toctou`. Se reporta como fix incompleto, no como vulnerabilidad explotable hoy. |
| **`list_dir` TOCTOU entre `iterdir()` y `is_file()`** | **NO EJECUTADO** | Requiere un experimento concurrente que no se corrió. Capado honestamente en HIPÓTESIS PLAUSIBLE. La ronda previa dejó la misma deuda anotada en `es.md:109`. |

---

## 7. Lo que se intentó romper y resistió

Un informe que solo lista fallas no informa sobre el estado del sistema. Estas propiedades fueron
atacadas y aguantaron:

- **El sello es correcto.** Type-tagged, `bool` antes que `int`, rechazo fail-closed de floats,
  versionado. No se encontró forma de producir una colisión ni de sellar un float.
- **La frontera de autoridad del LLM se sostiene.** No se encontró camino por el que el narrador
  escriba un valor sellado.
- **Los fixes de rondas previas siguen en pie.** Se re-verificó la presencia de `C10`/`C35`
  (vocabulario cerrado de veredictos), `C12` (re-hash post-ejecución), `C36`
  (`hmac.compare_digest`), `C38` (`chmod 0o500` del directorio) y `C39` (permisos de clave). Ninguno
  regresó.
- **`PathGuard` acierta en lo difícil.** Allowlist por componente y no por prefijo de texto (`:113-115`
  — `<root>-vecino` no entra), rechazo de `..` antes de normalizar (`:79`), `lstat` por componente,
  `O_NOFOLLOW` + `flock`. El punto ciego de Z18-01 es un error de alcance del testigo, no un diseño
  flojo.

---

## 8. Recomendaciones — solo registradas, no aplicadas

Esta auditoría no modificó una sola línea fuera de `docs/informe/`. La remediación es decisión del
mantenedor.

| Para | Recomendación |
|---|---|
| Z18-01 | Hashear el archivo completo en `validate()`, o mejor: hacer que `safe_read` compare el digest de lo que efectivamente leyó contra un re-hash posterior. `sandbox.py:108-116` ya tiene el patrón correcto; conviene una sola implementación en vez de dos. Si el costo de hashear entero preocupa, el tamaño de la ventana debería al menos ser explícito en el nombre y en el docstring — `verify_no_toctou` promete más de lo que verifica. |
| Z18-02 | Comparar `os.fstat(fd).st_ino` contra `check.inode` dentro de `safe_open`, y aplicar lo mismo en `sandbox.py:_open_confined`. |
| Z18-03 | Decisión de producto, no de código: si `peirce_layer` y `forensic_anomalies` son anotaciones del analista, el resultado debería declarar que su score depende de input no verificado. Si pretenden ser medición, tienen que derivarse de la evidencia. Hoy son lo primero presentado como lo segundo. |
| Z18-04 | Unificar las dos tablas en una sola fuente, y rechazar la etiqueta desconocida en lugar de asignarle un default. |
| Z18-05 | `Fraction` hasta la frontera de presentación, en coherencia con lo que `_math_utils.py` ya declara. |
| Z18-06 | Marcar la provenance sintética con un flag explícito (`provenance_synthetic: true`) para que la UI pueda distinguirla. Es exactamente el patrón `requires_rebuild` que `CLAUDE.md` §5.3 ya prescribe. |
| Z18-07 | Quitar el `.strip()`, o documentarlo en el docstring de `resolve_hmac_key`. |
| Proceso | `AGENTS.md` §2.1 prohíbe **parchear** VIGÍA. Convendría explicitar que no prohíbe **auditarlo**: 17 rondas dejaron el motor que produce el veredicto sin una sola mirada adversarial. |

---

## 9. Reproducibilidad

Los tres bancos de experimentos se corrieron con `python3.12` (3.12.3) contra el commit
`aa642767b0b582a686a7929d654c7452b090bc95`, con el árbol limpio (`git status --short` vacío) y sin
acceso a red. No se instaló ninguna dependencia: el núcleo determinista (`path_guard`,
`authority_seal`, `hmac_chain`, `audit_log`, `tools`) importa con stdlib pura vía
`PYTHONPATH=src`, y el bridge del motor vía `PYTHONPATH=src:vendor/vigia_engine`.

Por pedido del mantenedor, este informe es el único entregable: los scripts de inducción no se
commitean. Cada hallazgo confirmado incluye arriba el fragmento exacto que lo reproduce, con su
predicción escrita antes del resultado observado y su control correspondiente.

**Limitación declarada del entorno:** no hay `pytest` instalado en ningún intérprete y PyPI responde
403, así que **la suite de tests del repositorio no pudo correrse como línea de base**. Ninguna
afirmación de este informe depende de ella: todos los hallazgos se obtuvieron ejecutando el código de
producción directamente. Tampoco se ejecutó el pipeline completo de Mode 1 hasta el veredicto sellado,
razón por la cual Z18-03 mantiene su segunda mitad explícitamente capada en hipótesis.

---

*Las conclusiones de este informe valen exactamente lo que vale su evidencia. Donde se corrió un
experimento, dice qué se predijo y qué se observó. Donde no se corrió, lo dice también.*
