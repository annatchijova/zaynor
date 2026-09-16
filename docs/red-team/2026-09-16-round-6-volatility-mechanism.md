# Auditoría — mecanismo real de memoria/Volatility3 en Mode 1
## Red Team Round 6
**Fecha:** 2026-09-16
**Método:** Abductive Engineering (A-D-I) + Red-Team Auditing.
**Origen:** pedido directo de Anna — "necesito que esté disponible en el
código la integración, VIGÍA tiene con volatility en memory algo así
sift" — verificar que la integración de memoria/Volatility esté
realmente disponible, no sólo documentada como tal.
**Base:** `main` @ `5c2dde4` (antes de este fix). **Evidencia
reproducible:** lectura directa de `/home/labestiadevigia/vigia-repo/
sift_orchestrator.py` (el shim raíz, no `vigia/sift/sift_orchestrator.py`)
y de `vigia_agent.py`; inducción con `subprocess.run(["vol3", ...])`
antes/después del fix.

## Threat model

No aplica un modelo de atacante clásico acá — esta ronda no es sobre
seguridad ofensiva sino sobre **honestidad operacional** (CLAUDE.md §5.3):
¿el sistema, al no poder analizar memoria, lo dice explícitamente, o
produce un resultado que se ve como "memoria limpia" sin serlo? La
frontera de confianza es entre "0 señales porque el dump está limpio" y
"0 señales porque el binario nunca corrió."

## Epistemic legend
CODE FACT · PLAUSIBLE HYPOTHESIS · CONFIRMED BY INDUCTION · FALSIFIED

## Executive summary

| ID | Severity | Level | Module | Finding |
|----|----------|-------|--------|---------|
| R6-1 | Documentation | CODE FACT | `zaynor_mode1_executor.py` (comentario) | El comentario existente afirmaba que la memoria se analiza vía `vigia.sift.memory_forensics.MemoryForensicsEngine.analyze()` — falso; el shim real nunca invoca ese módulo |
| R6-2 | High (degradación silenciosa) | CODE FACT + CONFIRMED BY INDUCTION (fix) | integración ZAYNOR↔VIGÍA (subprocess env) | El binario real de Volatility3 se llama `vol`, pero el mecanismo de resolución de VIGÍA cae a buscar `vol3` en PATH — nombre que no existe en este entorno — produciendo un resultado de memoria vacío sin error visible |

## Findings

### R6-1 — Documentación describía un módulo que Mode 1 nunca invoca

**Severity:** Documentation (ningún comportamiento cambia; el riesgo era
de diagnóstico futuro equivocado) **Epistemic level:** CODE FACT
**Bucket:** hygiene — corrección de un comentario propio, no una
vulnerabilidad.

- **Surprise / expectation violada:** el comentario en
  `zaynor_mode1_executor.py` (escrito en una ronda anterior) afirmaba
  "`sift_orchestrator.py` calls `MemoryForensicsEngine.analyze()`". Al
  releer el shim raíz que `vigia_agent.py` realmente importa (`from
  sift_orchestrator import SIFTOrchestrator` — el archivo en la raíz del
  repo, NO `vigia/sift/sift_orchestrator.py`), su método `analyze()`
  nunca llama a `MemoryForensicsEngine`: la memoria siempre pasa por su
  propio `_analyze_memory_vol3`/`_vol3_run` (subprocess directo `vol -f
  <path> <plugin>`), incluso en la rama de evidencia mixta — el propio
  código del shim documenta por qué: pasar `memory_dump_path` al
  orquestador real duplicaría el conteo de señales de memoria.
- **Abducción:** el comentario anterior fue escrito leyendo
  `vigia/sift/sift_orchestrator.py` (la clase "real", con
  `self.memory = MemoryForensicsEngine`) sin confirmar cuál de los dos
  módulos con el mismo nombre (`sift_orchestrator.py` en la raíz vs.
  `vigia/sift/sift_orchestrator.py`) es el que `vigia_agent.py` importa
  en el camino de ejecución real — exactamente el tipo de error que
  CLAUDE.md §4.1 ("audit before patch — the finding is a claim, not a
  fact") existe para prevenir, aplicado retroactivamente a mi propio
  trabajo anterior.
- **Fix aplicado:** comentario corregido en `zaynor_mode1_executor.py`
  para describir el mecanismo real (shim raíz, `_vol3_run` directo, nunca
  `MemoryForensicsEngine`), con referencia cruzada a `VIGIA_ALLOWED_DUMP_PATHS`
  como allowlist de un módulo que Mode 1 nunca alcanza para memoria (sigue
  seteado por compatibilidad futura, sin efecto práctico hoy en este
  camino).

### R6-2 — `vol` vs `vol3`: el binario real nunca se encontraba

**Severity:** High — degradación silenciosa de una capacidad completa
(análisis de memoria) sin ningún WARN visible, violando CLAUDE.md §5.3
("never emit a result that looks correct" cuando la corrección no puede
garantizarse). **Epistemic level:** CODE FACT + CONFIRMED BY INDUCTION
(reproducido el fallo, luego confirmado el fix) **Bucket:** vulnerabilidad
de integración real, no una hipótesis — verificado corriendo el
subprocess exacto que VIGÍA ejecuta.

- **Surprise / expectation violada:** el pedido de Anna era simple —
  "que esté disponible en el código la integración" — pero al trazar el
  camino completo (no sólo confirmar que `vol --version` corre, que es lo
  que el test anterior hacía), la resolución real del binario dentro de
  `sift_orchestrator.py::_vol3_run` es:
  ```python
  _VOL3 = str(Path(sys.executable).parent / "vol")
  if not Path(_VOL3).exists():
      _VOL3 = "vol3"
  ```
  seguido de `subprocess.run([_VOL3, "-f", memory_path, plugin], ...)`.
- **Causal chain (antes del fix):**
  ```
  python3 (default) resuelve a /usr/bin/python3 dentro del subprocess
      ↓ Path(sys.executable).parent = /usr/bin
  /usr/bin/vol no existe (volatility3 se instaló con
  `pip install --user`, el script de consola queda en ~/.local/bin/vol,
  no junto al intérprete)
      ↓ fallback
  _VOL3 = "vol3"  (nombre de fallback, no "vol")
      ↓
  subprocess.run(["vol3", "-f", <dump>, <plugin>]) — "vol3" NO existe en
  PATH (sólo "vol" existe, instalado por pip como script de consola)
      ↓
  FileNotFoundError, capturado genéricamente dentro de _vol3_run
      ↓
  {"ok": False, "stdout": "", "stderr": str(e), ...} → 0 señales de
  memoria, sin distinguirse de "el dump está limpio"
  ```
- **Abducción:** desajuste de nombre entre el script de consola real que
  `pip install volatility3` genera (`vol`) y el nombre de fallback que
  `sift_orchestrator.py` asume (`vol3`) cuando la heurística
  sibling-of-interpreter falla — un problema de layout de instalación
  (`--user` vs venv), no de VIGÍA mal escrito para el caso común de venv
  con `vol` junto al intérprete.
- **Deducción:** si el mismo entorno (`python3` = `/usr/bin/python3`,
  `vol` instalado sólo en `~/.local/bin`) corre cualquier caso con un
  archivo `.raw`/`.vmem`/`.mem`/`.dmp`, el análisis de memoria debe fallar
  silenciosamente a 0 señales — verificable reproduciendo el subprocess
  exacto sin el fix.
- **Induction (antes del fix):** `subprocess.run(["vol3", "-h"], env=dict(os.environ), ...)`
  levanta `FileNotFoundError` en este entorno — reproducido directamente,
  no inferido.
- **Fix aplicado:** `ensure_vol3_alias_on_path()`, nueva función en
  `zaynor_mode1_executor.py`, crea un symlink `vol3 -> <vol real>` en un
  directorio privado dentro del `run_dir` temporal de esa ejecución de
  Mode 1, y antepone ese directorio a `subprocess_env["PATH"]` — sin
  tocar el `~/.local/bin` real del usuario ni el código de vigia-repo
  (AGENTS.md §2.1: integrar, nunca parchear VIGÍA). Es no-op si `vol3` ya
  resuelve por su cuenta (comprobado con `shutil.which(..., path=
  subprocess_env.get("PATH"))`, explícitamente sobre el PATH que el
  subprocess va a usar, no el del proceso de ZAYNOR).
- **Bug secundario encontrado durante la propia verificación del fix (no
  parte del hallazgo original):** la primera versión de
  `ensure_vol3_alias_on_path` llamaba `shutil.which("vol3")` sin `path=`,
  que por default consulta `os.environ["PATH"]` del proceso actual, no el
  `subprocess_env` que la función está construyendo — un test adversarial
  (`test_vol3_alias_is_a_noop_when_vol3_already_resolves`, que inyecta un
  `vol3` falso sólo en el PATH simulado) lo expuso de inmediato: el falso
  `vol3` de prueba no era detectado, y la función creaba el alias igual,
  pisando el `vol3` que el test esperaba que se respetara. Corregido
  pasando `path=subprocess_env.get("PATH")` a ambas llamadas de
  `shutil.which`.
- **Induction (después del fix):** `python3 -m pytest tests/ -q` → **115
  passed**, incluyendo los 3 tests nuevos de
  `test_memory_forensics_readiness.py`
  (`test_real_vol_binary_is_installed`,
  `test_vol3_alias_makes_vigias_fallback_name_resolve_and_run`,
  `test_vol3_alias_is_a_noop_when_vol3_already_resolves`). El segundo
  reproduce el subprocess exacto de VIGÍA (`vol3 -h`) y confirma que
  ahora corre el binario real (`"usage"` en el stdout de Volatility3
  2.28.0). El tercero confirma que el fix no pisa un `vol3` real si
  alguna vez existiera.
- **Threat-model precondition:** ninguna — esto no requiere un atacante,
  es una falla operacional del layout de instalación que afecta a
  cualquier corrida real de Mode 1 sobre un archivo de memoria en este
  tipo de entorno (`pip install --user`), reproducida y cerrada sin
  necesitar un dump real todavía (eso sigue siendo trabajo separado,
  diferido, per contexto previo).

## Discarded (non-exploitable) vectors

| Vector | Result | Why it failed |
|--------|--------|----------------|
| Parchear `sift_orchestrator.py` (VIGÍA) para que el fallback sea `"vol"` en vez de `"vol3"` | Descartado por diseño, no por prueba | AGENTS.md §2.1 prohíbe modificar/reimplementar VIGÍA; el fix debe vivir del lado de ZAYNOR del límite del subprocess |
| Symlinkear `vol3` directamente en el `~/.local/bin` real del usuario | Descartado por diseño, no por prueba | Modificaría el entorno global del usuario fuera del repo, de forma persistente y no reversible por el propio código — el fix scoped-al-subprocess es equivalente en efecto y estrictamente más seguro |

## Recommendations (fuera de alcance de este cambio — sólo registro)

- Cuando se consiga un memory dump real de Digital Corpora, correr Mode 1
  de punta a punta contra él para confirmar que `_analyze_memory_vol3`
  produce señales reales (pslist/malfind/netscan) más allá de la
  resolución del binario, que es todo lo que esta ronda pudo verificar
  sin un dump.
