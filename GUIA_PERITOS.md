# Guía para peritos — dos caminos de evidencia, comandos reales

Esta guía cubre las dos formas de entrada de evidencia que ZAYNOR sabe
analizar hoy, con comandos probados de verdad (no ilustrativos) para
copiar y pegar. EBS v1 no es un tercer camino de análisis: es una
verificación adicional disponible para los casos JSON del Camino A.
Requiere el repo instalado (`pip install -e .`, ver README.md) — nada de
esto necesita un segundo repositorio ni conexión a internet.

Hay **dos verificadores independientes, no intercambiables**:

- **`zaynor audit`** — verifica la capa propia de ZAYNOR: que el manifest,
  el snapshot de evidencia, el resultado y su sello no fueron alterados
  desde que se generaron. Aplica a **cualquiera** de los dos caminos.
- **`vendor/vigia_engine/forensics/verify_ebs_v1.py`** — verificador
  independiente de VIGÍA (100% stdlib, sin importar código de producción),
  que re-deriva los 4 hashes del *bundle EBS v1* (bundle/graph/policy/
  decision hash). Es un formato de bundle **distinto** al que guarda
  `zaynor analyze` — aplica solo al Camino A (casos JSON), con el script
  auxiliar `scripts/build_ebs_bundle.py`. Ver la sección final.

No son redundantes: uno certifica que la corrida no fue tocada después;
el otro certifica que el bundle es matemáticamente consistente en sí
mismo, sin confiar en el código que lo produjo.

---

## Camino A — casos JSON (`casos/*.json`)

Para evidencia ya estructurada en el formato de caso de VIGÍA (artefactos
con tipo, puntaje, procedencia). El repo ya trae 10 casos reales y
curados en `casos/` — 5 incidentes reales documentados públicamente
(NITROBA, Sony 2014, Target 2013, Colonial Pipeline, Cridex) y 5 del
corpus canónico de VIGÍA.

```bash
# 1. Elegí un caso. Este ejemplo usa el caso real de Nitroba/M57 Patents
#    (DFRWS 2009) — reemplazá el nombre de archivo por el que corresponda.
CASE_FILE="VIGIA-NITROBA-M57-001.json"
CASE_ID="NITROBA"

# 2. Congelar — crea el manifest sellado y el snapshot de evidencia.
mkdir -p /tmp/perito-cases /tmp/perito-outputs
echo "{\"caso\": [\"$CASE_FILE\"]}" > /tmp/perito-profile.json
zaynor freeze --case-id "$CASE_ID" --evidence-profile caso \
  --profile-map /tmp/perito-profile.json --source-root casos \
  --cases-root /tmp/perito-cases --json

# 3. Analizar — corre el motor determinista, sella el resultado.
#    --engine-repo explícito hasta que se cierre un bug de empaquetado en
#    curso (resuelve mal la ruta del motor vendorizado sin este flag).
zaynor analyze --case-id "$CASE_ID" --cases-root /tmp/perito-cases \
  --engine-repo vendor/vigia_engine \
  --output-root /tmp/perito-outputs --json

# 4. Auditar — verifica que nada se alteró desde el paso 3.
zaynor audit --case-id "$CASE_ID" --cases-root /tmp/perito-cases \
  --output-root /tmp/perito-outputs --json

# 5. Reporte para el expediente — elegí el formato que necesites.
zaynor report --case-id "$CASE_ID" --output-root /tmp/perito-outputs --format pdf
zaynor report --case-id "$CASE_ID" --output-root /tmp/perito-outputs --format html
zaynor report --case-id "$CASE_ID" --output-root /tmp/perito-outputs --format md
```

Para usar otro caso de `casos/`, o uno propio con el mismo esquema, solo
cambiá `CASE_FILE`/`CASE_ID` — el resto de los comandos no cambia.

---

## Camino B — evidencia de imagen forense (directorio)

Para evidencia ya extraída de una imagen forense (registro, prefetch,
navegador, event log, memoria, USB, shellbag, amcache) — un directorio
con los artefactos reales, no un JSON de caso.

```bash
CASE_ID="IMG-CASO-001"

# 1. Congelar — el profile map lista, por perfil, las rutas relativas
#    dentro de --source-root que forman parte de este caso. Ejemplo con
#    un perfil que incluye registro y prefetch:
cat > /tmp/perito-image-profile.json <<'EOF'
{
  "investigacion-registro-prefetch": [
    "registry/SYSTEM",
    "registry/SOFTWARE",
    "registry/NTUSER.DAT",
    "prefetch/EXAMPLE.EXE-ABCDEF12.pf"
  ]
}
EOF
zaynor freeze --case-id "$CASE_ID" --evidence-profile investigacion-registro-prefetch \
  --profile-map /tmp/perito-image-profile.json --source-root /ruta/a/la/imagen/extraida \
  --cases-root /tmp/perito-cases --json

# 2. Analizar — el registro necesita las rutas explícitamente permitidas
#    (VIGÍA nunca analiza fuera de lo declarado). Ajustá VIGIA_ALLOWED_*
#    a las rutas reales congeladas en el paso 1.
export VIGIA_ALLOWED_REGISTRY_PATHS="registry/SYSTEM,registry/SOFTWARE,registry/NTUSER.DAT"
zaynor analyze --case-id "$CASE_ID" --cases-root /tmp/perito-cases \
  --engine-repo vendor/vigia_engine \
  --output-root /tmp/perito-outputs --json

# 3. Auditar y reportar — igual que el Camino A.
zaynor audit --case-id "$CASE_ID" --cases-root /tmp/perito-cases \
  --output-root /tmp/perito-outputs --json
zaynor report --case-id "$CASE_ID" --output-root /tmp/perito-outputs --format pdf
```

Este camino usa **solo** `zaynor audit` para verificar la integridad y el
tamper-evidence de la corrida ZAYNOR. No dispone de la segunda verificación
standalone EBS v1: el bundle que guarda `zaynor analyze` acá es la salida
directa de la CLI de Mode 1 (`agent_verdict`/`pipeline_results`/`audit_trail`),
no el formato EBS v1 que entiende `verify_ebs_v1.py` (ver sección siguiente).

---

## Verificación EBS v1 independiente (solo Camino A)

VIGÍA tiene su propio verificador standalone, sin ninguna dependencia de
código de producción — pensado para que un tercero (otro perito, un
juzgado) pueda auditar el bundle con Python compatible, sin dependencias
externas.
Verifica un formato de bundle **distinto** al que ya usa `zaynor audit`
(bundle_hash/graph_hash/policy_hash/decision_hash — 4 hashes propios del
estándar EBS v1 de VIGÍA), así que hace falta un paso intermedio para
producir ese bundle a partir del caso JSON:

```bash
# 1. Construir el bundle EBS v1 real a partir del caso (no del resultado
#    de zaynor analyze — este bundle se genera aparte, del caso original).
python3 scripts/build_ebs_bundle.py casos/case_083_sacrificio_del_peon.json /tmp/bundle.ebs.json

# 2. Verificar, con el script vendorizado de VIGÍA (100% stdlib).
python3 vendor/vigia_engine/forensics/verify_ebs_v1.py /tmp/bundle.ebs.json --verbose
```

Confirmado real, ambos pasos, contra `casos/case_083_sacrificio_del_peon.json`:
el builder imprime veredicto `MALICE`; el verificador da `PASS`, `Level 2 —
Cryptographically valid`, con 9 de 11 chequeos satisfechos. La salida de
`R3_DECISION_COHERENCE` del bundle verificado muestra `decision=ABSTAIN`, así
que el veredicto del caso original y la decisión EBS no son equivalentes y
deben tratarse como una inconsistencia pendiente, no como un único resultado.
Los 2 chequeos que no pasan (`R4_ENGINE_ATTESTATION`,
`R5_ECL_BINDING`) requieren atestación criptográfica del motor y anclaje
ECL — funcionalidad de VIGÍA que no está cableada en ZAYNOR todavía; por
eso no uses `--strict` (exige Level 3) hasta que esa pieza se agregue —
es una limitación documentada, no un fallo oculto.
