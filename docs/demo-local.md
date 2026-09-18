# Demo local de ZAYNOR — guía terminal-first

Esta guía contiene el procedimiento completo para ejecutar y grabar una demo
local de ZAYNOR con VIGÍA, Ollama, API compatible con OpenAI, OpenWebUI,
frontend y MCP. El procedimiento no requiere analizar desde el chat.

Caso elegido: `case_026_ventrilocuo_process_hollowing`.

El caso combina un binario legítimo con ruta anómala, memoria RWX con un PE no
respaldado por disco, parent process incorrecto, persistencia y exfiltración.
Su flujo es:

```text
evidencia → freeze → VIGÍA → result.json + result.seal.json
          → audit trail → Ollama local → narración protegida
```

## Variables

```bash
export ZAYNOR=/home/labestiadevigia/zaynor
export DEMO_CASE=case_026_ventrilocuo_process_hollowing
export DEMO_CASES=/tmp/zaynor-demo-cases
export DEMO_OUTPUT=/tmp/zaynor-demo-output
export OLLAMA_HOST=http://127.0.0.1:11434
export OLLAMA_MODEL=hermes3:8b
```

## Preparar y analizar

```bash
cd "$ZAYNOR"
python3 --version
ollama list
python3 -m pip install -e '.[api]'

python3 - <<'PY'
import json
from pathlib import Path
Path('/tmp/zaynor-case-026-profile.json').write_text(
    json.dumps({'process-hollowing-demo': ['case_026_ventrilocuo_process_hollowing.json']}, indent=2) + '\n',
    encoding='utf-8',
)
PY

rm -rf "$DEMO_CASES" "$DEMO_OUTPUT"

PYTHONPATH=src python3 -m zaynor.cli freeze \
  --case-id "$DEMO_CASE" \
  --evidence-profile process-hollowing-demo \
  --profile-map /tmp/zaynor-case-026-profile.json \
  --source-root casos \
  --cases-root "$DEMO_CASES" --json

PYTHONPATH=src python3 -m zaynor.cli analyze \
  --case-id "$DEMO_CASE" \
  --cases-root "$DEMO_CASES" \
  --output-root "$DEMO_OUTPUT" --json
```

`analyze` es la única etapa que ejecuta VIGÍA y produce la decisión. Chat no
vuelve a analizar el caso.

## Verificar resultado y audit trail

```bash
PYTHONPATH=src python3 -m zaynor.cli audit \
  --case-id "$DEMO_CASE" --cases-root "$DEMO_CASES" \
  --output-root "$DEMO_OUTPUT" --json

PYTHONPATH=src python3 -m zaynor.cli audit-trail \
  --case-id "$DEMO_CASE" --cases-root "$DEMO_CASES" --json

sha256sum "$DEMO_OUTPUT/$DEMO_CASE/result.json" \
  "$DEMO_OUTPUT/$DEMO_CASE/result.seal.json"
```

La cadena esperada es `CASE_FROZEN → ENGINE_INVOKED → RESULT_SEALED`, con
`chain_valid=true`. El resultado esperado del caso es `MALICE`. Los timestamps
del audit trail están dentro de sus entradas hasheadas; esta demo no usa
trusted timestamping externo.

## Chat CLI

```bash
PYTHONPATH=src python3 -m zaynor.cli chat \
  --case-id "$DEMO_CASE" --output-root "$DEMO_OUTPUT" \
  --model "$OLLAMA_MODEL" --host "$OLLAMA_HOST" --timeout 120 \
  --audience senior \
  --question 'Explicá process hollowing, memoria RWX, parent incorrecto y la discrepancia entre hash de disco y memoria. No cambies ni infieras otro veredicto.' \
  --json
```

El guard puede eliminar claims no verificables o rechazar la narración. Eso es
fail-closed y no cambia `result.json` ni `result.seal.json`.

## Levantar API y probarla

Si `8420` ya está ocupado, usar `8421`:

```bash
cd "$ZAYNOR"
PYTHONPATH=src python3 -m zaynor.cli serve \
  --output-root "$DEMO_OUTPUT" --cases-root "$DEMO_CASES" \
  --host 127.0.0.1 --port 8421 \
  --ollama-host "$OLLAMA_HOST" --model "$OLLAMA_MODEL" --timeout 120
```

En otra terminal:

```bash
export ZAYNOR_API=http://127.0.0.1:8421
curl -sS "$ZAYNOR_API/health"
curl -sS "$ZAYNOR_API/v1/models"
curl -sS "$ZAYNOR_API/cases"
curl -sS "$ZAYNOR_API/cases/$DEMO_CASE/audit"
curl -sS "$ZAYNOR_API/cases/$DEMO_CASE/audit-trail"

curl -sS -X POST "$ZAYNOR_API/v1/chat/completions" \
  -H 'content-type: application/json' \
  --data '{
    "model": "zaynor-forensic",
    "stream": false,
    "messages": [{
      "role": "user",
      "content": "case_id: case_026_ventrilocuo_process_hollowing\nExplicá la evidencia de process hollowing sin cambiar el veredicto."
    }]
  }'
```

La API sólo acepta `model=zaynor-forensic` y rechaza `stream=true`.

## OpenWebUI y frontend

OpenWebUI se detecta normalmente en `http://127.0.0.1:8080`. Configurar el
proveedor OpenAI-compatible con:

```text
Base URL: http://127.0.0.1:8421/v1
API key: zaynor-local
Model: zaynor-forensic
```

La API no valida actualmente la API key. El valor sólo satisface el campo que
OpenWebUI suele exigir. Mantenerlo en localhost.

Cada pregunta debe incluir el caso:

```text
case_id: case_026_ventrilocuo_process_hollowing
¿Qué evidencia sostiene el resultado y qué incertidumbres quedan?
```

No conectar OpenWebUI directamente a Ollama para esta demo: eso omite la
verificación del resultado sellado y el authority/hallucination guard.

Para iniciar una instancia nueva del frontend apuntando a `8421`:

```bash
cd "$ZAYNOR/frontend"
NEXT_PUBLIC_ZAYNOR_API_MODE=http \
NEXT_PUBLIC_ZAYNOR_API_BASE_URL=http://127.0.0.1:8421 \
npm run dev -- --hostname 127.0.0.1 --port 3001
```

Abrir `http://127.0.0.1:3001`. Si Next informa que ya existe otro servidor,
usar el frontend que ya está en `:3000` o dejarlo fuera de la grabación; no
matar procesos a ciegas.

## Los cuatro MCP

ZAYNOR documenta tres integraciones auxiliares y un servidor propio:

| MCP | Función | Superficie | Autoridad |
| --- | --- | --- | --- |
| VIGÍA | Lectura y operaciones forenses acotadas | 9 tools vendorizadas | No reemplaza el resultado sellado |
| CRONOS | Trazas, hipótesis y auditoría de razonamiento | 10 allowlisted tools | No produce verdict |
| MNEME | Custodia y verificación de bundles | 3 allowlisted tools | No produce verdict |
| ZAYNOR | Memoria case-bound y verificación de audit | 6 tools | No modifica resultado/seal |

### ZAYNOR MCP

```bash
cd "$ZAYNOR"
mkdir -p /tmp/zaynor-mcp-state
ZAYNOR_MCP_STATE_DIR=/tmp/zaynor-mcp-state \
PYTHONPATH=src python3 -m zaynor.zaynor_mcp_server
```

Configuración MCP para Claude:

```json
{
  "mcpServers": {
    "zaynor": {
      "command": "/usr/bin/python3",
      "args": ["-m", "zaynor.zaynor_mcp_server"],
      "cwd": "/home/labestiadevigia/zaynor",
      "env": {
        "PYTHONPATH": "/home/labestiadevigia/zaynor/src",
        "ZAYNOR_MCP_STATE_DIR": "/tmp/zaynor-mcp-state"
      }
    }
  }
}
```

Tools: `zaynor_info`, `zaynor_verify_audit`, `zaynor_verify_memory`,
`zaynor_list_memory`, `zaynor_add_hypothesis` y `zaynor_note_question`.

Pedir a Claude, por ejemplo:

```text
Usá zaynor_verify_audit para case_026_ventrilocuo_process_hollowing.
Después listá la memoria del caso. No ejecutes análisis ni modifiques el
resultado autoritativo.
```

### VIGÍA MCP

El bridge local utiliza `src/zaynor/vigia_mcp_runner.py` y
`vendor/vigia_engine/vigia/vigia_sift_bridge_min.py`. Su entorno debe contener:

```text
VIGIA_EVIDENCE_DIR=/tmp/zaynor-demo-cases/case_026_ventrilocuo_process_hollowing/evidence
VIGIA_LLM_BACKEND=ollama
VIGIA_OLLAMA_HOST=http://127.0.0.1:11434
VIGIA_OLLAMA_MODEL=hermes3:8b
PYTHONPATH=/home/labestiadevigia/zaynor/vendor/vigia_engine
```

Herramientas allowlisted: `list_files`, `read_evidence`, `search_pattern`,
`generate_forensic_hash`, `calculate_shannon_entropy`, `infer_intent`,
`audit_grice_maxims`, `detect_eco_overinterpretation` y
`validate_and_correct_analysis`.

### CRONOS y MNEME

Localizar primero los servidores reales:

```bash
find /home/labestiadevigia -path '*/cronos/mcp_server.py' -type f -print
find /home/labestiadevigia -path '*/mneme/mcp_server.py' -type f -print
```

CRONOS usa `CRONOS_DB_PATH` y su allowlist es:
`cronos_open_trace`, `cronos_record_recall`, `cronos_record_tool_call`,
`cronos_add_hypothesis`, `cronos_add_evidence`, `cronos_discard_hypothesis`,
`cronos_close_trace`, `cronos_explain_trace`, `cronos_list_traces`,
`cronos_verify_chain`.

MNEME usa `MNEME_DB_PATH` y su allowlist es:
`mneme_verify_bundle`, `mneme_custody_chain`, `mneme_info`.

Plantillas de configuración:

```json
{
  "mcpServers": {
    "cronos": {
      "command": "/usr/bin/python3",
      "args": ["/RUTA/REAL/cronos/mcp_server.py"],
      "env": {"CRONOS_DB_PATH": "/tmp/zaynor-cronos-demo.db"}
    },
    "mneme": {
      "command": "/usr/bin/python3",
      "args": ["/RUTA/REAL/mneme/mcp_server.py"],
      "env": {"MNEME_DB_PATH": "/tmp/zaynor-mneme-demo.db"}
    }
  }
}
```

No habilitar herramientas de grants, claims, autorización ni side effects
externos. MCP es observación/memoria auxiliar; `result.json` y
`result.seal.json` siguen siendo la autoridad.

## Tests MCP

```bash
cd "$ZAYNOR"
PYTHONPATH=src python3 -m pytest -q \
  tests/test_zaynor_mcp_client.py \
  tests/test_zaynor_mcp_config_security.py -x
```

Resultado actual verificado: `11 passed`.

## Secuencia para grabar

1. `freeze`.
2. `analyze` y mostrar `MALICE`.
3. `audit` y mostrar `VERIFIED`.
4. `audit-trail` y mostrar la cadena de tres entradas.
5. `curl` a health, models y cases.
6. `curl` al chat normal.
7. `curl` al chat pidiendo un veredicto contradictorio.
8. Repetir `audit` y `sha256sum`.
9. OpenWebUI conectado a ZAYNOR.
10. Claude verifica el audit trail por MCP.

Más detalle de las tres integraciones está en
[`mcp-locales.md`](./mcp-locales.md).
