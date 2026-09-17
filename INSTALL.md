# Instalación de Zaynor

Guía paso a paso para levantar Zaynor en una máquina local. Todo corre en
la computadora del perito — nada de esto sale a un servicio externo (ver
"Requisitos y soberanía" en el [`README.md`](./README.md)).

## 1. Requisitos

- **Python 3.12 o superior.**
- **Git.**
- **[Ollama](https://ollama.com)** (u otro backend local equivalente) —
  necesario para `chat`/`serve`; los comandos `freeze`/`analyze`/`audit`/
  `audit-trail`/`consult`/`report` no lo requieren, son puro motor
  determinista.
- Espacio en disco para casos congelados: la evidencia se copia (no se
  referencia) al congelar un caso.

No hace falta clonar VIGÍA por separado: el motor determinista viene
vendorizado dentro de este mismo repositorio
(`vendor/vigia_engine/`).

## 2. Clonar e instalar

```bash
git clone https://github.com/annatchijova/zaynor.git
cd zaynor

python3 -m venv .venv
source .venv/bin/activate

pip install -e .
```

Eso instala el paquete base: `freeze`, `analyze`, `audit`, `audit-trail`,
`reindex`, `chat`, `consult`, `hunts`, `models`. Tres extras opcionales,
según qué necesites:

```bash
# Para `zaynor serve` (API compatible con OpenAI/OpenWebUI):
pip install -e ".[api]"

# Para `zaynor report --format pdf` (md/html no necesitan nada extra):
pip install -e ".[report]"

# Para trazas OpenTelemetry opcionales sobre freeze/analyze:
pip install -e ".[telemetry]"

# Para desarrollar sobre el propio Zaynor (lint, tests, tipos):
pip install -e ".[dev]"
```

Podés combinarlos: `pip install -e ".[api,report]"`.

## 3. Instalar y preparar Ollama (para `chat`/`serve`)

```bash
# Instalar Ollama (ver https://ollama.com/download para tu plataforma).
# Después, bajar al menos un modelo:
ollama pull llama3.1:8b
```

`llama3.1:8b` es el modelo de referencia (fallback si no configurás otro).
Para ver qué tenés instalado y qué se recomienda según el hardware:

```bash
zaynor models
```

Elegido un modelo, fijalo con una variable de entorno para no tener que
pasarlo en cada comando:

```bash
export ZAYNOR_OLLAMA_MODEL="llama3.1:8b"   # o el que hayas elegido
```

Zaynor solo habla con Ollama en `http://127.0.0.1:11434` (o el host que le
pases explícitamente, siempre local — nunca un endpoint remoto).

## 4. Verificación rápida

```bash
zaynor case --fixture scenarios/inc-2026-demo-001/telemetry.jsonl --json
```

Si esto imprime un JSON con eventos y alertas, la instalación base
funciona. Este comando no toca Ollama ni el motor VIGÍA — es el pipeline
propio de detección/correlación de Zaynor sobre un fixture de ejemplo.

## 5. Flujo completo sobre un caso

Todo lo que sigue usa el escenario de demostración incluido en el repo
(`scenarios/inc-2026-demo-001/`). Con evidencia propia, el flujo es
idéntico — solo cambian las rutas.

```bash
# a) Congelar la evidencia: crea el manifest con hash de cada artefacto.
zaynor freeze --case-id CASO-001 \
  --evidence-profile admin-session-investigation \
  --profile-map scenarios/inc-2026-demo-001/evidence_profile.json \
  --source-root scenarios/inc-2026-demo-001 \
  --cases-root ./cases

# b) Analizar: corre el motor determinista VIGÍA sobre la evidencia congelada.
zaynor analyze --case-id CASO-001 --cases-root ./cases --output-root ./outputs

# c) Auditar: re-verifica manifest, snapshot, evidencia, bundle, resultado,
#    sello y la cadena de auditoría, desde cero, sin confiar en nada
#    calculado antes.
zaynor audit --case-id CASO-001 --cases-root ./cases --output-root ./outputs

# d) Ver el audit trail hash-chained del caso (quién hizo qué, en qué orden).
zaynor audit-trail --case-id CASO-001 --cases-root ./cases

# e) Preguntar sobre el caso ya sellado — el LLM local narra, nunca decide.
zaynor chat --case-id CASO-001 --output-root ./outputs \
  --question "¿Qué sostiene el veredicto?"

# f) Generar un reporte legible.
zaynor report --case-id CASO-001 --output-root ./outputs --format md
```

`--cases-root` es la evidencia congelada (manifest + artefactos + audit
trail del caso); `--output-root` es donde vive el resultado sellado
(`result.json`, `result.seal.json`, el índice derivado de casos). Son
directorios distintos a propósito — separan "lo que se congeló" de "lo
que el motor produjo".

### Servidor HTTP (opcional)

Para exponer los casos ya analizados vía una API compatible con
OpenAI/OpenWebUI (requiere el extra `api` del paso 2):

```bash
zaynor serve --output-root ./outputs --cases-root ./cases
```

Por defecto escucha en `127.0.0.1:8420` — local, sin autenticación,
pensado para un solo operador en su propia máquina (ver "Requisitos y
soberanía" en el README para el resto de las garantías).

## 6. Variables de entorno relevantes

| Variable | Para qué sirve | Opcional |
|---|---|---|
| `ZAYNOR_OLLAMA_MODEL` | Modelo por defecto para `chat`/`serve` si no se pasa `--model`. | Sí — cae al fallback bundleado si no está. |
| `ZAYNOR_HMAC_KEY` | Clave HMAC (hex) para firmar el audit trail. Sin ella, el chain opera en modo hash-only (documentado como caveat, nunca oculto). | Sí. |
| `ZAYNOR_HMAC_KEY_FILE` | Alternativa a `ZAYNOR_HMAC_KEY`: ruta a un archivo con la clave en bytes crudos. El archivo no puede ser legible por grupo/otros. | Sí. |

## 7. Servidor MCP propio (avanzado)

Si necesitás exponer las herramientas de Zaynor por MCP (por ejemplo,
para conectarlo a un cliente MCP externo en vez de usar la CLI
directamente):

```bash
zaynor-mcp
```

Ver [`docs/mcp-locales.md`](./docs/mcp-locales.md) para el detalle de qué
herramientas expone y con qué garantías de solo-lectura.

## 8. Problemas comunes

- **`no --engine-repo given and the vendored engine is missing`**: el
  checkout está incompleto o corriste algo fuera de la raíz del repo. El
  motor vendorizado vive en `vendor/vigia_engine/` — confirmá que existe
  antes de nada más.
- **`local Ollama request failed`**: Ollama no está corriendo, o no
  bajaste ningún modelo (`ollama pull llama3.1:8b`) o `ZAYNOR_OLLAMA_MODEL`
  apunta a un modelo que no instalaste.
- **`case-id must be a bounded path-safe identifier`**: el `--case-id`
  solo acepta letras, números, `.`, `_` y `-`, y no puede empezar con esos
  tres últimos.
- **Python demasiado viejo**: `pip install -e .` va a fallar si tenés
  menos de 3.12 — `python3 --version` para confirmar antes de reportar
  cualquier otro error.

## Próximos pasos

- [`README.md`](./README.md) — qué es Zaynor, el flujo de autoridad
  completo, alcance y estado real.
- [`AGENTS.md`](./AGENTS.md) — contratos de integración con VIGÍA y
  límites de autoridad entre evidencia, motor determinista y LLM.
- [`CONTRIBUYENDO.md`](./CONTRIBUYENDO.md) — si vas a tocar código, no
  solo a usarlo.
- [`docs/red-team/`](./docs/red-team/) — rondas de auditoría adversarial,
  para entender qué se verificó y cómo.
