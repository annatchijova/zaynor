# Ollama + OpenWebUI — `zaynor chat` and `zaynor serve`
## Round 15
**Fecha:** 2026-09-16
**Origen:** Anna: "sirve la PI de vigia para Ollama y OpenWebUI?" — tras el
motor vendorizado (round 14), siguiendo el orden que ella misma fijó ("motor
primero, API después").

## Qué se leyó de VIGÍA, en detalle (no solo el encabezado)

- `vigia_api.py` (233 líneas, raíz de vigia-repo): FastAPI wrapper con
  `/health`, `/cases`, `/analyze/path`, `/analyze/json`, más
  `install_openai_compatibility(app, run_pipeline=..., run_narrative=...)`.
- `vigia/openai_compat.py` (154 líneas): expone `/v1/models` y
  `/v1/chat/completions` con el schema OpenAI exacto que OpenWebUI espera.
  Esta pieza SÍ es directamente lo que hace falta para que OpenWebUI pueda
  agregar un backend — está bien construida, no es "basura improvisada".
- `vigia/vigia_api.py` (219 líneas, dentro del paquete): diff hecho contra el
  archivo de raíz — casi idéntico, la única diferencia real es cómo resuelve
  `REPO` según si el archivo vive en la raíz del repo o un nivel adentro del
  paquete. No son dos productos distintos, son el mismo módulo con dos puntos
  de montaje.
- `scripts/vigia_ask.sh` (866 bytes, confirmado que existe y es ejecutable):
  llama `ollama run deepseek-r1:8b` de verdad — esta es la pieza que
  efectivamente toca Ollama en VIGÍA. Tiene dos problemas para vendorizar tal
  cual: `cd ~/vigia-repo` hardcodeado (ruta de una máquina específica) y el
  modelo fijo en el script en vez de parametrizado.
- `scripts/run_vigia_full.py`: SÍ existe (contra lo que sugería un primer
  vistazo al docstring de `vigia_api.py`, que lo menciona sin ruta) — está en
  `scripts/`, no en la raíz. No era una referencia muerta, solo una ruta vieja
  en el comentario.

## Por qué no se vendorizó tal cual

El hallazgo clave, leyendo `openai_compat.py::chat_completions` completo: el
"modelo" que responde en `/v1/chat/completions` no es Ollama — es VIGÍA mismo
disfrazado de LLM de chat. Cada mensaje de OpenWebUI se interpreta como un
CASO JSON completo (`artifacts` en el body del mensaje), se corre el pipeline
determinístico ahí mismo (`_run_pipeline` → `vigia_scorer` + `build_bundle`,
sellado), y el veredicto vuelve formateado como si fuera la respuesta del
"modelo". Ollama entra en un lugar aparte y menor, dentro de `_run_narrative`,
solo para narrar el veredicto ya sellado — nunca decide nada (arquitectura
correcta, igual a la de ZAYNOR: CLAUDE.md 5.1).

Esa forma de leer el mensaje de chat no encaja con el pipeline de ZAYNOR:
acá un caso se congela (`freeze`), se analiza (`analyze`, sellado
inmediatamente) y se audita (`audit`) como pasos separados — nunca llega un
caso crudo dentro de un mensaje de chat. Copiar `openai_compat.py` tal cual
habría significado o (a) reimplementar el flujo de análisis-por-chat-message
de VIGÍA además del propio de ZAYNOR (dos caminos de análisis, divergentes),
o (b) forzar la lógica de parseo de VIGÍA sobre datos que no tienen esa forma.
Ninguna de las dos es "reutilizar lo que sirve": la primera duplica, la
segunda rompe.

**Lo que sí se reutilizó, deliberadamente:** la FORMA del contrato
`/v1/models` + `/v1/chat/completions` (el shape exacto que OpenWebUI
necesita para agregar un backend) — no el código de parseo de VIGÍA. El
`ChatRequest`/`chat_completions` de `src/zaynor/api.py` tiene el mismo
esqueleto de respuesta que `vigia/openai_compat.py`, adaptado a que un
mensaje de chat de ZAYNOR es `{"case_id": ..., "question": ...}` (o su
equivalente en texto plano), no un caso completo.

**Ollama:** en vez de adaptar `vigia_ask.sh` (hardcodeo de ruta + modelo fijo,
sin el enforcement local-only que exige el hackathon), se usó el
`OllamaClient` propio de ZAYNOR (`agents/ollama_client.py`), que ya rechaza
cualquier host no-local en `__post_init__`. Ya existía y ya cumplía la regla
"OBLIGATORIO: solo IA local" mejor que el script de VIGÍA.

## Qué se construyó

Un solo camino de chat verificado contra el sello, usado por dos entradas:

- `src/zaynor/agents/chat_service.py::answer_question` — el único lugar
  donde se arma el contexto del resultado sellado y se llama
  `Mentor.chat_checked`. `zaynor chat` (CLI) y `zaynor serve` (HTTP) llaman a
  esta misma función; no hay dos implementaciones divergentes del mismo
  camino.
- `zaynor chat --case-id ... --output-root ... --question ...`: carga
  `result.json`/`result.seal.json` ya escritos por `zaynor analyze`, verifica
  el sello, narra con Ollama local, y solo imprime `safe_narration` (nunca
  `original_narration`) — `--json` expone además el diagnóstico completo de
  `GuardResult.to_dict()`.
- `zaynor serve --output-root ...`: FastAPI (`src/zaynor/api.py`) con
  `/health`, `/v1/models`, `/cases`, `/v1/chat/completions` — el contrato
  OpenAI que OpenWebUI necesita para agregarlo como backend. Un mensaje de
  chat es `{"case_id": "...", "question": "..."}` (JSON) o
  `"case_id: ...\n<pregunta>"` (texto plano); cualquier otra cosa devuelve la
  guía de uso, igual que `vigia/openai_compat.py::_usage_guidance`.
- Dependencia opcional `pip install -e '.[api]'` (`fastapi`, `uvicorn`,
  `pydantic`) — `analyze`/`freeze`/`audit`/`chat` no la necesitan; solo
  `serve` la importa, de forma perezosa, con un mensaje claro si falta.

## Verificación

`Mentor.chat_checked` construye el contexto del prompt vía
`chat_service.result_context` (verdict/confidence/findings/unknowns del
resultado sellado) y corre `check_narrative` después, que deriva sus propios
hechos autorizados directamente de `result` — independiente de lo que se le
haya mandado al modelo. Probado por inducción con dos respuestas simuladas
del LLM: una que narra el veredicto real (`ABSTAIN`, el que produce el motor
stub de test) pasa limpia; una que narra un veredicto no sellado (`MALICE`)
es detectada y removida de `safe_narration`, con la advertencia visible en
stderr (CLI) o en el propio `content` (API). 232/232 tests pasan
(226 previos + 3 `test_cli.py::test_chat_*` + 6 `test_api.py::*` — un test
neto extra viene de una tercera prueba de rechazo de caso no analizado en
`test_cli.py`, no reflejada en la cuenta de arriba).

Confirmado además con un smoke test real: `zaynor serve` levantado en
`127.0.0.1:18421`, `/health`, `/v1/models` y `/cases` respondidos por HTTP de
verdad (no solo `TestClient`).

## Pendiente, fuera de alcance de esta ronda

- `Audience` en `zaynor serve` está fijo en `SENIOR` — no hay forma de que
  OpenWebUI lo cambie por mensaje. Si hace falta, agregar un campo opcional
  al body en vez de inferirlo del texto libre.
- CORS de `create_app` apunta a `localhost:8080`/`127.0.0.1:8080` (puerto por
  defecto de OpenWebUI) — hardcodeado; parametrizar si OpenWebUI corre en
  otro puerto.
