"""OpenAI-compatible HTTP surface so OpenWebUI can talk to ZAYNOR directly.

Modeled on the same `/v1/models` + `/v1/chat/completions` shape VIGIA's own
`vigia/openai_compat.py` exposes for OpenWebUI — confirmed by reading it in
full (docs/red-team/2026-09-16-round-15-ollama-openwebui.md) — but wired to
ZAYNOR's own pipeline rather than copied: VIGIA's endpoint treats the whole
chat message AS a raw case to analyze inline; ZAYNOR's cases are frozen,
analyzed, and sealed ahead of time by `zaynor analyze`; a chat message here
asks a question about one of those already-sealed cases by id. Reusing
VIGIA's request-parsing logic verbatim would have papered over that
difference, not reused it.

The LLM narrates; it never decides. Every answer passes through the same
hallucination guard `zaynor chat` uses — this module and the CLI both call
`zaynor.agents.chat_service.answer_question`, so there is exactly one
seal-verified chat path, not two.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from zaynor.agents.chat_service import answer_question
from zaynor.agents.contracts import Audience
from zaynor.agents.ollama_client import OllamaClient, OllamaError
from zaynor.cli import CliInputError, _SAFE_CASE_ID, _load_stored_result, _load_stored_seal

_MODEL_ID = "zaynor-forensic"


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    model: str = _MODEL_ID
    messages: list[ChatMessage]
    stream: bool = False


def _usage_guidance() -> str:
    return (
        "ZAYNOR Forensic Intelligence API.\n\n"
        'Send a chat message as JSON: {"case_id": "<ID>", "question": "<question>"}\n'
        'or as plain text: "case_id: <ID>" on the first line, the question on the rest.\n\n'
        "The case must already have been analyzed with `zaynor analyze` "
        "(its result and seal are read from --output-root).\n"
        "GET /cases lists analyzed cases. GET /health reports status."
    )


def _parse_request(raw: str) -> tuple[str | None, str | None]:
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        parsed = None
    if isinstance(parsed, dict):
        case_id = parsed.get("case_id")
        question = parsed.get("question")
        return (case_id if isinstance(case_id, str) else None, question if isinstance(question, str) else None)
    first_line, separator, rest = raw.partition("\n")
    if separator and first_line.strip().lower().startswith("case_id:"):
        return first_line.split(":", 1)[1].strip(), rest.strip()
    return None, None


def create_app(
    *,
    output_root: Path,
    ollama_host: str = "http://127.0.0.1:11434",
    model: str = "llama3.1:8b",
    timeout_seconds: int = 120,
) -> FastAPI:
    app = FastAPI(title="ZAYNOR Forensic Intelligence API", version="1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:8080", "http://127.0.0.1:8080"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "zaynor operational"}

    @app.get("/v1/models")
    def list_models() -> dict[str, Any]:
        return {
            "object": "list",
            "data": [{"id": _MODEL_ID, "object": "model", "owned_by": "zaynor", "created": 1716000000}],
        }

    @app.get("/cases")
    def list_cases() -> dict[str, Any]:
        if not output_root.is_dir():
            return {"cases": []}
        cases = sorted(
            entry.name
            for entry in output_root.iterdir()
            if entry.is_dir() and (entry / "result.json").is_file() and (entry / "result.seal.json").is_file()
        )
        return {"cases": cases}

    @app.post("/v1/chat/completions")
    def chat_completions(req: ChatRequest) -> dict[str, Any]:
        user_messages = [message for message in req.messages if message.role == "user"]
        content = _usage_guidance()
        if user_messages:
            case_id, question = _parse_request(user_messages[-1].content)
            if not case_id or not question or not question.strip():
                content = _usage_guidance()
            elif not _SAFE_CASE_ID.fullmatch(case_id):
                content = "Invalid case_id."
            else:
                try:
                    case_dir = output_root / case_id
                    result = _load_stored_result(case_id, case_dir / "result.json")
                    seal = _load_stored_seal(case_dir / "result.seal.json")
                    client = OllamaClient(host=ollama_host, model=model, timeout_seconds=timeout_seconds)
                    checked = answer_question(
                        question, result=result, seal=seal, client=client, audience=Audience.SENIOR
                    )
                    content = checked.safe_narration
                    if checked.suspicious:
                        content += (
                            f"\n\n[warning: {checked.claims_hallucinated} unsupported claim(s) "
                            "removed from the model output]"
                        )
                except (CliInputError, OllamaError) as exc:
                    content = f"ZAYNOR could not answer: {exc}"

        return {
            "id": f"zaynor-{int(time.time())}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": req.model,
            "choices": [
                {"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }

    return app
