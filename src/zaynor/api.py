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
import logging
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from zaynor.agents.chat_service import answer_question
from zaynor.agents.contracts import Audience
from zaynor.agents.ollama_client import OllamaClient, OllamaError
from zaynor.cli import CliInputError, _SAFE_CASE_ID, load_verified_stored_case

_MODEL_ID = "zaynor-forensic"
logger = logging.getLogger(__name__)


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    model: str = _MODEL_ID
    messages: list[ChatMessage]
    stream: bool = False


class CaseChatRequest(BaseModel):
    question: str


class ApiError(Exception):
    def __init__(self, status_code: int, code: str, message: str, error_type: str):
        self.status_code = status_code
        self.code = code
        self.message = message
        self.error_type = error_type


def _error_response(error: ApiError) -> JSONResponse:
    return JSONResponse(
        status_code=error.status_code,
        content={
            "error": {
                "message": error.message,
                "type": error.error_type,
                "code": error.code,
            }
        },
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


def _narrate_stored_case(
    case_id: str,
    question: str,
    *,
    output_root: Path,
    ollama_host: str,
    model: str,
    timeout_seconds: int,
):
    """Shared load-verify-narrate path for both the OpenAI-compat chat
    endpoint and the per-case REST chat endpoint -- one seal-verified,
    hallucination-guarded narration path, not two.

    Raises `ApiError` for every failure mode; never returns a narration
    that skipped the guard.
    """
    if not _SAFE_CASE_ID.fullmatch(case_id):
        raise ApiError(400, "invalid_case_id", "case_id is invalid", "invalid_request_error")
    if not question or not question.strip():
        raise ApiError(400, "malformed_request", "question is required", "invalid_request_error")
    case_dir = output_root / case_id
    if (
        case_dir.is_symlink()
        or not case_dir.is_dir()
        or not (case_dir / "result.json").is_file()
        or not (case_dir / "result.seal.json").is_file()
    ):
        raise ApiError(404, "case_not_found", "case is not available", "not_found_error")
    try:
        result, seal = load_verified_stored_case(
            case_id, case_dir / "result.json", case_dir / "result.seal.json"
        )
        client = OllamaClient(host=ollama_host, model=model, timeout_seconds=timeout_seconds)
        return answer_question(question, result=result, seal=seal, client=client, audience=Audience.SENIOR)
    except CliInputError:
        raise ApiError(422, "invalid_authority", "stored result or seal could not be verified", "authority_error") from None
    except OllamaError:
        raise ApiError(503, "ollama_unavailable", "local narration service is unavailable", "service_unavailable") from None
    except Exception:
        logger.exception("unexpected failure while narrating stored case")
        raise ApiError(500, "internal_error", "internal server error", "server_error") from None


def create_app(
    *,
    output_root: Path,
    ollama_host: str = "http://127.0.0.1:11434",
    model: str = "llama3.1:8b",
    timeout_seconds: int = 120,
) -> FastAPI:
    app = FastAPI(title="ZAYNOR Forensic Intelligence API", version="1.0")

    @app.exception_handler(ApiError)
    def api_error_handler(_request: Request, exc: ApiError) -> JSONResponse:
        return _error_response(exc)

    @app.exception_handler(RequestValidationError)
    def request_validation_handler(_request: Request, _exc: RequestValidationError) -> JSONResponse:
        return _error_response(ApiError(400, "malformed_request", "request body is invalid", "invalid_request_error"))

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
            [
                {
                    "case_id": entry.name,
                    "name": None,
                    "has_result": (entry / "result.json").is_file(),
                    "has_seal": (entry / "result.seal.json").is_file(),
                    "verification": "NOT_CHECKED",
                    "verdict": "UNKNOWN",
                    "seal_status": "UNKNOWN",
                    "updated_at": None,
                }
                for entry in output_root.iterdir()
                if entry.is_dir()
                and not entry.is_symlink()
                and ((entry / "result.json").is_file() or (entry / "result.seal.json").is_file())
            ],
            key=lambda item: item["case_id"],
        )
        return {"cases": cases}

    @app.post("/cases/{case_id}/chat")
    def case_chat(case_id: str, req: CaseChatRequest) -> dict[str, Any]:
        """Ask any question about one sealed case -- the REST-shaped
        counterpart to `/v1/chat/completions`, used by the Next.js
        frontend's `HttpApiClient.explain()`. Same guarded narration path,
        no restriction on what can be asked beyond what
        `answer_question`/`Mentor.chat_checked` already enforce.
        """
        checked = _narrate_stored_case(
            case_id, req.question,
            output_root=output_root, ollama_host=ollama_host, model=model, timeout_seconds=timeout_seconds,
        )
        # finding_refs/evidence_refs: no structured-citation extraction
        # exists on this narration path yet -- an honest empty list, not a
        # fabricated one, matching the sealed result's own vocabulary.
        return {
            "narrative": checked.safe_narration,
            "finding_refs": [],
            "evidence_refs": [],
            "certainty": "LIMITED" if checked.suspicious else "AUTHORIZED",
            "disclaimer": (
                f"{checked.claims_hallucinated} unsupported claim(s) removed out of {checked.claims_total}."
                if checked.suspicious
                else "Narración verificada contra el resultado sellado."
            ),
        }

    @app.post("/v1/chat/completions")
    def chat_completions(req: ChatRequest) -> dict[str, Any]:
        if req.model != _MODEL_ID:
            raise ApiError(400, "unsupported_model", "requested model is not supported", "invalid_request_error")
        if req.stream:
            raise ApiError(400, "stream_not_supported", "streaming is not supported", "invalid_request_error")
        user_messages = [message for message in req.messages if message.role == "user"]
        if not user_messages:
            raise ApiError(400, "malformed_request", "a user message is required", "invalid_request_error")
        case_id, question = _parse_request(user_messages[-1].content)
        if not case_id or not question or not question.strip():
            raise ApiError(400, "malformed_request", "case_id and question are required", "invalid_request_error")
        checked = _narrate_stored_case(
            case_id, question,
            output_root=output_root, ollama_host=ollama_host, model=model, timeout_seconds=timeout_seconds,
        )
        content = checked.safe_narration
        if checked.suspicious:
            content += (
                f"\n\n[warning: {checked.claims_hallucinated} unsupported claim(s) "
                "removed from the model output]"
            )

        return {
            "id": f"zaynor-{uuid.uuid4().hex}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": _MODEL_ID,
            "choices": [
                {"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}
            ],
        }

    return app
