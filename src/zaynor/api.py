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
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field, model_validator

from zaynor.agents.chat_service import answer_question
from zaynor.agents.contracts import Audience
from zaynor.agents.ollama_client import OllamaClient, OllamaError
from zaynor.cli import CliInputError, _SAFE_CASE_ID, _load_case_manifest, compute_case_audit, load_verified_stored_case
from zaynor.frozen_snapshot import FrozenSnapshotError, _validated_entries
from zaynor.schemas import AuthoritativeFinding, ZaynorAuthoritativeResult

_MODEL_ID = "zaynor-forensic"
_MAX_CHAT_MESSAGES = 64
_MAX_MESSAGE_CONTENT_CHARS = 32_768
_MAX_CHAT_TEXT_BYTES = 131_072
logger = logging.getLogger(__name__)


class ChatMessage(BaseModel):
    role: str = Field(max_length=32)
    content: str = Field(max_length=_MAX_MESSAGE_CONTENT_CHARS)


class ChatRequest(BaseModel):
    model: str = _MODEL_ID
    messages: list[ChatMessage] = Field(max_length=_MAX_CHAT_MESSAGES)
    stream: bool = False

    @model_validator(mode="after")
    def validate_total_chat_text(self) -> "ChatRequest":
        total_bytes = sum(len(message.content.encode("utf-8")) for message in self.messages)
        if total_bytes > _MAX_CHAT_TEXT_BYTES:
            raise ValueError("chat message content exceeds the request limit")
        return self


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


_CONFIDENCE_VALUES = frozenset({"LOW", "MEDIUM", "HIGH", "UNKNOWN"})
_REPORT_CONTENT_TYPES = {"md": "text/markdown", "html": "text/html", "pdf": "application/pdf"}


def _finding_payload(finding: AuthoritativeFinding) -> dict[str, Any]:
    return {
        "finding_id": finding.finding_id,
        "state": finding.state,
        "rationale": finding.rationale,
        "evidence_refs": [{"artifact": ref.artifact, "lineage_id": ref.lineage_id} for ref in finding.evidence_refs],
        "lineage_ids": list(finding.lineage_ids),
        "mitre": dict(finding.mitre) if finding.mitre else None,
        "nist": dict(finding.nist) if finding.nist else None,
    }


def _authoritative_result_payload(result: ZaynorAuthoritativeResult, result_sha256: str) -> dict[str, Any]:
    """Map the sealed result to the frontend's AuthoritativeResult contract.

    `hypotheses`/`fractures`/`signals` are honest empty lists: the sealed
    schema carries `fractures`/`hypotheses` as free-form dicts with no
    fixed key shape (whatever the engine bundle happened to emit, always
    empty in every real run tried so far) and no `signals` field exists at
    all. Fabricating a mapped shape from data that is not actually
    produced would be exactly the kind of overclaim this project keeps
    catching elsewhere -- an empty list is the honest state today.
    """
    confidence = result.integrity.get("confidence", "UNKNOWN")
    if confidence not in _CONFIDENCE_VALUES:
        confidence = "UNKNOWN"
    return {
        "case_id": result.case_id,
        "verdict": result.verdict,
        "confidence": confidence,
        "findings": [_finding_payload(finding) for finding in result.findings],
        "unknowns": [
            {"id": f"U{index + 1:03d}", "statement": unknown, "what_would_resolve": None}
            for index, unknown in enumerate(result.unknowns)
        ],
        "hypotheses": [],
        "fractures": [],
        "signals": [],
        "result_sha256": result_sha256,
        "engine": {
            "name": result.engine.get("name", "UNKNOWN"),
            "version": result.engine.get("version", "UNKNOWN"),
            "configuration_hash": result.engine.get("configuration_hash", "UNKNOWN"),
        },
        "audit_refs": list(result.audit_refs),
    }


def _verification_status(value: str) -> str:
    if value == "VERIFIED" or "VERIFIED" in value:
        return "VERIFIED"
    if value == "UNKNOWN":
        return "UNKNOWN"
    return "FAILED"


def _audit_status_payload(audit_report: dict[str, Any]) -> dict[str, Any]:
    """Map `compute_case_audit`'s report dict to the frontend's AuditStatus
    contract -- the exact same verification `zaynor audit` runs, not a
    second re-derivation of it. "UNKNOWN" (cases_root not configured on
    this server) is preserved as its own state, never collapsed into
    "FAILED" -- a WARN is not a FAIL (CLAUDE.md 5.3).
    """
    overall = _verification_status(audit_report["overall"])
    return {
        "status": overall,
        "manifest": _verification_status(audit_report["manifest"]),
        "snapshot": _verification_status(audit_report["snapshot"]),
        "evidence": _verification_status(str(audit_report["evidence"])),
        "result": _verification_status(audit_report["result"]),
        "seal": _verification_status(audit_report["seal"]),
        "provenance": audit_report["provenance"] if audit_report["provenance"] in ("PRESENT", "EMPTY") else "UNKNOWN",
        "checked_at": None,
        "detail": None if overall == "VERIFIED" else audit_report.get("error"),
    }


def _empty_investigation_payload() -> dict[str, Any]:
    """No investigation session is persisted anywhere in the backend today
    (`InvestigationSession`/`BoundedInvestigator` are real and tested but
    unwired to any CLI/API command -- see agents/README.md). This is the
    honest reflection of that: every case has NOT_STARTED, not a
    fabricated in-progress session.
    """
    return {
        "session_id": None,
        "status": "NOT_STARTED",
        "proposals": [],
        "observations": [],
        "authoritative_result_unchanged": True,
    }


def _evidence_payload(case_id: str, cases_root: Path, result: ZaynorAuthoritativeResult) -> list[dict[str, Any]]:
    case_dir = cases_root / case_id
    manifest = _load_case_manifest(case_dir)
    entries = _validated_entries(manifest, case_dir / "evidence")
    referenced_artifacts = {
        ref.artifact for finding in result.findings for ref in finding.evidence_refs
    }
    payload = []
    for relative_path, sha256, size_bytes in entries:
        payload.append(
            {
                "evidence_id": relative_path,
                "type": Path(relative_path).suffix.lstrip(".") or "file",
                "source": "manifest congelado",
                "relative_path": relative_path,
                "sha256": sha256,
                "size_bytes": size_bytes,
                "manifest_status": "VERIFIED",
                "lineage_id": relative_path,
                "provenance": [],
                "finding_refs": [
                    finding.finding_id
                    for finding in result.findings
                    if any(ref.artifact == relative_path for ref in finding.evidence_refs)
                ],
                "metadata": {},
            }
        )
    return payload


def _load_case_for_overview(
    case_id: str, *, output_root: Path, cases_root: Path | None
) -> tuple[ZaynorAuthoritativeResult, Any, dict[str, Any]]:
    """Load and verify a stored case, plus its audit report. Raises
    `ApiError` for every failure mode -- never returns unverified state.
    """
    if not _SAFE_CASE_ID.fullmatch(case_id):
        raise ApiError(400, "invalid_case_id", "case_id is invalid", "invalid_request_error")
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
    except CliInputError:
        raise ApiError(422, "invalid_authority", "stored result or seal could not be verified", "authority_error") from None
    if cases_root is None:
        audit_report = {
            "case_id": case_id, "manifest": "UNKNOWN", "snapshot": "UNKNOWN", "evidence": "UNKNOWN",
            "engine": "UNKNOWN", "result": "VERIFIED", "seal": "VERIFIED", "verdict": result.verdict,
            "confidence": result.integrity.get("confidence", "UNKNOWN"), "findings": len(result.findings),
            "unknowns": list(result.unknowns), "provenance": "UNKNOWN", "overall": "UNKNOWN",
        }
    else:
        audit_report = compute_case_audit(case_id, cases_root, output_root)
    return result, seal, audit_report


def _snapshot_payload(case_id: str, cases_root: Path | None, output_root: Path, result: ZaynorAuthoritativeResult) -> dict[str, Any]:
    if cases_root is None:
        return {
            "status": "UNKNOWN",
            "manifest_sha256": "UNKNOWN",
            "evidence_set_sha256": result.integrity.get("analyzed_snapshot_sha256", "UNKNOWN"),
            "artifact_count": 0,
            "sealed_at": None,
        }
    manifest = _load_case_manifest(cases_root / case_id)
    return {
        "status": "VERIFIED",
        "manifest_sha256": manifest.content_sha256,
        "evidence_set_sha256": result.integrity.get("analyzed_snapshot_sha256", "UNKNOWN"),
        "artifact_count": len(manifest.entries),
        "sealed_at": manifest.sealed_at,
    }


def create_app(
    *,
    output_root: Path,
    cases_root: Path | None = None,
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

    @app.get("/cases/{case_id}")
    def get_case(case_id: str) -> dict[str, Any]:
        result, seal, audit_report = _load_case_for_overview(case_id, output_root=output_root, cases_root=cases_root)
        return {
            "case_id": result.case_id,
            "snapshot": _snapshot_payload(case_id, cases_root, output_root, result),
            "authoritative_result": _authoritative_result_payload(result, seal.sha256),
            "seal": {
                "status": "VERIFIED",
                "result_sha256": seal.sha256,
                "canonicalize_version": seal.canonicalize_version,
            },
            "audit": _audit_status_payload(audit_report),
            "investigation": _empty_investigation_payload(),
        }

    @app.get("/cases/{case_id}/result")
    def get_case_result(case_id: str) -> dict[str, Any]:
        result, seal, _ = _load_case_for_overview(case_id, output_root=output_root, cases_root=cases_root)
        return _authoritative_result_payload(result, seal.sha256)

    @app.get("/cases/{case_id}/audit")
    def get_case_audit(case_id: str) -> dict[str, Any]:
        _, _, audit_report = _load_case_for_overview(case_id, output_root=output_root, cases_root=cases_root)
        return _audit_status_payload(audit_report)

    @app.get("/cases/{case_id}/evidence")
    def get_case_evidence(case_id: str) -> dict[str, Any]:
        result, _, _ = _load_case_for_overview(case_id, output_root=output_root, cases_root=cases_root)
        if cases_root is None:
            raise ApiError(500, "internal_error", "evidence access is not configured on this server", "server_error")
        try:
            evidence = _evidence_payload(case_id, cases_root, result)
        except FrozenSnapshotError as exc:
            raise ApiError(422, "invalid_authority", f"evidence could not be re-verified: {exc}", "authority_error") from None
        return {"evidence": evidence}

    @app.get("/cases/{case_id}/investigation")
    def get_case_investigation(case_id: str) -> dict[str, Any]:
        _load_case_for_overview(case_id, output_root=output_root, cases_root=cases_root)
        return _empty_investigation_payload()

    @app.get("/cases/{case_id}/reports/{fmt}")
    def get_case_report(case_id: str, fmt: str) -> dict[str, Any]:
        if fmt not in _REPORT_CONTENT_TYPES:
            raise ApiError(400, "invalid_request", "unsupported report format", "invalid_request_error")
        _load_case_for_overview(case_id, output_root=output_root, cases_root=cases_root)
        return {
            "format": fmt,
            "content_type": _REPORT_CONTENT_TYPES[fmt],
            "download_url": f"/cases/{case_id}/reports/{fmt}/download",
        }

    @app.get("/cases/{case_id}/reports/{fmt}/download")
    def download_case_report(case_id: str, fmt: str) -> Response:
        """Render the report on demand from the same sealed result/seal
        `zaynor report` uses (report.py::render_markdown/html/pdf) -- no
        separate rendering path, no pre-generation required.
        """
        if fmt not in _REPORT_CONTENT_TYPES:
            raise ApiError(400, "invalid_request", "unsupported report format", "invalid_request_error")
        result, seal, _ = _load_case_for_overview(case_id, output_root=output_root, cases_root=cases_root)
        from zaynor.report import ReportError, render_html, render_markdown, render_pdf

        try:
            if fmt == "md":
                rendered: str | bytes = render_markdown(result, seal)
            elif fmt == "html":
                rendered = render_html(result, seal)
            else:
                rendered = render_pdf(result, seal)
        except ReportError as exc:
            raise ApiError(500, "internal_error", str(exc), "server_error") from None
        media_type = _REPORT_CONTENT_TYPES[fmt]
        body = rendered if isinstance(rendered, bytes) else rendered.encode("utf-8")
        return Response(content=body, media_type=media_type)

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
