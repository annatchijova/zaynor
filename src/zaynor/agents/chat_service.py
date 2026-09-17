"""Shared seal-verified chat path for the `zaynor chat` CLI and `zaynor serve` API.

Both entry points ask a question about an already-analyzed, sealed case and
return a hallucination-checked narration (`Mentor.chat_checked`). Keeping the
logic in one place avoids two independently-drifting, ad-hoc reimplementations
of the same seal-verified chat path.
"""

from __future__ import annotations

import json

from zaynor.hallucination_guard import GuardResult
from zaynor.schemas import ZaynorAuthoritativeResult
from zaynor.authority_seal import AuthoritySeal

from .contracts import Audience, UntrustedContext
from .mentor import Mentor
from .ollama_client import OllamaClient


def result_context(result: ZaynorAuthoritativeResult) -> UntrustedContext:
    """The sealed result, compressed to what a narration needs to talk about.

    Without this, `Mentor.chat` has no information about the case at all —
    `check_narrative` independently verifies claims against `result`
    regardless, but the model has nothing to narrate correctly without seeing
    a summary of it first.
    """
    summary = {
        "case_id": result.case_id,
        "verdict": result.verdict,
        "confidence": result.integrity.get("confidence", "UNKNOWN"),
        "unknowns": list(result.unknowns),
        "findings": [
            {
                "finding_id": finding.finding_id,
                "state": finding.state,
                "rationale": finding.rationale,
                "mitre": finding.mitre,
            }
            for finding in result.findings
        ],
    }
    encoded = json.dumps(summary, ensure_ascii=False, sort_keys=True)
    return UntrustedContext(source="zaynor_result_summary", content=encoded)


def answer_question(
    question: str,
    *,
    result: ZaynorAuthoritativeResult,
    seal: AuthoritySeal,
    client: OllamaClient,
    audience: Audience = Audience.SENIOR,
) -> GuardResult:
    if not isinstance(question, str) or not question.strip():
        raise ValueError("question must not be empty")
    return Mentor(client).chat_checked(
        question,
        audience=audience,
        result=result,
        seal=seal,
        contexts=(result_context(result),),
    )
