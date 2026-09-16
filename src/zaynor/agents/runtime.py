"""Bounded Ollama tool loop for ZAYNOR agents."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any

from .contracts import AgentRole, ToolRequest, UntrustedContext
from .ollama_client import OllamaClient
from .policy import authorize_tool
from .registry import require_approved, spec_for


class AgentRuntimeError(RuntimeError):
    """The local model produced an unsafe or unusable agent turn."""


ToolHandler = Callable[[dict[str, Any]], Any]


class AgentRuntime:
    """Run one bounded agent loop with deterministic tool authorization."""

    def __init__(self, client: OllamaClient, *, max_steps: int = 8):
        if max_steps <= 0:
            raise ValueError("max_steps must be positive")
        self._client = client
        self._max_steps = max_steps

    def run(
        self,
        role: AgentRole,
        *,
        system: str,
        prompt: str,
        tools: Mapping[str, ToolHandler] | None = None,
    ) -> str:
        handlers = dict(tools or {})
        approved = spec_for(role)
        require_approved(role, approved.tools)
        if not set(handlers).issubset(approved.tools):
            raise AgentRuntimeError("bound tool set exceeds the approved agent contract")
        transcript = [f"<operator-request>\n{prompt}\n</operator-request>"]

        for _ in range(self._max_steps):
            response = self._client.generate(system=system, prompt="\n\n".join(transcript))
            message = self._parse_response(response)
            if message["type"] == "final":
                return message["text"]

            request = ToolRequest(message["tool"], message["arguments"])
            authorize_tool(role, request)
            handler = handlers.get(request.tool)
            if handler is None:
                raise AgentRuntimeError(f"tool {request.tool!r} was not bound")
            try:
                result = handler(request.arguments)
                json.dumps(result, ensure_ascii=False)
            except Exception as exc:  # tool failures are data, not model instructions
                result = {"error": f"tool failed: {type(exc).__name__}: {exc}"}
            context = UntrustedContext(f"tool:{request.tool}", json.dumps(result, ensure_ascii=False))
            transcript.append(
                f"<tool-call name={request.tool!r}>\n"
                f"{json.dumps(request.arguments, ensure_ascii=False, sort_keys=True)}\n"
                "</tool-call>"
            )
            transcript.append(context.as_prompt_block())

        raise AgentRuntimeError("agent exceeded its step budget")

    @staticmethod
    def _parse_response(response: str) -> dict[str, Any]:
        try:
            value = json.loads(response)
        except (TypeError, json.JSONDecodeError) as exc:
            raise AgentRuntimeError("agent response must be a JSON object") from exc
        if not isinstance(value, dict) or value.get("type") not in {"final", "tool_call"}:
            raise AgentRuntimeError("agent response has an invalid type")
        if value["type"] == "final":
            if not isinstance(value.get("text"), str) or not value["text"].strip():
                raise AgentRuntimeError("final agent response requires nonempty text")
        else:
            if not isinstance(value.get("tool"), str) or not isinstance(value.get("arguments"), dict):
                raise AgentRuntimeError("tool_call requires tool and object arguments")
        return value
