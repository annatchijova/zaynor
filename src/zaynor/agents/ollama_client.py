"""Small local-only Ollama client; no cloud fallback."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
import re


_MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


class OllamaError(RuntimeError):
    """Ollama is unavailable or returned an invalid response."""


def _local_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise OllamaError("Ollama endpoint must be local-only")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise OllamaError("Ollama endpoint must not contain a path or query")
    return value.rstrip("/")


@dataclass(frozen=True)
class OllamaClient:
    host: str = "http://127.0.0.1:11434"
    model: str = "llama3.1:8b"
    timeout_seconds: int = 120

    def __post_init__(self) -> None:
        _local_url(self.host)
        if not _MODEL_NAME.fullmatch(self.model) or self.timeout_seconds <= 0:
            raise OllamaError("model and timeout must be valid")

    def generate(self, *, system: str, prompt: str) -> str:
        payload = json.dumps(
            {"model": self.model, "system": system, "prompt": prompt, "stream": False},
            ensure_ascii=False,
        ).encode("utf-8")
        request = urllib.request.Request(
            _local_url(self.host) + "/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                body = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise OllamaError(f"local Ollama request failed: {exc}") from exc
        text = body.get("response") if isinstance(body, dict) else None
        if not isinstance(text, str):
            raise OllamaError("Ollama response does not contain text")
        return text


def list_available_models(host: str = "http://127.0.0.1:11434", *, timeout_seconds: int = 10) -> list[str]:
    """Return the names of models already pulled into this local Ollama.

    Used by `zaynor models` to show what is actually installed, next to the
    suggested catalog — nobody is required to have any specific model pulled.
    """
    if timeout_seconds <= 0:
        raise OllamaError("Ollama timeout must be positive")
    request = urllib.request.Request(_local_url(host) + "/api/tags", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        raise OllamaError(f"could not list local Ollama models: {exc}") from exc
    models = body.get("models") if isinstance(body, dict) else None
    if not isinstance(models, list):
        raise OllamaError("Ollama /api/tags response has an unexpected shape")
    return [entry["name"] for entry in models if isinstance(entry, dict) and isinstance(entry.get("name"), str)]
