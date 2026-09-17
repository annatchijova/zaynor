"""Suggested Ollama models by hardware tier — none of them is required.

The narrator sits outside the decision path (CLAUDE.md 5.1): swapping the
model changes only the wording, never the verdict or the seal. Nobody
running Zaynor should be forced onto one specific model just to get a
narration — this list exists to help someone with nothing pulled yet pick a
reasonable starting point for their own hardware, not to gate anything.
"""

from __future__ import annotations

from dataclasses import dataclass

_FALLBACK_MODEL = "llama3.1:8b"


@dataclass(frozen=True)
class SuggestedModel:
    name: str
    tier: str
    note: str


SUGGESTED_MODELS: tuple[SuggestedModel, ...] = (
    SuggestedModel("llama3.2:1b", "ligero", "CPU sin GPU, poca RAM libre"),
    SuggestedModel("qwen2.5:1.5b", "ligero", "alternativa a llama3.2:1b, buen español"),
    SuggestedModel("llama3.1:8b", "medio", "GPU chica o 16GB+ de RAM"),
    SuggestedModel("hermes3:8b", "medio", "el modelo mediano que VIGÍA ya sugiere en su propio modo Ollama"),
    SuggestedModel("deepseek-r1:8b", "medio", "razonamiento paso a paso; el que usa vigia_ask.sh"),
    SuggestedModel("gemma3:27b", "grande", "GPU potente; el modelo grande que VIGÍA ya sugiere en su propio modo Ollama"),
)
