"""Unit tests for `VigiaMCPConfig`'s security invariants — construction
only, no real VIGÍA bridge subprocess needed, so these run unconditionally
(unlike test_zaynor_mcp_client.py, which skips without a vigia-repo
checkout).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from zaynor.zaynor_mcp_client import VigiaMCPConfig, VigiaMCPError


def _config(**overrides):
    defaults = dict(vigia_repo_path=Path("/vigia-repo"), evidence_dir=Path("/evidence"))
    defaults.update(overrides)
    return VigiaMCPConfig(**defaults)


def test_ollama_host_rejects_a_remote_url():
    """Red-team round 7 (RT-05, per Codex's fuller report): before this
    fix, `VigiaMCPConfig.ollama_host` had no validation at all, unlike
    `agents/ollama_client.py`'s `OllamaClient`, which already enforces the
    hackathon's local-only-AI rule for the same kind of value.
    """
    with pytest.raises(VigiaMCPError, match="local-only"):
        _config(ollama_host="https://example.invalid")
    with pytest.raises(VigiaMCPError, match="local-only"):
        _config(ollama_host="http://10.0.0.4:11434")


def test_ollama_host_accepts_localhost_variants():
    _config(ollama_host="http://127.0.0.1:11434")
    _config(ollama_host="http://localhost:11434")


def test_extra_env_cannot_override_the_local_only_backend():
    """Confirmed by induction: before this fix, `extra_env` applied last
    and unconditionally, so `extra_env={"VIGIA_LLM_BACKEND": "anthropic",
    "ANTHROPIC_API_KEY": "sk-..."}` would have silently defeated the
    hackathon's local-only-AI guarantee this same class already documents
    enforcing for `OllamaClient`.
    """
    with pytest.raises(VigiaMCPError, match="extra_env"):
        _config(extra_env={"VIGIA_LLM_BACKEND": "anthropic"})
    with pytest.raises(VigiaMCPError, match="extra_env"):
        _config(extra_env={"ANTHROPIC_API_KEY": "sk-forged"})
    with pytest.raises(VigiaMCPError, match="extra_env"):
        _config(extra_env={"VIGIA_EVIDENCE_DIR": "/somewhere-else"})
    with pytest.raises(VigiaMCPError, match="extra_env"):
        _config(extra_env={"PYTHONPATH": "/attacker-controlled"})


def test_extra_env_accepts_unrelated_keys():
    config = _config(extra_env={"SOME_UNRELATED_TOOL_FLAG": "1"})
    assert config.extra_env == {"SOME_UNRELATED_TOOL_FLAG": "1"}
