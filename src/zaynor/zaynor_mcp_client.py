"""Zaynor's MCP client for VIGÍA's bridge — the local, Ollama-only
replacement for what VIGÍA's own docs call "Mode 2" (there, a Claude Code
session drives the same bridge over the Anthropic API; the hackathon rules
forbid any non-local AI in the shipped product, so Zaynor drives it itself
instead, backed by Ollama for `reason_with_llm` and needing no LLM at all
for the deterministic tools).

Confirmed by reading `vigia_sift_bridge.py` directly before writing this
client (not assumed from its docs):

- Startup requires no cloud credential. `if __name__ == "__main__"` checks
  stdlib integrity and derives a session nonce, then calls `mcp.run()` —
  no `ANTHROPIC_API_KEY` read anywhere except a redaction allowlist for
  audit logging.
- It serves over stdio unconditionally (`mcp.run()` takes no transport
  argument), so any standard MCP client can drive it — nothing here is
  Claude-Code-specific.
- Most tools (`list_files`, `read_evidence`, `generate_forensic_hash`,
  `infer_intent`, `cross_artifact_analysis`/CAIE) are deterministic
  pattern-matching/scoring functions with no LLM call inside them.
  `reason_with_llm` is the one tool that calls an LLM, and its own
  docstring states it supports `VIGIA_LLM_BACKEND=ollama` explicitly.
- `VIGIA_HMAC_KEY`/`VIGIA_HMAC_KEY_FILE` are optional — their absence
  degrades the tool-call audit chain to hash-only mode, documented as such
  by VIGÍA itself, not a startup requirement.

This module only connects and calls tools; it does not decide which tool
to call — that is the investigator's job (see `investigation_log.py`),
driven by ZAYNOR's own Ollama client (`ollama_client.py`), not by this
module.
"""

from __future__ import annotations

import os
import sys
import urllib.parse
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


class VigiaMCPError(RuntimeError):
    """A VIGÍA MCP call could not be completed or returned a tool-level error."""


# Red-team round 7 (RT-05, per Codex's fuller report): these are set/cleared
# deliberately, in this order, to guarantee the bridge subprocess never gets
# a cloud AI backend or an evidence directory other than the one this
# config names — the hackathon's local-only-AI rule and the case-boundary
# guarantee both depend on it. `extra_env` used to apply after them
# unconditionally, so a config built from anything other than fully-trusted
# code (a future config loader, a value threaded through from user input)
# could silently re-enable a cloud backend or repoint evidence/PYTHONPATH.
_PROTECTED_ENV_KEYS = frozenset(
    {
        "VIGIA_EVIDENCE_DIR",
        "VIGIA_LLM_BACKEND",
        "VIGIA_OLLAMA_MODEL",
        "VIGIA_OLLAMA_HOST",
        "PYTHONPATH",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_VERTEX_PROJECT_ID",
        "GOOGLE_CLOUD_PROJECT",
        "CLOUD_ML_REGION",
    }
)


def _local_ollama_url(value: str) -> str:
    """Same local-only contract as `agents/ollama_client.py`'s
    `_local_url` (that module's version stays private to it; duplicated
    here in miniature rather than imported, since raising `VigiaMCPError`
    — this module's own error type — matters more than sharing four lines).
    """
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise VigiaMCPError("ollama_host must be local-only (http://127.0.0.1, localhost, or ::1)")
    return value


def _default_vendored_vigia_path() -> Path:
    """ZAYNOR's own vendored VIGÍA subset (`vendor/vigia_engine/`).

    Computed independently of `vendored_engine.py`'s `VENDORED_ENGINE_PATH`
    (same idea, same directory) so this module has no import-time dependency
    on that file. Same reasoning as `cli.py`'s `_default_engine_repo()` for
    Mode 1: bundled with the repo, so defaulting to it does not "silently
    break on any other checkout" the way a path on one development machine
    would — that concern is what the field's docstring below still guards
    against for anyone overriding it.
    """
    import zaynor

    return Path(zaynor.__file__).resolve().parent.parent.parent / "vendor" / "vigia_engine"


def _zaynor_mcp_runner_path() -> Path:
    import zaynor

    return Path(zaynor.__file__).resolve().parent / "vigia_mcp_runner.py"


_DEFAULT_BRIDGE_RELATIVE_PATH = "vigia/vigia_sift_bridge_min.py"


@dataclass(frozen=True)
class VigiaMCPConfig:
    """Everything needed to launch the bridge as a local, offline subprocess.

    `vigia_repo_path` defaults to ZAYNOR's own vendored subset (round 17: 9
    tools, see docs/red-team/2026-09-17-round-17-vendored-mcp-tools.md) —
    bundled with this repo, not a path on one development machine. Passing
    an external checkout still works for the full 22-tool bridge; pair it
    with `bridge_relative_path="vigia/vigia_sift_bridge.py"` (the vendored
    subset uses a different filename precisely so the two are never
    confused for each other). `evidence_dir` has no reasonable default and
    stays required.
    """

    evidence_dir: Path
    vigia_repo_path: Path = field(default_factory=_default_vendored_vigia_path)
    bridge_relative_path: str = _DEFAULT_BRIDGE_RELATIVE_PATH
    python_executable: str = field(default_factory=lambda: sys.executable)
    ollama_host: str = "http://127.0.0.1:11434"
    ollama_model: str = "deepseek-r1:8b"
    extra_env: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _local_ollama_url(self.ollama_host)
        collisions = _PROTECTED_ENV_KEYS & self.extra_env.keys()
        if collisions:
            raise VigiaMCPError(
                f"extra_env cannot override the local-only/evidence-boundary "
                f"variables {sorted(collisions)} — set them via the named "
                "VigiaMCPConfig fields instead"
            )

    def server_params(self) -> StdioServerParameters:
        bridge_path = self.vigia_repo_path / self.bridge_relative_path
        if not bridge_path.is_file():
            raise VigiaMCPError(f"VIGÍA bridge not found at {bridge_path}")
        if not self.evidence_dir.is_dir():
            raise VigiaMCPError(f"evidence_dir does not exist: {self.evidence_dir}")

        env = dict(os.environ)
        # Strip anything that could route a tool call to a cloud backend,
        # mirroring launch_vigia_mcp.sh's own unset list — belt and
        # suspenders, since VIGIA_LLM_BACKEND alone already selects Ollama.
        for cloud_var in ("ANTHROPIC_API_KEY", "ANTHROPIC_VERTEX_PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "CLOUD_ML_REGION"):
            env.pop(cloud_var, None)
        env.update(self.extra_env)  # __post_init__ already rejects any protected key here
        env.update(
            {
                "VIGIA_EVIDENCE_DIR": str(self.evidence_dir),
                "VIGIA_LLM_BACKEND": "ollama",
                "VIGIA_OLLAMA_MODEL": self.ollama_model,
                "VIGIA_OLLAMA_HOST": self.ollama_host,
                "PYTHONPATH": str(self.vigia_repo_path),
            }
        )

        return StdioServerParameters(
            command=self.python_executable,
            args=[str(_zaynor_mcp_runner_path()), str(bridge_path)],
            env=env,
            cwd=str(self.vigia_repo_path),
        )


class VigiaMCPClient:
    """Async context manager around one VIGÍA bridge subprocess + session.

    Usage:
        async with VigiaMCPClient(config) as client:
            tools = await client.list_tools()
            result = await client.call_tool("list_files", {"directory": "."})
    """

    def __init__(self, config: VigiaMCPConfig):
        self._config = config
        self._stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None

    async def __aenter__(self) -> "VigiaMCPClient":
        self._stack = AsyncExitStack()
        try:
            read, write = await self._stack.enter_async_context(
                stdio_client(self._config.server_params())
            )
            session = await self._stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
        except Exception:
            await self._stack.aclose()
            self._stack = None
            raise
        self._session = session
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._stack is not None:
            await self._stack.aclose()
        self._session = None
        self._stack = None

    def _require_session(self) -> ClientSession:
        if self._session is None:
            raise VigiaMCPError("VigiaMCPClient is not connected — use it as `async with`")
        return self._session

    async def list_tools(self) -> list[str]:
        result = await self._require_session().list_tools()
        return [tool.name for tool in result.tools]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        """Call one allowlisted VIGÍA tool by name and return its content.

        Raises `VigiaMCPError` on a protocol-level error (`isError=True`) or
        if the tool is not present on this bridge — never returns a
        malformed or partial result silently.
        """
        session = self._require_session()
        result = await session.call_tool(name, arguments)
        if result.isError:
            raise VigiaMCPError(f"VIGÍA tool {name!r} returned an error: {result.content!r}")
        return result.content
