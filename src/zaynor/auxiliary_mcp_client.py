"""Clients for the optional local CRONOS and MNEME MCP servers."""

from __future__ import annotations

import os
import asyncio
import sys
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


class AuxiliaryMCPError(RuntimeError):
    """An auxiliary MCP server could not be safely used."""


CRONOS_TOOLS = frozenset({
    "cronos_open_trace", "cronos_record_recall", "cronos_record_tool_call",
    "cronos_add_hypothesis", "cronos_add_evidence", "cronos_discard_hypothesis",
    "cronos_close_trace", "cronos_explain_trace", "cronos_list_traces",
    "cronos_verify_chain",
})

# MNEME's server may expose more tools as its protocol evolves. This is the
# deliberately narrow ZAYNOR surface; authority, grants, claims, and state
# mutation tools stay outside ordinary agent/chat access.
MNEME_TOOLS = frozenset({
    "mneme_custody_chain",
    "mneme_verify_bundle", "mneme_info",
})

_PROTECTED_ENV_KEYS = frozenset({
    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PATH", "LD_PRELOAD",
    "CRONOS_DB_PATH", "MNEME_DB_PATH", "SLACK_BOT_TOKEN",
})


@dataclass(frozen=True)
class AuxiliaryMCPConfig:
    name: str
    server_script: Path
    allowed_tools: frozenset[str]
    database_path: Path
    python_executable: str = field(default_factory=lambda: sys.executable)
    timeout_seconds: float = 30.0
    extra_env: dict[str, str] = field(default_factory=dict)

    def server_params(self) -> StdioServerParameters:
        if self.timeout_seconds <= 0:
            raise AuxiliaryMCPError("auxiliary MCP timeout_seconds must be positive")
        collisions = _PROTECTED_ENV_KEYS & self.extra_env.keys()
        if collisions:
            raise AuxiliaryMCPError(f"extra_env cannot override protected keys: {sorted(collisions)}")
        if self.server_script.is_symlink():
            raise AuxiliaryMCPError(f"{self.name} MCP server cannot be a symlink")
        script = self.server_script.resolve()
        if not script.is_file():
            raise AuxiliaryMCPError(f"{self.name} MCP server is not a regular file")
        if not self.database_path.is_absolute():
            raise AuxiliaryMCPError("auxiliary MCP database_path must be absolute")
        env = dict(os.environ)
        env.update(self.extra_env)
        if self.name == "cronos":
            env["CRONOS_DB_PATH"] = str(self.database_path)
            env.pop("SLACK_BOT_TOKEN", None)
        elif self.name == "mneme":
            env["MNEME_DB_PATH"] = str(self.database_path)
        return StdioServerParameters(
            command=self.python_executable, args=[str(script)],
            env=env, cwd=str(script.parent),
        )


def cronos_config(server_root: Path, database_path: Path) -> AuxiliaryMCPConfig:
    return AuxiliaryMCPConfig("cronos", Path(server_root) / "mcp_server.py", CRONOS_TOOLS, Path(database_path))


def mneme_config(server_root: Path, database_path: Path) -> AuxiliaryMCPConfig:
    return AuxiliaryMCPConfig("mneme", Path(server_root) / "mcp_server.py", MNEME_TOOLS, Path(database_path))


class AuxiliaryMCPClient:
    """Async client for one local server with a closed tool surface."""

    def __init__(self, config: AuxiliaryMCPConfig):
        self._config = config
        self._stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None

    async def __aenter__(self) -> "AuxiliaryMCPClient":
        self._stack = AsyncExitStack()
        try:
            await asyncio.wait_for(self._connect(), self._config.timeout_seconds)
        except Exception as exc:
            try:
                await asyncio.wait_for(self._stack.aclose(), 1.0)
            except Exception:
                pass
            self._stack = None
            self._session = None
            raise AuxiliaryMCPError(f"{self._config.name} MCP initialization failed") from exc
        return self

    async def _connect(self) -> None:
        read, write = await self._stack.enter_async_context(
            stdio_client(self._config.server_params())
        )
        self._session = await self._stack.enter_async_context(ClientSession(read, write))
        await self._session.initialize()

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._stack is not None:
            await self._stack.aclose()
        self._stack = None
        self._session = None

    async def list_tools(self) -> list[str]:
        if self._session is None:
            raise AuxiliaryMCPError("auxiliary MCP client is not connected")
        try:
            result = await asyncio.wait_for(self._session.list_tools(), self._config.timeout_seconds)
        except asyncio.TimeoutError as exc:
            raise AuxiliaryMCPError(f"{self._config.name} MCP list_tools timed out") from exc
        return [tool.name for tool in result.tools if tool.name in self._config.allowed_tools]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        if name not in self._config.allowed_tools:
            raise AuxiliaryMCPError(f"tool {name!r} is not allowlisted for {self._config.name}")
        if self._session is None:
            raise AuxiliaryMCPError("auxiliary MCP client is not connected")
        try:
            result = await asyncio.wait_for(
                self._session.call_tool(name, arguments), self._config.timeout_seconds
            )
        except asyncio.TimeoutError as exc:
            raise AuxiliaryMCPError(f"{self._config.name} MCP tool timed out") from exc
        if result.isError:
            raise AuxiliaryMCPError(f"{self._config.name} MCP tool failed")
        return result.content
