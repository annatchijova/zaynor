from pathlib import Path
import asyncio

import pytest

from zaynor.auxiliary_mcp_client import (
    AuxiliaryMCPClient, AuxiliaryMCPConfig, AuxiliaryMCPError,
    CRONOS_TOOLS, MNEME_TOOLS, cronos_config, mneme_config,
)


def test_servers_have_separate_allowlists(tmp_path):
    assert cronos_config(tmp_path / "cronos", tmp_path / "c.db").allowed_tools == CRONOS_TOOLS
    assert mneme_config(tmp_path / "mneme", tmp_path / "m.db").allowed_tools == MNEME_TOOLS
    assert CRONOS_TOOLS.isdisjoint(MNEME_TOOLS)


def test_invalid_server_and_relative_database_fail_closed(tmp_path):
    config = AuxiliaryMCPConfig("mneme", tmp_path / "missing.py", MNEME_TOOLS, Path("db.sqlite"))
    with pytest.raises(AuxiliaryMCPError, match="regular file"):
        config.server_params()
    script = tmp_path / "server.py"
    script.write_text("# test", encoding="utf-8")
    config = AuxiliaryMCPConfig("mneme", script, MNEME_TOOLS, Path("db.sqlite"))
    with pytest.raises(AuxiliaryMCPError, match="absolute"):
        config.server_params()


def test_unallowlisted_call_is_rejected_before_connection(tmp_path):
    client = AuxiliaryMCPClient(
        AuxiliaryMCPConfig("mneme", tmp_path / "missing.py", MNEME_TOOLS, tmp_path / "db.sqlite")
    )
    with pytest.raises(AuxiliaryMCPError, match="not allowlisted"):
        asyncio.run(client.call_tool("mneme_reinforce", {}))


def test_protected_environment_overrides_are_rejected(tmp_path):
    config = AuxiliaryMCPConfig(
        "mneme", tmp_path / "server.py", MNEME_TOOLS, tmp_path / "db.sqlite",
        extra_env={"PYTHONPATH": "/tmp/hostile"},
    )
    with pytest.raises(AuxiliaryMCPError, match="protected"):
        config.server_params()


def test_tool_timeout_fails_closed(tmp_path):
    class HangingSession:
        async def call_tool(self, name, arguments):
            await asyncio.sleep(1)

    config = AuxiliaryMCPConfig(
        "mneme", tmp_path / "server.py", MNEME_TOOLS, tmp_path / "db.sqlite",
        timeout_seconds=0.01,
    )
    client = AuxiliaryMCPClient(config)
    client._session = HangingSession()
    with pytest.raises(AuxiliaryMCPError, match="timed out"):
        asyncio.run(client.call_tool("mneme_info", {}))
