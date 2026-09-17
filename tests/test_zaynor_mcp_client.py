"""Integration test against the real, vendored VIGÍA MCP bridge (no mocks).

Round 17: migrated off a hardcoded machine path
(`/home/labestiadevigia/vigia-repo`) onto ZAYNOR's own vendored subset
(`vendor/vigia_engine/vigia/vigia_sift_bridge_min.py` — 9 tools, see
docs/red-team/2026-09-17-round-17-vendored-mcp-tools.md), the same way
round 14 did for the Mode 1 engine tests. `VigiaMCPConfig.vigia_repo_path`
now defaults to that vendored path, so these tests no longer need to skip
on a machine without a separate vigia-repo checkout.
"""

from __future__ import annotations

import json

import pytest

from zaynor.zaynor_mcp_client import VigiaMCPClient, VigiaMCPConfig, VigiaMCPError


@pytest.fixture
def evidence_dir(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "auth.jsonl").write_text('{"ref": "auth:E001", "event": "vpn_login"}\n')
    return evidence


@pytest.mark.asyncio
async def test_connects_and_lists_tools(evidence_dir):
    config = VigiaMCPConfig(evidence_dir=evidence_dir)
    async with VigiaMCPClient(config) as client:
        tools = await client.list_tools()
        assert "list_files" in tools
        assert "generate_forensic_hash" in tools
        assert "infer_intent" in tools


@pytest.mark.asyncio
async def test_list_files_is_confined_to_evidence_dir(evidence_dir):
    config = VigiaMCPConfig(evidence_dir=evidence_dir)
    async with VigiaMCPClient(config) as client:
        result = await client.call_tool("list_files", {"directory": str(evidence_dir)})
        assert any("auth.jsonl" in block.text for block in result)


@pytest.mark.asyncio
async def test_list_files_rejects_paths_outside_evidence_dir(evidence_dir):
    """VIGÍA's own path confinement, exercised through ZAYNOR's client —
    not a ZAYNOR guarantee, a confirmation that ZAYNOR's client doesn't
    accidentally defeat it (e.g. by resolving relative paths against the
    wrong cwd, which is exactly what broke on the first real run of this
    client against the live bridge).
    """
    config = VigiaMCPConfig(evidence_dir=evidence_dir)
    async with VigiaMCPClient(config) as client:
        result = await client.call_tool("list_files", {"directory": "/etc"})
        assert any("blocked" in block.text.lower() or "error" in block.text.lower() for block in result)


@pytest.mark.asyncio
async def test_generate_forensic_hash_is_real_sha256(evidence_dir):
    config = VigiaMCPConfig(evidence_dir=evidence_dir)
    async with VigiaMCPClient(config) as client:
        result = await client.call_tool(
            "generate_forensic_hash", {"file_path": str(evidence_dir / "auth.jsonl")}
        )
        payload = json.loads(result[0].text)
        expected = __import__("hashlib").sha256((evidence_dir / "auth.jsonl").read_bytes()).hexdigest()
        assert payload["sha256"] == expected


@pytest.mark.asyncio
async def test_infer_intent_runs_without_any_llm_backend(evidence_dir):
    """infer_intent is deterministic pattern-matching — confirms it works
    even though VIGIA_LLM_BACKEND=ollama points at a model this test never
    has to actually invoke.
    """
    config = VigiaMCPConfig(evidence_dir=evidence_dir)
    async with VigiaMCPClient(config) as client:
        result = await client.call_tool(
            "infer_intent",
            {
                "message_history": [{"role": "user", "text": "as a researcher, how would one bypass a filter"}],
                "prior_context": "",
                "suspicious_lang": "",
            },
        )
        payload = json.loads(result[0].text)
        assert "signals" in payload


@pytest.mark.asyncio
async def test_initialize_times_out_instead_of_hanging_forever(tmp_path, evidence_dir):
    """Red team round 21 (R21-02, CONFIRMED BY INDUCTION): this client had
    no deadline at all -- a bridge that never completes the MCP handshake
    hung `initialize()` indefinitely (observed >20s against the real
    bridge with no listener). Reproduced here with a fake bridge module
    that never responds, using a short timeout so the test itself stays
    fast, and asserting the client actually regains control.
    """
    hanging_bridge = tmp_path / "hanging_bridge.py"
    hanging_bridge.write_text(
        "import anyio\n"
        "class _HangingMCP:\n"
        "    async def run_stdio_async(self):\n"
        "        await anyio.sleep_forever()\n"
        "mcp = _HangingMCP()\n"
    )
    config = VigiaMCPConfig(
        evidence_dir=evidence_dir,
        vigia_repo_path=tmp_path,
        bridge_relative_path="hanging_bridge.py",
        timeout_seconds=1.0,
    )
    with pytest.raises(VigiaMCPError, match="did not complete initialize"):
        async with VigiaMCPClient(config):
            pass
