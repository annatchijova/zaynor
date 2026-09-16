"""Integration test against the real VIGÍA bridge (no mocks).

Skips cleanly if the vigia-repo checkout this machine happens to have isn't
present — this test documents and exercises the real integration surface,
but ZAYNOR's own unit tests must not hard-depend on a sibling repo's exact
location on disk.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from zaynor.zaynor_mcp_client import VigiaMCPClient, VigiaMCPConfig

VIGIA_REPO_PATH = Path("/home/labestiadevigia/vigia-repo")

pytestmark = pytest.mark.skipif(
    not (VIGIA_REPO_PATH / "vigia" / "vigia_sift_bridge.py").is_file(),
    reason="vigia-repo checkout not present on this machine",
)


@pytest.fixture
def evidence_dir(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "auth.jsonl").write_text('{"ref": "auth:E001", "event": "vpn_login"}\n')
    return evidence


@pytest.mark.asyncio
async def test_connects_and_lists_tools(evidence_dir):
    config = VigiaMCPConfig(vigia_repo_path=VIGIA_REPO_PATH, evidence_dir=evidence_dir)
    async with VigiaMCPClient(config) as client:
        tools = await client.list_tools()
        assert "list_files" in tools
        assert "generate_forensic_hash" in tools
        assert "infer_intent" in tools


@pytest.mark.asyncio
async def test_list_files_is_confined_to_evidence_dir(evidence_dir):
    config = VigiaMCPConfig(vigia_repo_path=VIGIA_REPO_PATH, evidence_dir=evidence_dir)
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
    config = VigiaMCPConfig(vigia_repo_path=VIGIA_REPO_PATH, evidence_dir=evidence_dir)
    async with VigiaMCPClient(config) as client:
        result = await client.call_tool("list_files", {"directory": str(VIGIA_REPO_PATH)})
        assert any("blocked" in block.text.lower() or "error" in block.text.lower() for block in result)


@pytest.mark.asyncio
async def test_generate_forensic_hash_is_real_sha256(evidence_dir):
    config = VigiaMCPConfig(vigia_repo_path=VIGIA_REPO_PATH, evidence_dir=evidence_dir)
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
    config = VigiaMCPConfig(vigia_repo_path=VIGIA_REPO_PATH, evidence_dir=evidence_dir)
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
