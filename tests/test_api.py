import json
import shutil
import textwrap
from pathlib import Path

from fastapi.testclient import TestClient

from zaynor.agents.ollama_client import OllamaClient
from zaynor.api import create_app
from zaynor.cli import main

FIXTURE = Path(__file__).parent.parent / "scenarios" / "inc-2026-demo-001" / "telemetry.jsonl"


def _analyzed_case(tmp_path: Path, capsys):
    scenario = tmp_path / "scenario"
    shutil.copytree(FIXTURE.parent, scenario)
    cases_root = tmp_path / "cases"
    assert main([
        "freeze", "--case-id", "INC-API-CASE", "--evidence-profile",
        "admin-session-investigation", "--profile-map", str(scenario / "evidence_profile.json"),
        "--source-root", str(scenario), "--cases-root", str(cases_root), "--json",
    ]) == 0
    capsys.readouterr()

    engine = tmp_path / "engine"
    engine.mkdir()
    (engine / "vigia_agent.py").write_text(textwrap.dedent("""
        import hashlib, json, pathlib, sys
        evidence = pathlib.Path(sys.argv[sys.argv.index('--evidence') + 1])
        output = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])
        digest = hashlib.sha256()
        for path in sorted(evidence.rglob('*')):
            if path.is_file():
                digest.update(str(path.relative_to(evidence)).encode())
                digest.update(hashlib.sha256(path.read_bytes()).digest())
        bundle = {'case_id': 'INC-API-CASE', 'evidence_sha256': digest.hexdigest(),
                  'agent_verdict': 'ABSTAIN', 'audit_trail': []}
        raw = json.dumps(bundle).encode()
        output.write_bytes(raw)
        output.with_suffix(output.suffix + '.sha256').write_text(
            hashlib.sha256(raw).hexdigest() + '  ' + str(output) + '\\n')
        sys.exit(4)
    """))
    output_root = tmp_path / "outputs"
    assert main([
        "analyze", "--case-id", "INC-API-CASE", "--cases-root", str(cases_root),
        "--engine-repo", str(engine), "--output-root", str(output_root), "--json",
    ]) == 0
    capsys.readouterr()
    return output_root


def test_health_and_models(tmp_path):
    client = TestClient(create_app(output_root=tmp_path / "outputs"))
    assert client.get("/health").json() == {"status": "zaynor operational"}
    models = client.get("/v1/models").json()
    assert models["data"][0]["id"] == "zaynor-forensic"


def test_cases_lists_only_analyzed_cases(tmp_path, capsys):
    output_root = _analyzed_case(tmp_path, capsys)
    client = TestClient(create_app(output_root=output_root))
    assert client.get("/cases").json() == {"cases": ["INC-API-CASE"]}


def test_chat_completions_answers_a_known_case(tmp_path, capsys, monkeypatch):
    output_root = _analyzed_case(tmp_path, capsys)
    monkeypatch.setattr(
        OllamaClient, "generate", lambda self, *, system, prompt: "The verdict is ABSTAIN."
    )
    client = TestClient(create_app(output_root=output_root))
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "zaynor-forensic",
            "messages": [
                {"role": "user", "content": json.dumps({"case_id": "INC-API-CASE", "question": "Verdict?"})}
            ],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["choices"][0]["message"]["content"] == "The verdict is ABSTAIN."


def test_chat_completions_accepts_plain_text_case_id_prefix(tmp_path, capsys, monkeypatch):
    output_root = _analyzed_case(tmp_path, capsys)
    monkeypatch.setattr(
        OllamaClient, "generate", lambda self, *, system, prompt: "The verdict is ABSTAIN."
    )
    client = TestClient(create_app(output_root=output_root))
    response = client.post(
        "/v1/chat/completions",
        json={"messages": [{"role": "user", "content": "case_id: INC-API-CASE\nWhat happened?"}]},
    )
    content = response.json()["choices"][0]["message"]["content"]
    assert content == "The verdict is ABSTAIN."


def test_chat_completions_returns_usage_guidance_for_garbage_input(tmp_path):
    client = TestClient(create_app(output_root=tmp_path / "outputs"))
    response = client.post(
        "/v1/chat/completions",
        json={"messages": [{"role": "user", "content": "hello"}]},
    )
    content = response.json()["choices"][0]["message"]["content"]
    assert "ZAYNOR Forensic Intelligence API" in content


def test_chat_completions_rejects_an_unknown_case_id(tmp_path):
    client = TestClient(create_app(output_root=tmp_path / "outputs"))
    response = client.post(
        "/v1/chat/completions",
        json={
            "messages": [
                {"role": "user", "content": json.dumps({"case_id": "NEVER-ANALYZED", "question": "Verdict?"})}
            ]
        },
    )
    content = response.json()["choices"][0]["message"]["content"]
    assert "could not answer" in content
