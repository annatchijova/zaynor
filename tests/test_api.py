import json
import shutil
import textwrap
from dataclasses import asdict
from pathlib import Path

from zaynor.agents.ollama_client import OllamaClient, OllamaError
from zaynor.authority_seal import seal_authoritative_result
from zaynor.api import ApiError, CaseChatRequest, ChatRequest, InvestigationProposalRequest, create_app
from zaynor.cli import main
from zaynor.schemas import ZaynorAuthoritativeResult

FIXTURE = Path(__file__).parent.parent / "scenarios" / "inc-2026-demo-001" / "telemetry.jsonl"


def _route(app, path: str):
    return next(route.endpoint for route in app.routes if route.path == path)


def _chat(app, payload):
    return _route(app, "/v1/chat/completions")(ChatRequest.model_validate(payload))


def _case_chat(app, case_id, question):
    return _route(app, "/cases/{case_id}/chat")(case_id, CaseChatRequest(question=question))


def _api_error(call):
    try:
        call()
    except ApiError as exc:
        return exc
    raise AssertionError("expected ApiError")


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


def _stored_case(tmp_path: Path, case_id: str = "CASE-API") -> Path:
    output_root = tmp_path / "outputs"
    case_dir = output_root / case_id
    case_dir.mkdir(parents=True)
    result = ZaynorAuthoritativeResult(
        case_id=case_id,
        engine={"name": "fixture", "version": "1", "configuration_hash": "fixture"},
        verdict="ABSTAIN",
        integrity={"confidence": "HIGH", "score": "0"},
    )
    seal = seal_authoritative_result(result)
    (case_dir / "result.json").write_text(json.dumps(asdict(result)), encoding="utf-8")
    (case_dir / "result.seal.json").write_text(json.dumps(asdict(seal)), encoding="utf-8")
    return output_root


def test_health_and_models(tmp_path):
    app = create_app(output_root=tmp_path / "outputs")
    assert _route(app, "/health")() == {"status": "zaynor operational"}
    models = _route(app, "/v1/models")()
    assert models["data"][0]["id"] == "zaynor-forensic"


def test_cases_lists_only_analyzed_cases(tmp_path, capsys):
    output_root = _analyzed_case(tmp_path, capsys)
    cases = _route(create_app(output_root=output_root), "/cases")()["cases"]
    assert cases == [{
        "case_id": "INC-API-CASE",
        "name": None,
        "has_result": True,
        "has_seal": True,
        "verification": "NOT_CHECKED",
        "verdict": "UNKNOWN",
        "seal_status": "UNKNOWN",
        "updated_at": None,
    }]


def test_cases_do_not_claim_verification_from_file_presence(tmp_path):
    output_root = _stored_case(tmp_path)
    case = _route(create_app(output_root=output_root), "/cases")()["cases"][0]
    assert case["verification"] == "NOT_CHECKED"
    assert case["seal_status"] == "UNKNOWN"


def test_chat_rejects_unsupported_model_and_stream(tmp_path):
    output_root = _stored_case(tmp_path)
    app = create_app(output_root=output_root)
    unsupported = _api_error(lambda: _chat(app, {"model": "other-model", "messages": []}))
    assert unsupported.status_code == 400
    assert unsupported.code == "unsupported_model"
    streamed = _api_error(lambda: _chat(app, {"model": "zaynor-forensic", "messages": [], "stream": True}))
    assert streamed.status_code == 400
    assert streamed.code == "stream_not_supported"


def test_chat_missing_case_returns_safe_structured_error(tmp_path):
    error = _api_error(lambda: _chat(create_app(output_root=tmp_path / "outputs"), {
        "messages": [{"role": "user", "content": json.dumps({"case_id": "NEVER-ANALYZED", "question": "Verdict?"})}]
    }))
    assert error.status_code == 404
    assert error.code == "case_not_found"


def test_chat_rejects_tampered_stored_result_before_ollama(tmp_path, monkeypatch):
    output_root = _stored_case(tmp_path)
    result_path = output_root / "CASE-API" / "result.json"
    payload = json.loads(result_path.read_text())
    payload["verdict"] = "MALICE"
    result_path.write_text(json.dumps(payload))
    calls = []
    monkeypatch.setattr(OllamaClient, "generate", lambda *args, **kwargs: calls.append(True) or "The verdict is MALICE.")

    error = _api_error(lambda: _chat(create_app(output_root=output_root), {
        "messages": [{"role": "user", "content": json.dumps({"case_id": "CASE-API", "question": "Verdict?"})}]
    }))
    assert error.status_code == 422
    assert error.code == "invalid_authority"
    assert calls == []


def test_chat_rejects_invalid_seal_and_case_mismatch(tmp_path, monkeypatch):
    output_root = _stored_case(tmp_path)
    seal_path = output_root / "CASE-API" / "result.seal.json"
    seal = json.loads(seal_path.read_text())
    seal["sha256"] = "0" * 64
    seal_path.write_text(json.dumps(seal))
    calls = []
    monkeypatch.setattr(OllamaClient, "generate", lambda *args, **kwargs: calls.append(True) or "narration")
    invalid = _api_error(lambda: _chat(create_app(output_root=output_root), {
        "messages": [{"role": "user", "content": json.dumps({"case_id": "CASE-API", "question": "Verdict?"})}],
    }))
    assert invalid.status_code == 422
    assert invalid.code == "invalid_authority"
    assert calls == []

    output_root = _stored_case(tmp_path / "mismatch")
    result_path = output_root / "CASE-API" / "result.json"
    payload = json.loads(result_path.read_text())
    payload["case_id"] = "OTHER-CASE"
    result_path.write_text(json.dumps(payload))
    mismatch = _api_error(lambda: _chat(create_app(output_root=output_root), {
        "messages": [{"role": "user", "content": json.dumps({"case_id": "CASE-API", "question": "Verdict?"})}],
    }))
    assert mismatch.status_code == 422
    assert mismatch.code == "invalid_authority"


def test_chat_reports_ollama_unavailable_without_assistant_error_content(tmp_path, monkeypatch):
    output_root = _stored_case(tmp_path)
    monkeypatch.setattr(OllamaClient, "generate", lambda *args, **kwargs: (_ for _ in ()).throw(OllamaError("offline")))
    error = _api_error(lambda: _chat(create_app(output_root=output_root), {
        "messages": [{"role": "user", "content": json.dumps({"case_id": "CASE-API", "question": "Verdict?"})}],
    }))
    assert error.status_code == 503
    assert error.code == "ollama_unavailable"


def test_chat_completions_answers_a_known_case(tmp_path, capsys, monkeypatch):
    output_root = _analyzed_case(tmp_path, capsys)
    monkeypatch.setattr(
        OllamaClient, "generate", lambda self, *, system, prompt: "The verdict is ABSTAIN."
    )
    body = _chat(create_app(output_root=output_root), {
        "model": "zaynor-forensic",
        "messages": [{"role": "user", "content": json.dumps({"case_id": "INC-API-CASE", "question": "Verdict?"})}],
    })
    assert body["choices"][0]["message"]["content"] == "The verdict is ABSTAIN."
    assert "usage" not in body


def test_chat_completions_accepts_plain_text_case_id_prefix(tmp_path, capsys, monkeypatch):
    output_root = _analyzed_case(tmp_path, capsys)
    monkeypatch.setattr(
        OllamaClient, "generate", lambda self, *, system, prompt: "The verdict is ABSTAIN."
    )
    body = _chat(create_app(output_root=output_root), {
        "messages": [{"role": "user", "content": "case_id: INC-API-CASE\nWhat happened?"}],
    })
    content = body["choices"][0]["message"]["content"]
    assert content == "The verdict is ABSTAIN."


def test_chat_completions_rejects_malformed_input(tmp_path):
    error = _api_error(lambda: _chat(create_app(output_root=tmp_path / "outputs"), {
        "messages": [{"role": "user", "content": "hello"}],
    }))
    assert error.status_code == 400
    assert error.code == "malformed_request"


def test_case_chat_answers_any_question_about_a_known_case(tmp_path, capsys, monkeypatch):
    """The per-case REST chat route the frontend uses -- same guarded
    narration path as /v1/chat/completions, no restriction on the question
    beyond what answer_question/Mentor.chat_checked already enforce.
    """
    output_root = _analyzed_case(tmp_path, capsys)
    monkeypatch.setattr(
        OllamaClient, "generate", lambda self, *, system, prompt: "The verdict is ABSTAIN, based on the sealed result."
    )
    body = _case_chat(create_app(output_root=output_root), "INC-API-CASE", "What happened here, in your own words?")
    assert body["narrative"] == "The verdict is ABSTAIN, based on the sealed result."
    assert body["certainty"] == "AUTHORIZED"
    assert body["finding_refs"] == []
    assert body["evidence_refs"] == []
    assert "Narración verificada" in body["disclaimer"]


def test_case_chat_flags_a_certainty_downgrade_for_a_hallucinated_claim(tmp_path, capsys, monkeypatch):
    output_root = _analyzed_case(tmp_path, capsys)
    monkeypatch.setattr(OllamaClient, "generate", lambda self, *, system, prompt: "The verdict is MALICE.")
    body = _case_chat(create_app(output_root=output_root), "INC-API-CASE", "What is the verdict?")
    assert body["certainty"] == "LIMITED"
    assert "MALICE" not in body["narrative"]
    assert "unsupported claim" in body["disclaimer"]


def test_case_chat_rejects_an_unknown_case(tmp_path):
    error = _api_error(lambda: _case_chat(create_app(output_root=tmp_path / "outputs"), "NEVER-ANALYZED", "Verdict?"))
    assert error.status_code == 404
    assert error.code == "case_not_found"


def test_case_chat_rejects_an_empty_question(tmp_path):
    output_root = _stored_case(tmp_path)
    error = _api_error(lambda: _case_chat(create_app(output_root=output_root), "CASE-API", "   "))
    assert error.status_code == 400
    assert error.code == "malformed_request"


def test_case_chat_rejects_tampered_stored_result_before_ollama(tmp_path, monkeypatch):
    output_root = _stored_case(tmp_path)
    result_path = output_root / "CASE-API" / "result.json"
    payload = json.loads(result_path.read_text())
    payload["verdict"] = "MALICE"
    result_path.write_text(json.dumps(payload))
    calls = []
    monkeypatch.setattr(OllamaClient, "generate", lambda *args, **kwargs: calls.append(True) or "The verdict is MALICE.")

    error = _api_error(lambda: _case_chat(create_app(output_root=output_root), "CASE-API", "Verdict?"))
    assert error.status_code == 422
    assert error.code == "invalid_authority"
    assert calls == []


def test_chat_completions_rejects_an_unknown_case_id(tmp_path):
    error = _api_error(lambda: _chat(create_app(output_root=tmp_path / "outputs"), {
        "messages": [{"role": "user", "content": json.dumps({"case_id": "NEVER-ANALYZED", "question": "Verdict?"})}],
    }))
    assert error.status_code == 404
    assert error.code == "case_not_found"


def test_get_case_returns_the_full_overview(tmp_path, capsys):
    output_root = _analyzed_case(tmp_path, capsys)
    cases_root = tmp_path / "cases"
    app = create_app(output_root=output_root, cases_root=cases_root)
    overview = _route(app, "/cases/{case_id}")("INC-API-CASE")
    assert overview["case_id"] == "INC-API-CASE"
    assert overview["authoritative_result"]["verdict"] == "ABSTAIN"
    assert overview["seal"]["status"] == "VERIFIED"
    assert overview["audit"]["status"] == "VERIFIED"
    assert overview["snapshot"]["status"] == "VERIFIED"
    assert overview["snapshot"]["artifact_count"] > 0
    assert overview["investigation"] == {
        "session_id": None, "status": "NOT_STARTED", "proposals": [], "observations": [],
        "authoritative_result_unchanged": True,
    }


def test_get_case_degrades_snapshot_honestly_without_cases_root(tmp_path, capsys):
    output_root = _analyzed_case(tmp_path, capsys)
    app = create_app(output_root=output_root)  # no cases_root configured
    overview = _route(app, "/cases/{case_id}")("INC-API-CASE")
    assert overview["snapshot"]["status"] == "UNKNOWN"
    assert overview["audit"]["status"] == "UNKNOWN"
    # The sealed result itself is still verified independently of cases_root.
    assert overview["authoritative_result"]["verdict"] == "ABSTAIN"


def test_get_case_result_matches_the_overview(tmp_path, capsys):
    output_root = _analyzed_case(tmp_path, capsys)
    app = create_app(output_root=output_root, cases_root=tmp_path / "cases")
    result = _route(app, "/cases/{case_id}/result")("INC-API-CASE")
    assert result["case_id"] == "INC-API-CASE"
    assert result["verdict"] == "ABSTAIN"
    assert result["hypotheses"] == []
    assert result["fractures"] == []
    assert result["signals"] == []


def test_get_case_audit_reuses_compute_case_audit(tmp_path, capsys):
    output_root = _analyzed_case(tmp_path, capsys)
    cases_root = tmp_path / "cases"
    app = create_app(output_root=output_root, cases_root=cases_root)
    audit = _route(app, "/cases/{case_id}/audit")("INC-API-CASE")
    assert audit["status"] == "VERIFIED"
    assert audit["manifest"] == "VERIFIED"
    assert audit["seal"] == "VERIFIED"


def test_get_case_audit_trail_returns_the_real_hash_chain(tmp_path, capsys):
    output_root = _analyzed_case(tmp_path, capsys)
    cases_root = tmp_path / "cases"
    app = create_app(output_root=output_root, cases_root=cases_root)
    trail = _route(app, "/cases/{case_id}/audit-trail")("INC-API-CASE")
    assert trail["chain_valid"] is True
    assert trail["total_entries"] == 3
    assert [entry["action"] for entry in trail["entries"]] == ["CASE_FROZEN", "ENGINE_INVOKED", "RESULT_SEALED"]


def test_get_case_audit_trail_fails_closed_on_a_tampered_entry(tmp_path, capsys):
    output_root = _analyzed_case(tmp_path, capsys)
    cases_root = tmp_path / "cases"
    log_path = cases_root / "INC-API-CASE" / "audit.jsonl"
    lines = log_path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[-1])
    tampered["reason"] = "tampered after the fact"
    lines[-1] = json.dumps(tampered)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    app = create_app(output_root=output_root, cases_root=cases_root)
    trail = _route(app, "/cases/{case_id}/audit-trail")("INC-API-CASE")
    assert trail["chain_valid"] is False
    assert "entry_hash mismatch" in trail["chain_detail"]


def test_get_case_audit_trail_requires_cases_root(tmp_path, capsys):
    output_root = _analyzed_case(tmp_path, capsys)
    app = create_app(output_root=output_root)  # no cases_root configured
    error = _api_error(lambda: _route(app, "/cases/{case_id}/audit-trail")("INC-API-CASE"))
    assert error.status_code == 500


def test_get_case_evidence_reflects_the_real_frozen_manifest(tmp_path, capsys):
    output_root = _analyzed_case(tmp_path, capsys)
    cases_root = tmp_path / "cases"
    app = create_app(output_root=output_root, cases_root=cases_root)
    evidence = _route(app, "/cases/{case_id}/evidence")("INC-API-CASE")["evidence"]
    assert len(evidence) > 0
    for artifact in evidence:
        assert artifact["manifest_status"] == "VERIFIED"
        assert len(artifact["sha256"]) == 64


def test_get_case_evidence_requires_cases_root(tmp_path, capsys):
    output_root = _analyzed_case(tmp_path, capsys)
    app = create_app(output_root=output_root)  # no cases_root configured
    error = _api_error(lambda: _route(app, "/cases/{case_id}/evidence")("INC-API-CASE"))
    assert error.status_code == 500


def test_get_case_investigation_is_honestly_not_started(tmp_path, capsys):
    output_root = _analyzed_case(tmp_path, capsys)
    app = create_app(output_root=output_root, cases_root=tmp_path / "cases")
    investigation = _route(app, "/cases/{case_id}/investigation")("INC-API-CASE")
    assert investigation["status"] == "NOT_STARTED"
    assert investigation["proposals"] == []


def test_get_case_rejects_an_unknown_case(tmp_path):
    app = create_app(output_root=tmp_path / "outputs")
    error = _api_error(lambda: _route(app, "/cases/{case_id}")("NEVER-ANALYZED"))
    assert error.status_code == 404
    assert error.code == "case_not_found"


def test_get_case_report_descriptor_and_download_render_real_content(tmp_path, capsys):
    output_root = _analyzed_case(tmp_path, capsys)
    app = create_app(output_root=output_root, cases_root=tmp_path / "cases")
    descriptor = _route(app, "/cases/{case_id}/reports/{fmt}")("INC-API-CASE", "md")
    assert descriptor["format"] == "md"
    assert descriptor["content_type"] == "text/markdown"
    assert descriptor["download_url"] == "/cases/INC-API-CASE/reports/md/download"

    response = _route(app, "/cases/{case_id}/reports/{fmt}/download")("INC-API-CASE", "md")
    assert response.media_type == "text/markdown"
    assert b"INC-API-CASE" in response.body


def test_get_case_report_rejects_an_unsupported_format(tmp_path, capsys):
    output_root = _analyzed_case(tmp_path, capsys)
    app = create_app(output_root=output_root)
    error = _api_error(lambda: _route(app, "/cases/{case_id}/reports/{fmt}")("INC-API-CASE", "docx"))
    assert error.status_code == 400


def test_rest_errors_use_the_flat_shape_the_frontend_actually_parses(tmp_path):
    """Regression: REST routes previously rendered ApiError with the
    OpenAI-nested {error:{message,type,code}} shape over real HTTP, which
    contracts.ts's parseApiError (flat {code,message,request_id}) never
    recognizes -- every REST error silently fell back to a generic
    per-status message. Exercised through the real ASGI/HTTP layer (not
    a direct route-function call), since that is exactly the layer the
    bug lived in.
    """
    from fastapi.testclient import TestClient

    app = create_app(output_root=tmp_path / "outputs")
    client = TestClient(app)

    response = client.get("/cases/NEVER-ANALYZED")
    assert response.status_code == 404
    body = response.json()
    assert body == {"code": "CASE_NOT_FOUND", "message": "case is not available", "request_id": None}


def test_openai_chat_errors_keep_the_nested_shape(tmp_path):
    from fastapi.testclient import TestClient

    app = create_app(output_root=tmp_path / "outputs")
    client = TestClient(app)

    response = client.post("/v1/chat/completions", json={"model": "not-zaynor", "messages": []})
    assert response.status_code == 400
    body = response.json()
    assert body["error"]["code"] == "unsupported_model"
    assert "code" not in body


def _propose(app, case_id, question):
    return _route(app, "/cases/{case_id}/investigations/proposals")(
        case_id, InvestigationProposalRequest(question=question)
    )


def _valid_proposal_json(*, requested_tool="verify_custody", arguments=None, case_id="INC-API-CASE"):
    return json.dumps({
        "proposal_id": "P-001",
        "case_id": case_id,
        "question": "What does the auth log say?",
        "rationale": "Checking for evidence of the login anomaly.",
        "requested_tool": requested_tool,
        "arguments": arguments if arguments is not None else {},
        "information_sought": "Recomputed hash of the auth log.",
    })


def test_propose_investigation_runs_a_real_deterministic_tool_call(tmp_path, capsys, monkeypatch):
    """The LLM only proposes (via a mocked but strictly-parsed JSON turn);
    the tool call itself is real: an actual subprocess call into VIGIA's
    vendored MCP bridge (generate_forensic_hash), not a mock.

    VIGIA's bridge tools require an absolute path confined under
    VIGIA_EVIDENCE_DIR, confirmed against test_zaynor_mcp_client.py's own
    real (non-mocked) calls -- a relative path resolves against the
    bridge subprocess's cwd (the engine repo), not the evidence dir, and
    fails closed as PATH_TRAVERSAL.
    """
    output_root = _analyzed_case(tmp_path, capsys)
    cases_root = tmp_path / "cases"
    evidence_path = str(cases_root / "INC-API-CASE" / "evidence" / "collected" / "auth.jsonl")
    monkeypatch.setattr(
        OllamaClient, "generate",
        lambda self, *, system, prompt: _valid_proposal_json(arguments={"path": evidence_path}),
    )

    app = create_app(output_root=output_root, cases_root=cases_root)
    body = _propose(app, "INC-API-CASE", "What does the auth log say?")

    assert body["requested_tool"] == "verify_custody"
    assert body["status"] == "EXECUTED"
    assert body["capability"] == "read:custody"
    assert "arguments" not in body
    assert isinstance(body["arguments_digest"], str) and len(body["arguments_digest"]) == 64

    summary = _route(app, "/cases/{case_id}/investigation")("INC-API-CASE")
    assert summary["status"] == "OPEN"
    assert len(summary["proposals"]) == 1
    assert len(summary["observations"]) == 1
    observation = summary["observations"][0]
    assert observation["status"] == "OBSERVED"
    assert "sha256" in json.dumps(observation["payload"])


def test_propose_investigation_serializes_concurrent_requests_for_the_same_case(tmp_path, capsys, monkeypatch):
    """Red team round 22 (R22-01, CONFIRMED BY INDUCTION): before
    `_investigation_write_lock` was added, `propose_investigation` was a
    plain load -> compute -> save cycle with no lock at all. Two
    concurrent requests for the same case_id both loaded the same stale
    ledger, both really executed their MCP tool call, and whichever
    `os.replace` ran last silently discarded the other's real,
    already-executed observation -- a lost update reproduced with real
    threads and a real subprocess call into VIGIA's vendored MCP bridge,
    no fault injection needed. This confirms the fix: both real,
    genuinely concurrent requests now persist, because the second one
    blocks on the per-case flock until the first has saved, then loads
    the *updated* ledger instead of the stale one.
    """
    from concurrent.futures import ThreadPoolExecutor

    output_root = _analyzed_case(tmp_path, capsys)
    cases_root = tmp_path / "cases"
    evidence_path = str(cases_root / "INC-API-CASE" / "evidence" / "collected" / "auth.jsonl")
    app = create_app(output_root=output_root, cases_root=cases_root)

    def fake_generate(self, *, system, prompt):
        proposal_id = "P-AAA" if "Question A" in prompt else "P-BBB"
        return json.dumps({
            "proposal_id": proposal_id,
            "case_id": "INC-API-CASE",
            "question": "irrelevant, the real prompt carries it",
            "rationale": "concurrency induction test",
            "requested_tool": "verify_custody",
            "arguments": {"path": evidence_path},
            "information_sought": "recomputed hash",
        })

    monkeypatch.setattr(OllamaClient, "generate", fake_generate)

    with ThreadPoolExecutor(max_workers=2) as pool:
        future_a = pool.submit(_propose, app, "INC-API-CASE", "Question A")
        future_b = pool.submit(_propose, app, "INC-API-CASE", "Question B")
        result_a = future_a.result(timeout=30)
        result_b = future_b.result(timeout=30)

    assert result_a["status"] == "EXECUTED"
    assert result_b["status"] == "EXECUTED"

    summary = _route(app, "/cases/{case_id}/investigation")("INC-API-CASE")
    assert len(summary["proposals"]) == 2
    assert len(summary["observations"]) == 2


def test_propose_investigation_persists_across_requests(tmp_path, capsys, monkeypatch):
    output_root = _analyzed_case(tmp_path, capsys)
    cases_root = tmp_path / "cases"
    monkeypatch.setattr(OllamaClient, "generate", lambda self, *, system, prompt: _valid_proposal_json())
    app = create_app(output_root=output_root, cases_root=cases_root)

    _propose(app, "INC-API-CASE", "What does the auth log say?")
    # A brand-new app instance (simulating a fresh request against the
    # same on-disk state) still sees the persisted proposal.
    second_app = create_app(output_root=output_root, cases_root=cases_root)
    summary = _route(second_app, "/cases/{case_id}/investigation")("INC-API-CASE")
    assert len(summary["proposals"]) == 1


def test_propose_investigation_rejects_a_tool_outside_the_investigator_manifest(tmp_path, capsys, monkeypatch):
    output_root = _analyzed_case(tmp_path, capsys)
    cases_root = tmp_path / "cases"
    monkeypatch.setattr(
        OllamaClient, "generate",
        lambda self, *, system, prompt: _valid_proposal_json(requested_tool="collect_endpoint_window", arguments={}),
    )
    app = create_app(output_root=output_root, cases_root=cases_root)

    error = _api_error(lambda: _propose(app, "INC-API-CASE", "Collect endpoint telemetry"))
    assert error.status_code == 422
    assert error.code == "policy_rejected"

    # Nothing was persisted -- a rejected proposal never reaches the ledger.
    summary = _route(app, "/cases/{case_id}/investigation")("INC-API-CASE")
    assert summary["proposals"] == []


def test_propose_investigation_requires_cases_root(tmp_path, capsys):
    output_root = _analyzed_case(tmp_path, capsys)
    app = create_app(output_root=output_root)  # no cases_root configured
    error = _api_error(lambda: _propose(app, "INC-API-CASE", "What does the auth log say?"))
    assert error.status_code == 500


def test_propose_investigation_rejects_an_empty_question(tmp_path, capsys):
    output_root = _analyzed_case(tmp_path, capsys)
    cases_root = tmp_path / "cases"
    app = create_app(output_root=output_root, cases_root=cases_root)
    error = _api_error(lambda: _propose(app, "INC-API-CASE", "   "))
    assert error.status_code == 400


def test_get_case_investigation_fails_closed_on_a_corrupted_ledger(tmp_path, capsys):
    """Red team round 21 (R21-03): a truncated/unreadable
    investigation.json used to be caught and silently treated as a fresh,
    empty session -- data loss disguised as NOT_STARTED. It must now
    surface as a real error instead.
    """
    output_root = _analyzed_case(tmp_path, capsys)
    ledger_path = output_root / "INC-API-CASE" / "investigation.json"
    ledger_path.write_text("{not valid json", encoding="utf-8")

    app = create_app(output_root=output_root)
    error = _api_error(lambda: _route(app, "/cases/{case_id}/investigation")("INC-API-CASE"))
    assert error.status_code == 500
    assert "could not be read" in error.message


def test_propose_investigation_writes_the_ledger_atomically(tmp_path, capsys, monkeypatch):
    """R21-03: the ledger is written via temp-file + os.replace, not a
    direct write -- confirmed by observing that a NamedTemporaryFile is
    actually created next to the target path during the write.
    """
    import tempfile as tempfile_module

    output_root = _analyzed_case(tmp_path, capsys)
    cases_root = tmp_path / "cases"
    evidence_path = str(cases_root / "INC-API-CASE" / "evidence" / "collected" / "auth.jsonl")
    monkeypatch.setattr(
        OllamaClient, "generate",
        lambda self, *, system, prompt: _valid_proposal_json(arguments={"path": evidence_path}),
    )

    seen_temp_names = []
    real_named_temp_file = tempfile_module.NamedTemporaryFile

    def _spying_named_temp_file(*args, **kwargs):
        handle = real_named_temp_file(*args, **kwargs)
        seen_temp_names.append(handle.name)
        return handle

    monkeypatch.setattr(tempfile_module, "NamedTemporaryFile", _spying_named_temp_file)
    app = create_app(output_root=output_root, cases_root=cases_root)
    _propose(app, "INC-API-CASE", "What does the auth log say?")

    ledger_path = output_root / "INC-API-CASE" / "investigation.json"
    assert any(Path(name).parent == ledger_path.parent for name in seen_temp_names)
    assert ledger_path.is_file()
    # The temp file is gone -- os.replace consumed it, it was not left behind.
    assert not any(Path(name).exists() for name in seen_temp_names)
