import hashlib
import json
import shutil
import sys
import textwrap
from pathlib import Path

from zaynor.cli import main


FIXTURE = Path(__file__).parent.parent / "scenarios" / "inc-2026-demo-001" / "telemetry.jsonl"


def _analyzed_case(tmp_path: Path, capsys):
    scenario = tmp_path / "scenario"
    shutil.copytree(FIXTURE.parent, scenario)
    cases_root = tmp_path / "cases"
    assert main([
        "freeze", "--case-id", "INC-CLI-AUDIT", "--evidence-profile",
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
        bundle = {'case_id': 'INC-CLI-AUDIT', 'evidence_sha256': digest.hexdigest(),
                  'agent_verdict': 'ABSTAIN', 'audit_trail': []}
        raw = json.dumps(bundle).encode()
        output.write_bytes(raw)
        output.with_suffix(output.suffix + '.sha256').write_text(
            hashlib.sha256(raw).hexdigest() + '  ' + str(output) + '\\n')
        sys.exit(4)
    """))
    output_root = tmp_path / "outputs"
    assert main([
        "analyze", "--case-id", "INC-CLI-AUDIT", "--cases-root", str(cases_root),
        "--engine-repo", str(engine), "--output-root", str(output_root), "--json",
    ]) == 0
    capsys.readouterr()
    return scenario, cases_root, output_root


_STUB_AGENT_BODY = textwrap.dedent("""
    import hashlib, json, pathlib, sys
    evidence = pathlib.Path(sys.argv[sys.argv.index('--evidence') + 1])
    output = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])
    if evidence.is_dir():
        digest = hashlib.sha256()
        for path in sorted(evidence.rglob('*')):
            if path.is_file():
                digest.update(str(path.relative_to(evidence)).encode())
                digest.update(hashlib.sha256(path.read_bytes()).digest())
        evidence_sha256 = digest.hexdigest()
    else:
        evidence_sha256 = hashlib.sha256(evidence.read_bytes()).hexdigest()
    bundle = {'case_id': 'INC-CLI-JSON-CASE', 'evidence_sha256': evidence_sha256,
              'agent_verdict': 'ABSTAIN', 'audit_trail': []}
    raw = json.dumps(bundle).encode()
    output.write_bytes(raw)
    output.with_suffix(output.suffix + '.sha256').write_text(
        hashlib.sha256(raw).hexdigest() + '  ' + str(output) + '\\n')
    sys.exit(4)
""")


def test_analyze_and_audit_a_single_vigia_case_json_file(tmp_path, capsys):
    """Regression for the routing fix: a frozen case whose only evidence is
    one VIGÍA case-corpus JSON file (artifacts[] with type/source/content/
    metadata) must reach the engine as that FILE, not the directory
    containing it, and `audit` must recompute evidence_sha256 the same way
    (file hash, not directory hash) or a genuine, untampered case would
    fail closed for the wrong reason.
    """
    source = tmp_path / "source"
    source.mkdir()
    case_json = source / "OWL-MINI-CASE.json"
    case_json.write_text(json.dumps({
        "case_id": "INC-CLI-JSON-CASE",
        "artifacts": [{"id": "ART-001", "type": "account_registration"}],
    }))
    (source / "profile_map.json").write_text(json.dumps({"vigia-case": ["OWL-MINI-CASE.json"]}))

    cases_root = tmp_path / "cases"
    assert main([
        "freeze", "--case-id", "INC-CLI-JSON-CASE", "--evidence-profile", "vigia-case",
        "--profile-map", str(source / "profile_map.json"), "--source-root", str(source),
        "--cases-root", str(cases_root), "--json",
    ]) == 0
    capsys.readouterr()

    engine = tmp_path / "engine"
    engine.mkdir()
    (engine / "vigia_agent.py").write_text(_STUB_AGENT_BODY)
    output_root = tmp_path / "outputs"
    assert main([
        "analyze", "--case-id", "INC-CLI-JSON-CASE", "--cases-root", str(cases_root),
        "--engine-repo", str(engine), "--output-root", str(output_root), "--json",
    ]) == 0
    capsys.readouterr()

    assert main([
        "audit", "--case-id", "INC-CLI-JSON-CASE", "--cases-root", str(cases_root),
        "--output-root", str(output_root), "--json",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["overall"] == "VERIFIED"


def test_audit_trail_shows_the_real_chain_from_freeze_and_analyze(tmp_path, capsys):
    _, cases_root, _ = _analyzed_case(tmp_path, capsys)

    assert main([
        "audit-trail", "--case-id", "INC-CLI-AUDIT", "--cases-root", str(cases_root), "--json",
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["chain_valid"] is True
    assert payload["total_entries"] == 3
    assert [entry["action"] for entry in payload["entries"]] == ["CASE_FROZEN", "ENGINE_INVOKED", "RESULT_SEALED"]
    assert payload["entries"][0]["case_id"] == "INC-CLI-AUDIT"


def test_audit_trail_fails_closed_on_a_tampered_entry(tmp_path, capsys):
    _, cases_root, _ = _analyzed_case(tmp_path, capsys)
    log_path = cases_root / "INC-CLI-AUDIT" / "audit.jsonl"
    lines = log_path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["reason"] = "tampered after the fact"
    lines[0] = json.dumps(tampered)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    exit_code = main([
        "audit-trail", "--case-id", "INC-CLI-AUDIT", "--cases-root", str(cases_root), "--json",
    ])
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert payload["chain_valid"] is False
    assert "entry_hash mismatch" in payload["chain_detail"]


def test_case_cli_emits_reproducible_json(capsys):
    assert main(["case", "--fixture", str(FIXTURE), "--json"]) == 0
    first = capsys.readouterr().out

    assert main(["case", "--fixture", str(FIXTURE), "--json"]) == 0
    second = capsys.readouterr().out

    assert first == second
    assert '"case_id": "INC-' in first
    assert '"correlation_id"' in first


def test_detect_cli_known_device_is_benign(capsys):
    assert main(
        [
            "detect",
            "--fixture",
            str(FIXTURE),
            "--known-device",
            "DEV-UNKNOWN-17",
            "--json",
        ]
    ) == 0
    assert '"alerts": []' in capsys.readouterr().out


def test_cli_rejects_symlink_fixture(tmp_path, capsys):
    target = tmp_path / "fixture.jsonl"
    target.write_text('{"logical_time": 1, "event_type": "vpn_login"}\n')
    link = tmp_path / "link.jsonl"
    link.symlink_to(target)

    assert main(["replay", "--fixture", str(link)]) == 2
    assert "symlink" in capsys.readouterr().err


def test_cli_rejects_symlink_parent(tmp_path, capsys):
    target_dir = tmp_path / "real"
    target_dir.mkdir()
    target = target_dir / "fixture.jsonl"
    target.write_text('{"logical_time": 1, "event_type": "vpn_login"}\n')
    parent_link = tmp_path / "linked"
    parent_link.symlink_to(target_dir, target_is_directory=True)

    assert main(["replay", "--fixture", str(parent_link / "fixture.jsonl")]) == 2
    assert "symlink" in capsys.readouterr().err


def test_freeze_cli_creates_manifest_bound_case(tmp_path, capsys):
    scenario = FIXTURE.parent
    cases_root = tmp_path / "cases"
    assert main(
        [
            "freeze",
            "--case-id",
            "INC-CLI-001",
            "--evidence-profile",
            "admin-session-investigation",
            "--profile-map",
            str(scenario / "evidence_profile.json"),
            "--source-root",
            str(scenario),
            "--cases-root",
            str(cases_root),
            "--json",
        ]
    ) == 0
    output = capsys.readouterr().out
    assert '"case_id": "INC-CLI-001"' in output
    assert (cases_root / "INC-CLI-001" / "manifest.json").is_file()
    frozen_files = [path for path in (cases_root / "INC-CLI-001" / "evidence").rglob("*") if path.is_file()]
    assert len(frozen_files) == 5


def test_freeze_rejects_symlink_source_root_parent(tmp_path, capsys):
    scenario = FIXTURE.parent
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(scenario.parent, target_is_directory=True)
    assert main(
        [
            "freeze",
            "--case-id", "INC-CLI-002",
            "--evidence-profile", "admin-session-investigation",
            "--profile-map", str(scenario / "evidence_profile.json"),
            "--source-root", str(linked_parent / scenario.name),
            "--cases-root", str(tmp_path / "cases"),
        ]
    ) == 2
    assert "symlink" in capsys.readouterr().err


def test_freeze_rejects_symlink_cases_root_parent(tmp_path, capsys):
    scenario = FIXTURE.parent
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(tmp_path, target_is_directory=True)
    assert main(
        [
            "freeze",
            "--case-id", "INC-CLI-003",
            "--evidence-profile", "admin-session-investigation",
            "--profile-map", str(scenario / "evidence_profile.json"),
            "--source-root", str(scenario),
            "--cases-root", str(linked_parent / "cases"),
        ]
    ) == 2
    assert "symlink" in capsys.readouterr().err


def test_analyze_rejects_python_override_without_dev(tmp_path, capsys):
    scenario, cases_root, _ = _analyzed_case(tmp_path, capsys)
    assert main([
        "analyze", "--case-id", "INC-CLI-AUDIT", "--cases-root", str(cases_root),
        "--engine-repo", str(tmp_path / "missing-engine"), "--output-root", str(tmp_path / "out"),
        "--python", "/bin/sh",
    ]) == 2
    assert "dev-only" in capsys.readouterr().err


def test_audit_accepts_untouched_stored_case_and_source_mutation(tmp_path, capsys):
    scenario, cases_root, output_root = _analyzed_case(tmp_path, capsys)
    (scenario / "collected" / "auth.jsonl").write_text("mutated source after freeze")
    assert main([
        "audit", "--case-id", "INC-CLI-AUDIT", "--cases-root", str(cases_root),
        "--output-root", str(output_root), "--json",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["overall"] == "VERIFIED"


def test_audit_fails_closed_for_each_stored_artifact_tamper(tmp_path, capsys):
    _, cases_root, output_root = _analyzed_case(tmp_path, capsys)
    output_case = output_root / "INC-CLI-AUDIT"
    targets = {
        "evidence": cases_root / "INC-CLI-AUDIT" / "evidence" / "collected" / "auth.jsonl",
        "manifest": cases_root / "INC-CLI-AUDIT" / "manifest.json",
        "bundle": output_case / "bundle.json",
        "sidecar": output_case / "bundle.json.sha256",
        "result": output_case / "result.json",
        "seal": output_case / "result.seal.json",
    }
    for name, target in targets.items():
        original = target.read_bytes()
        if name == "evidence":
            target.chmod(0o600)
            target.write_bytes(original + b"tamper")
        elif name == "manifest":
            payload = json.loads(original)
            payload["content_sha256"] = "0" * 64
            target.write_text(json.dumps(payload))
        elif name == "sidecar":
            target.write_text("0" * 64 + "  bundle.json\n")
        elif name == "seal":
            payload = json.loads(original)
            payload["sha256"] = "0" * 64
            target.write_text(json.dumps(payload))
        else:
            target.write_bytes(original + b"tamper")
        assert main([
            "audit", "--case-id", "INC-CLI-AUDIT", "--cases-root", str(cases_root),
            "--output-root", str(output_root), "--json",
        ]) == 1, name
        assert json.loads(capsys.readouterr().out)["overall"] == "FAILED"
        target.write_bytes(original)
        if name == "evidence":
            target.chmod(0o400)


def test_chat_narrates_the_sealed_verdict_and_verifies_it(tmp_path, capsys, monkeypatch):
    from zaynor.agents.ollama_client import OllamaClient

    _, _, output_root = _analyzed_case(tmp_path, capsys)
    monkeypatch.setattr(
        OllamaClient, "generate", lambda self, *, system, prompt: "The verdict is ABSTAIN."
    )
    assert main([
        "chat", "--case-id", "INC-CLI-AUDIT", "--output-root", str(output_root),
        "--question", "What is the verdict?", "--json",
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["narration"] == "The verdict is ABSTAIN."
    assert payload["suspicious"] is False
    assert payload["claims_total"] >= 1


def test_chat_flags_a_claim_the_seal_does_not_support(tmp_path, capsys, monkeypatch):
    from zaynor.agents.ollama_client import OllamaClient

    _, _, output_root = _analyzed_case(tmp_path, capsys)
    monkeypatch.setattr(
        OllamaClient, "generate", lambda self, *, system, prompt: "The verdict is MALICE."
    )
    assert main([
        "chat", "--case-id", "INC-CLI-AUDIT", "--output-root", str(output_root),
        "--question", "What is the verdict?",
    ]) == 0
    out, err = capsys.readouterr()
    assert "MALICE" not in out
    assert "unsupported claim" in err


def test_chat_rejects_a_case_id_that_was_never_analyzed(tmp_path, capsys):
    output_root = tmp_path / "outputs"
    output_root.mkdir()
    assert main([
        "chat", "--case-id", "INC-NEVER-ANALYZED", "--output-root", str(output_root),
        "--question", "What happened?",
    ]) == 2
    assert "error de entrada" in capsys.readouterr().err


def test_no_model_is_required_env_var_picks_it_over_the_fallback(tmp_path, capsys, monkeypatch):
    """Nobody has to run one specific Ollama model: --model wins, then
    $ZAYNOR_OLLAMA_MODEL, then the bundled fallback in model_catalog.py."""
    from zaynor.agents.ollama_client import OllamaClient

    _, _, output_root = _analyzed_case(tmp_path, capsys)
    seen_models = []
    monkeypatch.setattr(
        OllamaClient,
        "generate",
        lambda self, *, system, prompt: (seen_models.append(self.model), "ok")[1],
    )
    monkeypatch.setenv("ZAYNOR_OLLAMA_MODEL", "qwen2.5:1.5b")
    assert main([
        "chat", "--case-id", "INC-CLI-AUDIT", "--output-root", str(output_root), "--question", "Verdict?",
    ]) == 0
    capsys.readouterr()
    assert seen_models == ["qwen2.5:1.5b"]


def test_models_lists_suggestions_without_requiring_any_of_them(capsys):
    assert main(["models", "--host", "http://127.0.0.1:1", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["installed"] is None
    assert payload["error"]
    names = {model["name"] for model in payload["suggested"]}
    assert "llama3.2:1b" in names
    assert payload["env_var"] == "ZAYNOR_OLLAMA_MODEL"


def test_report_md_and_html_render_from_a_real_analyzed_case(tmp_path, capsys):
    _, _, output_root = _analyzed_case(tmp_path, capsys)
    out_md = tmp_path / "report.md"
    assert main([
        "report", "--case-id", "INC-CLI-AUDIT", "--output-root", str(output_root),
        "--format", "md", "--out", str(out_md),
    ]) == 0
    capsys.readouterr()
    text = out_md.read_text()
    assert "INC-CLI-AUDIT" in text
    assert "ABSTAIN" in text

    out_html = tmp_path / "report.html"
    assert main([
        "report", "--case-id", "INC-CLI-AUDIT", "--output-root", str(output_root),
        "--format", "html", "--out", str(out_html),
    ]) == 0
    assert "INC-CLI-AUDIT" in out_html.read_text()


def test_report_defaults_the_output_path_under_output_root(tmp_path, capsys):
    _, _, output_root = _analyzed_case(tmp_path, capsys)
    assert main([
        "report", "--case-id", "INC-CLI-AUDIT", "--output-root", str(output_root), "--format", "md",
    ]) == 0
    printed = capsys.readouterr().out.strip()
    assert printed == str(output_root / "INC-CLI-AUDIT" / "report.md")
    assert Path(printed).is_file()


def test_report_rejects_a_case_id_that_was_never_analyzed(tmp_path, capsys):
    output_root = tmp_path / "outputs"
    output_root.mkdir()
    assert main([
        "report", "--case-id", "INC-NEVER-ANALYZED", "--output-root", str(output_root), "--format", "md",
    ]) == 2
    assert "error de entrada" in capsys.readouterr().err


def test_hunts_lists_the_real_dispatcher_catalog(capsys):
    assert main(["hunts", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    ids = {hunt["id"] for hunt in payload["hunts"]}
    assert {"registry", "prefetch", "browser", "event_log", "memory", "mft", "ebs_json"} == ids


def test_consult_exposes_a_sealed_case_without_touching_the_original_seal(tmp_path, capsys):
    _, _, output_root = _analyzed_case(tmp_path, capsys)
    stored_seal = json.loads((output_root / "INC-CLI-AUDIT" / "result.seal.json").read_text())

    assert main(["consult", "--case-id", "INC-CLI-AUDIT", "--output-root", str(output_root), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["result"]["found"] is True
    assert payload["result"]["case_id"] == "INC-CLI-AUDIT"
    assert payload["result"]["verdict"] == "ABSTAIN"
    # The consult surface reports its OWN (package-level) seal, not the
    # original result seal -- two different sealed objects, per design.
    assert payload["result"]["result_sha256"] != stored_seal["sha256"]
    assert payload["framework"]["changes_verdict"] is False
    assert payload["framework"]["mitre"] == []
    assert {hunt["id"] for hunt in payload["hunts"]["hunts"]} == {
        "registry", "prefetch", "browser", "event_log", "memory", "mft", "ebs_json",
    }

    # The original stored seal is untouched by building a consult package.
    assert json.loads((output_root / "INC-CLI-AUDIT" / "result.seal.json").read_text()) == stored_seal


def test_consult_rejects_a_case_id_that_was_never_analyzed(tmp_path):
    output_root = tmp_path / "outputs"
    output_root.mkdir()
    assert main(["consult", "--case-id", "NEVER-ANALYZED", "--output-root", str(output_root), "--json"]) == 2

