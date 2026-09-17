"""Tests for the docs-sync gate (scripts/docs_check.py).

Two layers:

- Pure tests of ``evaluate()`` against synthetic changed-file sets, so the
  map semantics (any-of vs require_all, waivers, fnmatch behavior) are
  pinned without touching git.
- Subprocess tests against a throwaway git repo, exercising the same
  entrypoints the pre-push hook and CI use (``--git-range``, ``--staged``,
  ``--list-rules``) and the ``Docs-Waiver`` trailer contract.
"""

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import docs_check  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent


def violated_ids(files: list[str]) -> list[str]:
    return [o.rule.id for o in docs_check.evaluate(files) if o.violated]


# --- map semantics (pure) --------------------------------------------------


def test_cli_change_without_readmes_is_rejected():
    outcomes = docs_check.evaluate(["src/zaynor/cli.py"])
    assert violated_ids(["src/zaynor/cli.py"]) == ["cli-usage"]
    outcome = next(o for o in outcomes if o.rule.id == "cli-usage")
    assert outcome.missing_docs == ["README.md", "README.en.md"]


def test_cli_change_with_both_readmes_passes():
    files = ["src/zaynor/cli.py", "README.md", "README.en.md"]
    assert not any(o.violated for o in docs_check.evaluate(files))


def test_cli_change_with_only_one_readme_still_rejected():
    # require_all: the READMEs are a mirrored pair, one side is not enough.
    files = ["src/zaynor/cli.py", "README.md"]
    assert docs_check.evaluate(files) and any(o.violated for o in docs_check.evaluate(files))


def test_any_of_rule_satisfied_by_a_single_doc():
    files = ["scripts/install-hooks.sh", "CHANGELOG.md"]
    assert not any(o.violated for o in docs_check.evaluate(files))


def test_unrelated_files_trigger_no_rule():
    files = ["tests/test_new_thing.py", "docs/red-team/round-21.md"]
    assert docs_check.evaluate(files) == []


def test_agent_package_pattern_crosses_directories():
    files = ["src/zaynor/agents/registry.py"]
    assert "agent-roles" in violated_ids(files)


def test_frontend_pattern_matches_nested_paths():
    files = ["frontend/src/lib/apiClient.ts"]
    assert "frontend-architecture" in violated_ids(files)


def test_waiver_marks_rule_not_violated_but_visible():
    outcomes = docs_check.evaluate(
        ["src/zaynor/cli.py"], {"cli-usage": "internal no-op, docs unchanged"}
    )
    outcome = next(o for o in outcomes if o.rule.id == "cli-usage")
    assert outcome.waived
    assert outcome.waiver_reason == "internal no-op, docs unchanged"
    assert not outcome.violated


def test_waiver_is_per_rule():
    outcomes = docs_check.evaluate(["scripts/docs_check.py"], {"cli-usage": "unrelated waiver"})
    sdlc = next(o for o in outcomes if o.rule.id == "sdlc")
    assert not sdlc.waived and sdlc.violated


# --- map integrity ----------------------------------------------------------


def test_rule_ids_are_unique():
    ids = [rule.id for rule in docs_check.DOCS_MAP]
    assert len(ids) == len(set(ids))


def test_every_doc_target_exists_in_the_tree():
    for rule in docs_check.DOCS_MAP:
        for pattern in rule.docs:
            if "*" in pattern:
                assert list(
                    REPO_ROOT.glob(pattern)
                ), f"rule '{rule.id}': doc pattern {pattern!r} matches nothing"
            else:
                assert (
                    REPO_ROOT / pattern
                ).exists(), f"rule '{rule.id}': doc {pattern!r} does not exist"


# --- CLI end-to-end (the entrypoints pre-push and CI actually call) ---------


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)
    return result.stdout.strip()


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    (repo / "docs" / "adr").mkdir(parents=True)
    (repo / "docs" / "adr" / "0001-test.md").write_text("adr\n")
    (repo / "README.md").write_text("readme\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "chore: base")
    return repo


def _run_gate(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "docs_check.py"), *args],
        cwd=repo,
        capture_output=True,
        text=True,
    )


def test_git_range_rejects_code_without_docs(git_repo: Path):
    (git_repo / "src" / "zaynor").mkdir(parents=True)
    (git_repo / "src" / "zaynor" / "cli.py").write_text("print(1)\n")
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-qm", "feat(cli): add command")
    base, head = _git(git_repo, "rev-parse", "HEAD~1"), _git(git_repo, "rev-parse", "HEAD")
    result = _run_gate(git_repo, "--git-range", f"{base}..{head}")
    assert result.returncode == 1
    assert "cli-usage" in result.stderr
    assert "README.en.md" in result.stderr


def test_git_range_accepts_when_docs_updated(git_repo: Path):
    (git_repo / "src" / "zaynor").mkdir(parents=True)
    (git_repo / "src" / "zaynor" / "cli.py").write_text("print(1)\n")
    (git_repo / "README.md").write_text("readme updated\n")
    (git_repo / "README.en.md").write_text("docs\n")
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-qm", "feat(cli): add command with docs")
    base, head = _git(git_repo, "rev-parse", "HEAD~1"), _git(git_repo, "rev-parse", "HEAD")
    result = _run_gate(git_repo, "--git-range", f"{base}..{head}")
    assert result.returncode == 0
    assert "docs_check: OK" in result.stderr


def test_waiver_trailer_clears_the_range(git_repo: Path):
    (git_repo / "src" / "zaynor").mkdir(parents=True)
    (git_repo / "src" / "zaynor" / "cli.py").write_text("print(1)\n")
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-qm", "feat(cli): tweak\n\nDocs-Waiver: cli-usage no-op tweak")
    base, head = _git(git_repo, "rev-parse", "HEAD~1"), _git(git_repo, "rev-parse", "HEAD")
    result = _run_gate(git_repo, "--git-range", f"{base}..{head}")
    assert result.returncode == 0
    assert "WAIVED by commit trailer" in result.stderr


def test_prose_mentioning_a_waiver_does_not_waive(git_repo: Path):
    (git_repo / "src" / "zaynor").mkdir(parents=True)
    (git_repo / "src" / "zaynor" / "cli.py").write_text("print(1)\n")
    _git(git_repo, "add", "-A")
    _git(
        git_repo,
        "commit",
        "-qm",
        "feat(cli): tweak\n\nwe considered a Docs-Waiver: cli-usage but kept the gate",
    )
    base, head = _git(git_repo, "rev-parse", "HEAD~1"), _git(git_repo, "rev-parse", "HEAD")
    result = _run_gate(git_repo, "--git-range", f"{base}..{head}")
    assert result.returncode == 1


def test_staged_mode_rejects_uncommitted_code(git_repo: Path):
    (git_repo / "src" / "zaynor").mkdir(parents=True)
    (git_repo / "src" / "zaynor" / "cli.py").write_text("print(1)\n")
    _git(git_repo, "add", "-A")
    result = _run_gate(git_repo, "--staged")
    assert result.returncode == 1
    assert "cli-usage" in result.stderr


def test_list_rules_exits_zero(git_repo: Path):
    result = _run_gate(git_repo, "--list-rules")
    assert result.returncode == 0
    assert "cli-usage" in result.stdout


def test_bad_usage_exits_two(git_repo: Path):
    result = _run_gate(git_repo, "--base")
    assert result.returncode == 2
