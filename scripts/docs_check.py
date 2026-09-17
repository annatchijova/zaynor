#!/usr/bin/env python3
"""Docs-sync gate for ZAYNOR — code changes must update the docs that describe them.

The gate answers one question: did the files changed in this branch (or this
push, or this stage) also update every document that contracts them? The
code-to-docs contract is `DOCS_MAP` below — the single source of truth, in
the spirit of `ALLOWED_TYPES` in `scripts/commitlint.py`.

Stdlib only, no dependencies beyond git + python3, mirroring
`scripts/commitlint.py` so it runs as a hook on a bare clone.

What counts as "changed":

- default (no arguments): the branch diff — `git diff --name-only` from the
  merge-base of `origin/main` (or `main`) to `HEAD`.
- ``--base <ref>``: same, against an explicit base ref.
- ``--git-range <base>..<head>``: an explicit git range (used by the
  `pre-push` hook over the range actually being pushed).
- ``--staged``: files staged in the index (no commit-trailer waivers —
  uncommitted work cannot carry a waiver yet).
- ``--files <path>...`` (or paths on stdin): an explicit file list.

Semantics:

- A rule triggers when at least one changed file matches its code patterns.
- An triggered rule is satisfied when the rule's doc patterns are matched by
  the changed set: every pattern when ``require_all`` (the mirrored
  README.md/README.en.md pair), otherwise at least one.
- A deliberate waiver is a commit trailer anywhere in the checked range::

      Docs-Waiver: <rule-id> <short reason>

  Waivers are per-rule, visible in git history, and reported (never silent).
- Exit codes: 0 accepts, 1 rejects (violations listed), 2 is an internal
  error. Violations print to stderr, so the `pre-push` hook can simply run
  the script and let its exit status decide.

The map is intentionally file-level and conservative: a module with no doc
contract imposes none. When you add a part of the codebase that has a doc
contract, add the rule here in the same change.
"""

from __future__ import annotations

import fnmatch
import subprocess
import sys
from dataclasses import dataclass, field

DEFAULT_BASE = "origin/main"


@dataclass(frozen=True)
class Rule:
    """One code-to-docs contract: changing `paths` requires touching `docs`."""

    id: str
    paths: tuple[str, ...]
    docs: tuple[str, ...]
    # True: every doc pattern in `docs` must be updated (mirrored language
    # pairs). False (default): updating any one of them satisfies the rule.
    require_all: bool = False


# The source of truth for which code parts contract which docs. Keep rules
# ordered by code path (cli/api first, tooling last) so `--list-rules`
# reads as a table of contents. Patterns are fnmatch globs against
# POSIX-style paths; `*` crosses `/`, so `src/zaynor/agents/*` covers the
# whole package tree.
DOCS_MAP: tuple[Rule, ...] = (
    Rule(
        "cli-usage",
        ("src/zaynor/cli.py",),
        ("README.md", "README.en.md"),
        require_all=True,
    ),
    Rule(
        "api-usage",
        ("src/zaynor/api.py",),
        ("README.md", "README.en.md"),
        require_all=True,
    ),
    Rule(
        "agent-roles",
        ("src/zaynor/agents/*", "src/zaynor/investigation_log.py"),
        ("README.md", "README.en.md"),
    ),
    Rule(
        "core-pipeline",
        (
            "src/zaynor/correlation.py",
            "src/zaynor/detection.py",
            "src/zaynor/replay.py",
            "src/zaynor/schemas.py",
            "src/zaynor/hash_utils.py",
            "src/zaynor/path_guard.py",
        ),
        ("AGENTS.md", "docs/adr/*"),
    ),
    Rule(
        "vigia-adapter",
        (
            "src/zaynor/adapter.py",
            "src/zaynor/vendored_engine.py",
            "src/zaynor/vigia_mcp_runner.py",
            "src/zaynor/zaynor_mode1_executor.py",
            "src/zaynor/case_freezer.py",
            "src/zaynor/frozen_snapshot.py",
        ),
        ("AGENTS.md", "docs/adr/*"),
    ),
    Rule(
        "authority-boundary",
        (
            "src/zaynor/authority_seal.py",
            "src/zaynor/hallucination_guard.py",
            "src/zaynor/custody.py",
            "src/zaynor/audit_log.py",
            "src/zaynor/hmac_chain.py",
            "src/zaynor/framework_context.py",
            "src/zaynor/d3fend_enrichment.py",
            "src/zaynor/response_actions.py",
            "src/zaynor/sigma_candidate.py",
        ),
        ("AGENTS.md", "docs/adr/*"),
    ),
    Rule(
        "mcp-contracts",
        (
            "src/zaynor/zaynor_mcp_server.py",
            "src/zaynor/zaynor_mcp_client.py",
            "src/zaynor/auxiliary_mcp_client.py",
            "src/zaynor/tools.py",
        ),
        ("docs/mcp-locales.md",),
    ),
    Rule("sandbox", ("src/zaynor/sandbox.py",), ("docs/SANDBOX.md",)),
    Rule("scorer", ("src/zaynor/ebs_artifact_scorer.py",), ("docs/adr/*",)),
    Rule("vendor", ("vendor/*",), ("AGENTS.md", "docs/adr/*")),
    Rule(
        "frontend-architecture",
        ("frontend/src/*",),
        ("docs/architecture-for-frontend.md",),
    ),
    Rule(
        "sdlc",
        (
            ".github/workflows/*",
            "scripts/*",
            ".pre-commit-config.yaml",
            "pyproject.toml",
        ),
        (
            "CONTRIBUTING.md",
            "CONTRIBUYENDO.md",
            "README.md",
            "README.en.md",
            "CHANGELOG.md",
        ),
    ),
)


@dataclass
class Outcome:
    """The evaluation of one triggered rule against the changed set."""

    rule: Rule
    code_files: list[str] = field(default_factory=list)
    missing_docs: list[str] = field(default_factory=list)
    waived: bool = False
    waiver_reason: str = ""

    @property
    def violated(self) -> bool:
        return bool(self.missing_docs) and not self.waived


def _git(*args: str) -> str:
    """Run one read-only git command and return its stdout."""
    result = subprocess.run(
        ["git", "-c", "core.quotepath=off", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def _normalize(path: str) -> str:
    """Normalize one git-reported path to a bare POSIX-style relative path."""
    return path.strip().removeprefix("./").replace("\\", "/")


def _match_any(path: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def _merge_base(base_ref: str, head: str = "HEAD") -> str:
    return _git("merge-base", base_ref, head).strip()


def changed_files_for_base(base_ref: str) -> list[str]:
    """Changed files from merge-base(base_ref, HEAD) to HEAD (branch diff)."""
    base = _merge_base(base_ref)
    return [
        _normalize(line)
        for line in _git("diff", "--name-only", f"{base}..HEAD").splitlines()
        if line.strip()
    ]


def changed_files_for_range(range_spec: str) -> list[str]:
    """Changed files across one explicit git range, e.g. ``base..head``."""
    return [
        _normalize(line)
        for line in _git("diff", "--name-only", range_spec).splitlines()
        if line.strip()
    ]


def changed_files_staged() -> list[str]:
    """Files staged in the index relative to HEAD."""
    return [
        _normalize(line)
        for line in _git("diff", "--name-only", "--cached", "HEAD").splitlines()
        if line.strip()
    ]


def load_waivers(range_spec: str) -> dict[str, str]:
    """Collect `Docs-Waiver: <rule-id> <reason>` trailers from a git range.

    Returns {rule_id: reason}; the last waiver in the range wins for a
    duplicate rule id. Only full-message lines whose key is
    ``Docs-Waiver`` (case-insensitive) count — prose mentioning the word
    does not, because Conventional Commits trailers are line-delimited.
    """
    blobs = _git("log", "--format=%x1e%B%x1e", range_spec)
    waivers: dict[str, str] = {}
    for blob in blobs.split("\x1e"):
        for line in blob.splitlines():
            stripped = line.strip()
            key, _, rest = stripped.partition(":")
            if key.strip().lower() != "docs-waiver":
                continue
            rule_id, _, reason = rest.strip().partition(" ")
            if rule_id:
                waivers[rule_id] = reason.strip()
    return waivers


def evaluate(files: list[str], waivers: dict[str, str] | None = None) -> list[Outcome]:
    """Evaluate DOCS_MAP against one changed-file set. Pure function."""
    waivers = waivers or {}
    outcomes: list[Outcome] = []
    for rule in DOCS_MAP:
        code_files = [path for path in files if _match_any(path, rule.paths)]
        if not code_files:
            continue
        if rule.require_all:
            missing = [
                pattern
                for pattern in rule.docs
                if not any(_match_any(path, (pattern,)) for path in files)
            ]
        else:
            satisfied = any(_match_any(path, rule.docs) for path in files)
            missing = [] if satisfied else list(rule.docs)
        reason = waivers.get(rule.id, "")
        outcomes.append(
            Outcome(
                rule=rule,
                code_files=code_files,
                missing_docs=missing,
                waived=rule.id in waivers,
                waiver_reason=reason,
            )
        )
    return outcomes


def _render(outcomes: list[Outcome], file_count: int) -> None:
    """Print a human-readable report to stderr."""
    plural = "rule" if len(outcomes) == 1 else "rules"
    print(
        f"docs_check: {file_count} changed files, {len(outcomes)} {plural} in scope",
        file=sys.stderr,
    )
    rejected = False
    for outcome in outcomes:
        if not outcome.violated and not outcome.waived:
            continue
        connector = "all of" if outcome.rule.require_all else "at least one of"
        doc_list = ", ".join(outcome.rule.docs)
        print(
            f"  rule '{outcome.rule.id}' (code: " f"{', '.join(outcome.code_files)})",
            file=sys.stderr,
        )
        if outcome.waived:
            reason = outcome.waiver_reason or "(no reason given)"
            print(f"    WAIVED by commit trailer — {reason}", file=sys.stderr)
        else:
            rejected = True
            print(f"    update {connector}: {doc_list}", file=sys.stderr)
    if rejected:
        print(
            "docs_check: REJECTED — code changed without the docs that "
            "describe it (DOCS_MAP in scripts/docs_check.py).",
            file=sys.stderr,
        )
        print(
            "docs_check: update the docs above, or waive this rule "
            "deliberately with a commit trailer: "
            "'Docs-Waiver: <rule-id> <reason>'.",
            file=sys.stderr,
        )
    else:
        print("docs_check: OK", file=sys.stderr)


def list_rules() -> None:
    """Print DOCS_MAP as a table (for onboarding and doc cross-references)."""
    for rule in DOCS_MAP:
        mode = "all" if rule.require_all else "any"
        print(f"{rule.id}:")
        print(f"  code: {', '.join(rule.paths)}")
        print(f"  docs ({mode}): {', '.join(rule.docs)}")


def _resolve_default_base() -> str:
    for candidate in (DEFAULT_BASE, "main"):
        try:
            _git("rev-parse", "--verify", candidate)
        except (subprocess.CalledProcessError, OSError):
            continue
        return candidate
    raise SystemExit(
        "docs_check: cannot determine a base ref (no 'origin/main' or "
        "'main'); pass --base <ref>, --git-range, --staged, or --files."
    )


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in ("-h", "--help"):
        print(__doc__, file=sys.stderr)
        return 0
    if args and args[0] == "--list-rules":
        list_rules()
        return 0

    try:
        if args and args[0] == "--base":
            if len(args) < 2:
                print("docs_check: --base requires a ref", file=sys.stderr)
                return 2
            files = changed_files_for_base(args[1])
            waivers = load_waivers(f"{_merge_base(args[1])}..HEAD")
        elif args and args[0] == "--git-range":
            if len(args) < 2:
                print("docs_check: --git-range requires '<base>..<head>'", file=sys.stderr)
                return 2
            files = changed_files_for_range(args[1])
            waivers = load_waivers(args[1])
        elif args and args[0] == "--staged":
            files = changed_files_staged()
            waivers = {}
        elif args and args[0] == "--files":
            rest = args[1:]
            if not rest and not sys.stdin.isatty():
                rest = [line.strip() for line in sys.stdin if line.strip()]
            files = [_normalize(path) for path in rest]
            waivers = {}
        else:
            base = _resolve_default_base()
            files = changed_files_for_base(base)
            waivers = load_waivers(f"{_merge_base(base)}..HEAD")
    except SystemExit:
        raise
    except subprocess.CalledProcessError as exc:
        print(f"docs_check: git failed: {exc.stderr.strip()}", file=sys.stderr)
        return 2

    outcomes = evaluate(files, waivers)
    _render(outcomes, len(files))
    if any(outcome.violated for outcome in outcomes):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
