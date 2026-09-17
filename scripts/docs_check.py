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
- A deliberate waiver is a commit trailer in the checked range: the final
  paragraph of the message, as a contiguous ``key: value`` block (the way
  ``git interpret-trailers`` defines it)::

      Docs-Waiver: <rule-id> <short reason>

  Waivers are per-rule, visible in git history, and reported (never
  silent). A trailer-shaped line anywhere else in the body — an example,
  an illustration followed by more prose — is not a waiver.
- Exit codes: 0 accepts, 1 rejects (violations listed), 2 is an internal
  error. Violations print to stderr, so the `pre-push` hook can simply run
  the script and let its exit status decide.

The map is intentionally file-level and conservative: a module with no doc
contract imposes none. When you add a part of the codebase that has a doc
contract, add the rule here in the same change.
"""

from __future__ import annotations

import fnmatch
import re
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

    Returns {rule_id: reason}; the newest commit's waiver wins for a
    duplicate rule id. A waiver only counts in *trailer position*: the
    final paragraph of the message must be a contiguous block of
    ``key: value`` lines, the way ``git interpret-trailers`` defines it.
    A trailer-shaped line anywhere else — mid-body prose, an example
    inside backticks, an illustration followed by more prose — is not a
    waiver, because waivers must be deliberate and placed, not accidental.
    """
    commits = _git("rev-list", "--reverse", range_spec).split()
    waivers: dict[str, str] = {}
    for commit in commits:
        body = _git("log", "--format=%B", "-n", "1", commit)
        for key, value in _message_trailers(body):
            if key.lower() != "docs-waiver":
                continue
            rule_id, _, reason = value.partition(" ")
            if rule_id:
                waivers[rule_id] = reason.strip()
    return waivers


# A trailer line is one ``token: value`` line — a token with no spaces
# (``git interpret-trailers`` also accepts ``[...]`` brackets and ``#``
# separators, which this gate does not need). Separator lines, comments,
# and indented lines are never trailer lines.
_TRAILER_LINE = re.compile(r"^(?!#|---)(?P<key>[^\s:#]+)\s*:\s*(?P<value>.*)$")


def _is_trailer_line(line: str) -> bool:
    """One ``key: value`` line, never a separator, comment, or indented line."""
    if not line.strip() or line[:1] in (" ", "\t"):
        return False
    match = _TRAILER_LINE.match(line)
    return match is not None and bool(match.group("key").strip())


def _message_trailers(body: str) -> list[tuple[str, str]]:
    """Return the ``key: value`` pairs of one message's trailer block.

    Trailer semantics, in the shape ``git interpret-trailers`` applies:
    the block starts at the first line of the final paragraph whose lines
    are all ``key: value`` (or continuation lines starting with a space);
    if some line of that paragraph is not trailer-shaped, or the message
    is a single paragraph, there is no trailer block. Separator and
    comment lines (``---``, ``# ...``, scissors) are never trailers.
    """
    lines = body.splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    if not lines:
        return []
    block: list[str] = []
    for line in reversed(lines):
        if not line.strip():
            break
        if _is_trailer_line(line) or line[:1] in (" ", "\t"):
            # An indented line is a continuation: git folds it into the
            # trailer above it, or treats a lone indented final line as a
            # one-line non-trailer paragraph (no trailer block). A later
            # non-trailer line still kills the block below.
            block.append(line)
            continue
        return []
    if len(block) == len(lines):
        # A single-paragraph message has no trailer block: its first line
        # is the subject, so a one-line ``Docs-Waiver: ...`` message is a
        # subject, not a trailer — same as git.
        return []
    trailers: list[tuple[str, str]] = []
    for raw in reversed(block):
        if raw[:1] in (" ", "\t"):
            if not trailers:
                # Lone indented final line: git reads it as a one-line
                # continuation paragraph, so there is no trailer block.
                return []
            key, value = trailers[-1]
            trailers[-1] = (key, f"{value} {raw.strip()}")
            continue
        match = _TRAILER_LINE.match(raw.strip())
        if match is None:  # unreachable: _is_trailer_line matched above
            continue
        trailers.append((match.group("key"), match.group("value").strip()))
    return trailers


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
            "docs_check: update the docs above in this branch, or — when "
            "the docs genuinely need no change — record that decision with "
            "a trailer in the final paragraph of the commit message: "
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
