#!/usr/bin/env python3
"""Conventional Commits gate for ZAYNOR — stdlib only, no Node required.

Reads one commit message (a file path, or stdin when no path is given) and
exits 0 when it satisfies the Conventional Commits contract this repo
enforces, non-zero with a human-readable explanation otherwise.

Accepted shape (mirrors AGENTS.md section 4 and the commit history on
main, which already follows it):

    <type>[optional scope][!]: <imperative description>

    [optional body]

    [optional footer(s)]

Rules enforced:

- ``type`` is one of the allowlisted types below (AGENTS.md section 4
  plus the ``security``/``perf``/``style``/``ci``/``build`` types already
  present in main's history).
- ``scope``, when present, is lowercase alphanumerics, ``-`` or ``/``
  (e.g. ``feat(frontend)``, ``fix(telemetry)``).
- The header's description is non-empty, starts lowercase, and the full
  header line is at most 100 characters. (Proper nouns such as ``OTel``,
  filenames in ``UPPERCASE.md``, and acronyms like ``VIGÍA`` at the start
  of the description are accepted — the lowercase rule only rejects a
  leading *sentence-case* word like ``Add ...``.)
- ``Merge ...`` and ``Revert ...`` headers pass untouched (git-generated).
- A ``HACKATHON:`` / ``POST HACKATHON:`` prefix passes with a deprecation
  warning on stderr: the prefix predates the Conventional Commits gate
  and is grandfathered, not banned — new commits should not use it.

Usage as a git hook (installed by ``scripts/install-hooks.sh``)::

    python3 scripts/commitlint.py .git/COMMIT_EDITMSG

Exit codes: 0 accepts, 1 rejects, 2 is an internal error (missing file).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ALLOWED_TYPES = frozenset(
    {
        "feat",
        "fix",
        "docs",
        "style",
        "refactor",
        "test",
        "chore",
        "perf",
        "ci",
        "build",
        "security",
        "revert",
    }
)

_HEADER = re.compile(
    r"^(?P<type>[a-z]+)"
    r"(?:\((?P<scope>[A-Za-z0-9][A-Za-z0-9_./-]*)\))?"
    r"(?P<breaking>!)?"
    r": (?P<description>.+)$"
)
_SCOPE = re.compile(r"^[a-z0-9][a-z0-9_./-]*$")
_LEGACY_PREFIX = re.compile(r"^(?:POST\s+HACKATHON|HACKATHON)\s*:\s*", re.IGNORECASE)
_MERGE_OR_REVERT = re.compile(r"^(?:Merge|Revert)\b", re.IGNORECASE)
_MAX_HEADER_LENGTH = 100
# Leading tokens the lowercase-description rule must not flag: filenames in
# full caps (``GUIA_PERITOS.md, ...``), acronyms (``OTel ...``, ``VIGÍA ...``),
# and similar proper nouns at the start of the description. A plain
# sentence-case word (``Add``, ``Update``, ``Fix``) is still rejected.
_LOWERCASE_EXEMPT = re.compile(
    r"^(?:[A-Z][A-Za-z]*[._-][A-Za-z0-9._-]*\.?[A-Za-z]*|OTel|VIG[IÍ]A|API|MCP|OTel|NIST|MITRE)\b"
)


def _load_allowlist() -> frozenset[str]:
    """Grandfathered pre-gate headers (see .commitlint-allowlist)."""
    allowlist = Path(__file__).resolve().parent.parent / ".commitlint-allowlist"
    try:
        return frozenset(
            line.strip()
            for line in allowlist.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        )
    except OSError:
        return frozenset()


def check_subject(header: str) -> list[str]:
    """Return a list of violations for one header line (empty means accept)."""
    errors: list[str] = []
    if _MERGE_OR_REVERT.match(header):
        return errors
    if header.strip() in _load_allowlist():
        return errors
    legacy = _LEGACY_PREFIX.match(header)
    if legacy:
        print(
            "commitlint: warning: 'HACKATHON:'/'POST HACKATHON:' prefix is "
            "deprecated; prefer a plain Conventional Commits header.",
            file=sys.stderr,
        )
        return errors  # grandfathered: warn, do not reject
    if len(header) > _MAX_HEADER_LENGTH:
        errors.append(
            f"header is {len(header)} characters (limit {_MAX_HEADER_LENGTH})"
        )
    match = _HEADER.match(header)
    if match is None:
        errors.append("header must match '<type>[optional scope][!]: <description>'")
        return errors
    commit_type = match.group("type")
    if commit_type not in ALLOWED_TYPES:
        errors.append(
            f"unknown type {commit_type!r} (allowed: {', '.join(sorted(ALLOWED_TYPES))})"
        )
    scope = match.group("scope")
    if scope is not None and _SCOPE.match(scope) is None:
        errors.append(
            f"invalid scope {scope!r} (lowercase alphanumerics, '-', '/', '.', '_')"
        )
    description = match.group("description").strip()
    if not description:
        errors.append("description must not be empty")
    elif description[0].isupper() and not _LOWERCASE_EXEMPT.match(description):
        errors.append("description must start lowercase ('Add ...' -> 'add ...')")
    if header != header.rstrip():
        errors.append("header must not have trailing whitespace")
    return errors


def check_message(text: str) -> list[str]:
    """Validate a full commit message; ignore comment and diff lines."""
    lines = [
        line
        for line in text.splitlines()
        if not line.startswith("#") and line != "-- "
    ]
    while lines and not lines[0].strip():
        lines.pop(0)
    if not lines:
        return ["commit message is empty"]
    return check_subject(lines[0].rstrip("\n"))


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if args:
            text = Path(args[0]).read_text(encoding="utf-8")
        else:
            text = sys.stdin.read()
    except OSError as exc:
        print(f"commitlint: cannot read commit message: {exc}", file=sys.stderr)
        return 2
    errors = check_message(text)
    if errors:
        header = next(
            (line for line in text.splitlines() if line.strip() and not line.startswith("#")),
            "",
        )
        print(f"commitlint: rejected commit header: {header!r}", file=sys.stderr)
        for error in errors:
            print(f"commitlint:   - {error}", file=sys.stderr)
        print(
            "commitlint: expected '<type>[optional scope][!]: <description>', e.g. "
            "'feat(core): add new evidence profile' or "
            "'fix(telemetry): correct OTel span naming'.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
