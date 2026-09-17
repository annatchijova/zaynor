#!/usr/bin/env bash
# install-hooks.sh — install ZAYNOR's git hooks (stdlib-first, no Node).
#
# Installs two hooks into this repo's .git/hooks:
#   commit-msg — runs scripts/commitlint.py (Conventional Commits gate).
#   pre-push   — blocks non-fast-forward (force) pushes; the hook body is
#                scripts/git-hooks/pre-push (single source of truth, also
#                installed by docs/skills/git-discipline/scripts/install_guard_hooks.sh).
#
# Pre-commit linting/formatting is handled by .pre-commit-config.yaml
# (run `pre-commit install` separately); these native hooks have zero
# dependencies beyond python3 + git, so they work on a bare clone.
#
# Usage: ./scripts/install-hooks.sh [--force]
set -euo pipefail

FORCE=0
if [ "${1:-}" = "--force" ]; then
    FORCE=1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "ERROR: not inside a git work tree." >&2
    exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOK_DIR="$(git rev-parse --git-path hooks)"
mkdir -p "$HOOK_DIR"

install_hook() {
    local name="$1"
    local target="$HOOK_DIR/$name"
    if [ -e "$target" ] && [ "$FORCE" -ne 1 ]; then
        echo "SKIP: $target already exists (use --force to overwrite)."
        return 0
    fi
    cp "$REPO_ROOT/scripts/git-hooks/$name" "$target"
    chmod +x "$target"
    echo "Installed $name -> $target"
}

install_hook "commit-msg"
install_hook "pre-push"
echo "Done. Hooks run scripts/commitlint.py and the force-push guard."
echo "For lint/format hooks: pip install pre-commit && pre-commit install"
