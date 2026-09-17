#!/usr/bin/env bash
# install_guard_hooks.sh — Install a pre-push hook that blocks force pushes.
#
# The prompt-level prohibition on force-push relies on the agent obeying it.
# This enforces it mechanically: a pre-push hook that aborts when the push
# rewrites the remote branch (a non-fast-forward / forced update).
#
# The hook body lives in exactly one place — scripts/git-hooks/pre-push —
# and this installer copies that file, so the two install paths
# (scripts/install-hooks.sh and this script) cannot drift apart.
#
# Usage: run from inside the repo:  ./install_guard_hooks.sh
set -euo pipefail

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "ERROR: not inside a git work tree." >&2
    exit 1
fi

repo_root="$(git rev-parse --show-toplevel)"
hook_dir="$(git rev-parse --git-path hooks)"
mkdir -p "$hook_dir"
hook="$hook_dir/pre-push"

cp "$repo_root/scripts/git-hooks/pre-push" "$hook"
chmod +x "$hook"
echo "Installed pre-push guard hook at: $hook"
echo "It blocks forced/rewriting pushes. A human can bypass deliberately with --no-verify."
