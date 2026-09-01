#!/usr/bin/env bash
# Idempotent installer: point .git/hooks/{pre-commit,pre-push} at scripts/.
#
# Both gates matter and they cover different ground: pre-commit is the ~10s
# fast pass on every commit, pre-push is the slower pair (lint, web build) that
# used to be discovered only by CI. Installing just one leaves the gap that
# every CI failure in this repo has fallen into.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"

install_hook() {
  local name="$1"
  local hook="$ROOT/.git/hooks/$name"
  local target="../../scripts/$name.sh"

  chmod +x "$ROOT/scripts/$name.sh"

  if [[ -L "$hook" && "$(readlink "$hook")" == "$target" ]]; then
    echo "✓ $name hook already installed"
    return 0
  fi

  if [[ -e "$hook" ]]; then
    mv "$hook" "$hook.bak.$(date +%s 2>/dev/null || echo backup)"
    echo "moved existing hook to $hook.bak.*"
  fi

  ln -s "$target" "$hook"
  echo "✓ installed $name hook -> scripts/$name.sh"
}

install_hook pre-commit
install_hook pre-push
