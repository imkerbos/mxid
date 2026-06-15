#!/usr/bin/env bash
# Idempotent installer: point .git/hooks/pre-commit at scripts/pre-commit.sh.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
HOOK="$ROOT/.git/hooks/pre-commit"
TARGET="../../scripts/pre-commit.sh"

chmod +x "$ROOT/scripts/pre-commit.sh"

if [[ -L "$HOOK" && "$(readlink "$HOOK")" == "$TARGET" ]]; then
  echo "✓ pre-commit hook already installed"
  exit 0
fi

if [[ -e "$HOOK" ]]; then
  mv "$HOOK" "$HOOK.bak.$(date +%s 2>/dev/null || echo backup)"
  echo "moved existing hook to $HOOK.bak.*"
fi

ln -s "$TARGET" "$HOOK"
echo "✓ installed pre-commit hook -> scripts/pre-commit.sh"
