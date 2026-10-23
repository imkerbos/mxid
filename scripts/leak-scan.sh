#!/usr/bin/env bash
# Refuse content that must not be published from this repository.
#
# Runs in two places off one rule file, so the two cannot drift apart:
#   - locally, through the pre-commit / pre-push hooks
#   - in CI, where no client-side flag can skip it
#
# CI deliberately sees only hack/internal-data-patterns.txt, which contains
# shapes rather than values. The machine-local list of actual strings stays out
# of the repository: shipping it would publish exactly what it is meant to keep
# unpublished.
#
# Usage:
#   leak-scan.sh                 scan every tracked file
#   leak-scan.sh <range>         also scan the lines and messages a push adds
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 2

RULE_FILES=(hack/internal-data-patterns.txt hack/internal-data-patterns.local.txt)
RANGE="${1:-}"
RED=$'\033[31m'; DIM=$'\033[2m'; OFF=$'\033[0m'
[ -t 1 ] || { RED=""; DIM=""; OFF=""; }

names=(); pats=(); skips=()
for f in "${RULE_FILES[@]}"; do
  [ -f "$f" ] || continue
  while IFS= read -r line; do
    case "$line" in ''|'#'*) continue ;; esac
    name=${line%%|*}; rest=${line#*|}
    skip=""
    case "$rest" in *'|skip='*) skip=${rest##*|skip=}; rest=${rest%|skip=*} ;; esac
    names+=("$name"); pats+=("$rest"); skips+=("$skip")
  done < "$f"
done

if [ ${#pats[@]} -eq 0 ]; then
  echo "leak-scan: 没有任何规则，拒绝以空检查冒充通过" >&2
  exit 2
fi
echo "==> leak-scan: ${#pats[@]} 条规则"

found=0
report() { printf '%s✗ %s%s\n    %s（%s）\n' "$RED" "$1" "$OFF" "$2" "$3"; found=1; }

# 1. every tracked file
while IFS= read -r file; do
  [ -f "$file" ] || continue
  grep -Iq . "$file" 2>/dev/null || continue   # skip binaries
  for i in "${!pats[@]}"; do
    [ -n "${skips[$i]}" ] && printf '%s' "$file" | grep -qE -e "${skips[$i]}" && continue
    if hit=$(grep -n -i -E -e "${pats[$i]}" "$file" 2>/dev/null | head -1); then
      [ -n "$hit" ] && report "${names[$i]}" "$file" "第 ${hit%%:*} 行"
    fi
  done
done < <(git ls-files)

# 2. what this push adds — content and messages alike. A name that is added and
#    later removed leaves nothing in the net diff but stays in the history, so
#    this walks each commit rather than diffing the endpoints.
if [ -n "$RANGE" ]; then
  added=$(git log -p --unified=0 --no-color --format='%n@@COMMIT %H@@' "$RANGE" 2>/dev/null \
          | grep -E '^(\+[^+]|@@COMMIT)' || true)
  msgs=$(git log --format='%B' "$RANGE" 2>/dev/null || true)
  for i in "${!pats[@]}"; do
    printf '%s' "$added" | grep -qi -E -e "${pats[$i]}" && report "${names[$i]}" "待推送的新增行" "$RANGE"
    printf '%s' "$msgs"  | grep -qi -E -e "${pats[$i]}" && report "${names[$i]}" "待推送的提交信息" "$RANGE"
  done
fi

if [ "$found" -eq 1 ]; then
  printf '%s修掉它，不要绕过检查。%s\n' "$DIM" "$OFF"
  exit 1
fi
echo "✓ leak-scan OK"
