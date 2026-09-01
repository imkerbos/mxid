#!/usr/bin/env bash
# Pre-push gate — the two checks that are in `make verify` but too slow for
# pre-commit, and that nothing else ran before the code reached CI.
#
# Every CI failure this repo has had fell into the gap between the three gates:
#
#   pre-commit   verify-mod / vet / build / gormtaglint  (~10s, every commit)
#   pre-push     verify-lint [+ verify-web]              (this file)
#   CI           all of the above + the test suite
#
# golangci-lint and `pnpm -r build` sat in `make verify` that nobody ran, so
# they were first exercised in the cloud, seven minutes after the push. Three of
# the six CI failures were exactly those two.
#
# Cost control: lint only when Go files moved, the web build only when web/
# moved. A docs-only push pays nothing.
#
# Bypass (use sparingly; CI still runs the full suite):
#   SKIP_VERIFY=1 git push ...
set -euo pipefail

if [[ "${SKIP_VERIFY:-0}" == "1" ]]; then
  echo "SKIP_VERIFY=1 set — skipping pre-push verify"
  exit 0
fi

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

ZERO='0000000000000000000000000000000000000000'

# `git push` feeds "<localref> <localsha> <remoteref> <remotesha>" on stdin, one
# line per ref. Collect the changed paths across every branch ref being pushed.
changed=''
gated=0
while read -r _localref localsha remoteref remotesha; do
  # Deleting a ref pushes a zero local sha — nothing to check.
  [[ "$localsha" == "$ZERO" ]] && continue

  # Only dev/main. Feature branches stay cheap to push; a tag is gated in the
  # cloud by the release workflow, which runs the whole CI suite before buildx.
  case "$remoteref" in
    refs/heads/dev|refs/heads/main) ;;
    *) continue ;;
  esac
  gated=1

  if [[ "$remotesha" == "$ZERO" ]]; then
    # New branch on the remote: no baseline to diff against, so check everything.
    changed="$(git ls-tree -r --name-only "$localsha")"
    break
  fi

  changed+=$'\n'"$(git diff --name-only "$remotesha".."$localsha")"
done

if [[ "$gated" == "0" ]]; then
  echo "==> pre-push: nothing bound for dev/main — skipping"
  exit 0
fi

# if-blocks, not `grep && targets+=`: under `set -e` a non-matching grep is a
# failing top-level command and would abort the push instead of skipping a gate.
targets=()
if grep -qE '\.go$|^go\.(mod|sum)$' <<<"$changed"; then targets+=(verify-lint); fi
if grep -qE '^web/'                  <<<"$changed"; then targets+=(verify-web);  fi

if [[ ${#targets[@]} -eq 0 ]]; then
  echo "==> pre-push: no Go or web/ changes — skipping"
  exit 0
fi

echo "==> pre-push: make ${targets[*]}"
make "${targets[@]}"

echo "✓ pre-push OK"
