#!/usr/bin/env bash
# Rebuild hack/internal-data-patterns.local.txt from what this machine knows.
#
# Why generated rather than maintained by hand: the hand-written list only ever
# contains what someone remembered to add, and the one time it mattered it was
# missing entirely — the hooks ran and passed because they had no rules for this
# project. Anything derivable from the machine should come from the machine.
#
# This script is safe to publish; its OUTPUT is not. The output is the list of
# strings to grep for, which is a map of exactly what must not be published, so
# .gitignore keeps *.local.txt out of the repository.
#
# Sources, all local and read-only:
#   - kubectl contexts, clusters and their API host names
#   - git remotes that are not the public ones
#   - git remotes other than the public ones
#
# It deliberately does NOT reach into a production database. Service and person
# names live there, but a script that connects to production to build a grep
# list is a worse idea than a slightly shorter list; add those by hand below the
# generated block.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2

OUT=hack/internal-data-patterns.local.txt
KEEP_BELOW="# ── 手工补充（生成时保留）─────────────────────────────"

# Words that look like identifiers but are too common to grep for: matching
# them would make the gate cry wolf, and a gate that cries wolf gets turned off.
# A generated list is only useful if people leave it switched on, so the noise
# filter matters more than the coverage. The first version swept up every
# "a.b" shape it saw and produced rules for https, local.mk and golangci.yml —
# the gate then fired on the README and would have been disabled within a day.
TOO_COMMON='^(com|net|org|local|localhost|default|kubernetes|docker|desktop|cluster|admin|test|dev|prod|staging|internal|svc|api|app|www|github|gitlab|https|http|example|invalid)$'
# Loopback and wildcard addresses come out of a kubeconfig server URL and then
# match half the repository — config defaults, docs, tests. A rule that fires
# on configs/config.yaml teaches people to ignore the gate.
TOO_COMMON_ADDR='^(127\.0\.0\.1|0\.0\.0\.0|::1|localhost|host\.docker\.internal|kubernetes\.default)$'
# File names are not environment identifiers.
FILE_EXT='\.(md|ya?ml|toml|mk|json|go|ts|tsx|js|sh|txt|sql|lock|mod|sum|env|conf|cfg|ini|log|png|svg|html|css)$'

collect() {
  tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9.-' '\n' \
    | grep -vE "$TOO_COMMON" | grep -vE "$TOO_COMMON_ADDR" | grep -vE "$FILE_EXT" | sort -u
}

tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT

# 1. kubectl contexts / clusters / API hosts
if command -v kubectl >/dev/null 2>&1; then
  kubectl config get-contexts -o name 2>/dev/null | collect >> "$tmp"
  kubectl config view -o jsonpath='{.clusters[*].name}{"\n"}{.clusters[*].cluster.server}{"\n"}' 2>/dev/null \
    | collect >> "$tmp"
fi

# 2. git remotes that are not the public ones
git remote -v 2>/dev/null | grep -vE 'github\.com[:/](imkerbos|matrixplusio)/' \
  | grep -ohE '[a-z0-9-]+(\.[a-z0-9-]+){1,}' | collect >> "$tmp"

words=()
while IFS= read -r w; do
  [ -n "$w" ] && words+=("$w")
done < <(grep -E '^[a-z0-9][a-z0-9.-]{3,}$' "$tmp" | sort -u)

{
  cat <<'HEADER'
# 本机环境数据的匹配规则。生成文件，不要手工改生成块——跑 hack/gen-local-patterns.sh。
#
# 这份文件本身就是「哪些字符串不能公开」的清单，所以它绝不能进仓库
# （.gitignore 挡着 hack/*.local.txt，leakcheck 专门读 .local 这一份）。
#
# 格式：名字|正则[|skip=<路径正则>]
# 整词匹配、忽略大小写。两侧用 (?<![a-z0-9]) / (?![a-z0-9]) 而不是 \b——
# \b 在下划线旁不成立，Name_Suffix 这种写法会整个躲过检查。

HEADER
  for w in ${words[@]+"${words[@]}"}; do
    esc=$(printf '%s' "$w" | sed 's/[.[\*^$()+?{|]/\\&/g')
    printf '本机标识|(?<![a-z0-9])%s(?![a-z0-9])\n' "$esc"
  done
  echo
  echo "$KEEP_BELOW"
  # Carry over whatever was written by hand under the marker last time.
  if [ -f "$OUT" ] && grep -qF "$KEEP_BELOW" "$OUT"; then
    sed -n "/$(printf '%s' "$KEEP_BELOW" | sed 's/[][\.*^$/]/\\&/g')/,\$p" "$OUT" | tail -n +2
  fi
} > "$OUT.new"

mv "$OUT.new" "$OUT"
echo "==> 生成 ${OUT}：${#words[@]} 条自动 + 手工补充段"
echo "    检查一遍再用：误报会让门禁最后被整个关掉。"
