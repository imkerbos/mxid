#!/usr/bin/env bash
# Boot-time smoke test. Exercises every console module's primary list
# endpoint as the seeded admin user.
#
# Catches the class of bug that compile + unit tests miss:
#   - nil-pointer panic in cross-module adapter wiring (e.g. authzBindingProvider.app)
#   - middleware ordering regressions
#   - migration drift that breaks list queries
#
# Captcha is bypassed by writing a known answer directly into Redis under
# a self-minted UUID. The backend's captcha store reads exactly this key,
# so login proceeds normally — no production code is changed.
#
# Prereqs (host-side): backend on :10050, redis container `redis` reachable
# via `docker exec redis redis-cli`, jq, uuidgen, curl.

set -euo pipefail

BASE="${MXID_CONSOLE_BASE:-http://localhost:10050/api/v1/console}"
PORTAL_BASE="${MXID_PORTAL_BASE:-http://localhost:10050/api/v1/portal}"
HEALTH="${MXID_HEALTH:-http://localhost:10050/health}"
ADMIN_USER="${MXID_ADMIN_USER:-admin}"
ADMIN_PASS="${MXID_ADMIN_PASS:-admin123}"
REDIS_CTR="${MXID_REDIS_CTR:-redis}"
REDIS_PASS="${MXID_REDIS_PASS:-123456}"
WAIT_S="${MXID_SMOKE_WAIT:-30}"

red()   { printf "\033[1;31m%s\033[0m\n" "$*" >&2; }
green() { printf "\033[1;32m%s\033[0m\n" "$*" >&2; }
log()   { printf "\033[1;36m[smoke]\033[0m %s\n" "$*" >&2; }
die()   { red "✗ $*"; exit 1; }

for bin in curl jq uuidgen docker; do
  command -v $bin >/dev/null 2>&1 || die "missing dependency: $bin"
done

# 1. Wait for backend health.
log "waiting for $HEALTH (up to ${WAIT_S}s) …"
for ((i=0; i<WAIT_S; i++)); do
  if curl -fsS "$HEALTH" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS "$HEALTH" >/dev/null || die "backend not healthy at $HEALTH"

# 2. Inject captcha into Redis directly.
CAPTCHA_ID="$(uuidgen)"
CAPTCHA_CODE="smoke1"
docker exec "$REDIS_CTR" redis-cli -a "$REDIS_PASS" --no-auth-warning \
  SET "mxid:captcha:$CAPTCHA_ID" "$CAPTCHA_CODE" EX 300 >/dev/null \
  || die "failed to seed captcha in redis ($REDIS_CTR)"

# 3. Login as admin.
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT
LOGIN_BODY="$(jq -nc \
  --arg u "$ADMIN_USER" --arg p "$ADMIN_PASS" \
  --arg cid "$CAPTCHA_ID" --arg ccd "$CAPTCHA_CODE" \
  '{username:$u, password:$p, captcha_id:$cid, captcha_code:$ccd}')"

LOGIN_RESP="$(curl -fsS -c "$JAR" -b "$JAR" \
  -H 'Content-Type: application/json' \
  -d "$LOGIN_BODY" \
  "$BASE/auth/login")" \
  || die "login failed for $ADMIN_USER"

green "✓ login OK"

# 4. Hit one list/probe endpoint per module.
#    Add new modules here as they ship. Any non-2xx fails the smoke.
PROBES=(
  "GET  /auth/me"
  "GET  /users?page=1&page_size=20"
  "GET  /orgs"
  "GET  /tenants"
  "GET  /groups?page=1&page_size=20"
  "GET  /apps?page=1&page_size=20"
  "GET  /external-idps"
  "GET  /external-idps/types"
  "GET  /audit/logs?page=1&page_size=20"
  "GET  /audit/stats"
  "GET  /permissions"
)

FAIL=0
for probe in "${PROBES[@]}"; do
  method="${probe%% *}"; path="${probe##* }"
  code="$(curl -s -o /tmp/smoke-body -w '%{http_code}' \
    -b "$JAR" -X "$method" "$BASE$path")"
  if [[ "$code" =~ ^2 ]]; then
    printf "  \033[1;32m✓\033[0m %3s %s -> %s\n" "$method" "$path" "$code" >&2
  else
    printf "  \033[1;31m✗\033[0m %3s %s -> %s\n" "$method" "$path" "$code" >&2
    head -c 500 /tmp/smoke-body >&2; printf "\n" >&2
    FAIL=$((FAIL+1))
  fi
done

# 5. Portal smoke. Login via captcha-inject trick (same as console) on
#    /portal/auth/login, then probe end-user surfaces.
CAPTCHA_ID2="$(uuidgen)"
CAPTCHA_CODE2="smoke2"
docker exec "$REDIS_CTR" redis-cli -a "$REDIS_PASS" --no-auth-warning \
  SET "mxid:captcha:$CAPTCHA_ID2" "$CAPTCHA_CODE2" EX 300 >/dev/null \
  || die "failed to seed portal captcha"

PORTAL_JAR="$(mktemp)"
trap 'rm -f "$JAR" "$PORTAL_JAR"' EXIT
LOGIN_BODY2="$(jq -nc \
  --arg u "$ADMIN_USER" --arg p "$ADMIN_PASS" \
  --arg cid "$CAPTCHA_ID2" --arg ccd "$CAPTCHA_CODE2" \
  '{username:$u, password:$p, captcha_id:$cid, captcha_code:$ccd}')"

curl -fsS -c "$PORTAL_JAR" -b "$PORTAL_JAR" \
  -H 'Content-Type: application/json' \
  -d "$LOGIN_BODY2" \
  "$PORTAL_BASE/auth/login" >/dev/null \
  || die "portal login failed for $ADMIN_USER"

green "✓ portal login OK"

PORTAL_PROBES=(
  "GET  /auth/me"
  "GET  /apps"
  "GET  /app-groups"
  "GET  /apps/favorites"
  "GET  /apps/recent"
)
for probe in "${PORTAL_PROBES[@]}"; do
  method="${probe%% *}"; path="${probe##* }"
  code="$(curl -s -o /tmp/smoke-body -w '%{http_code}' \
    -b "$PORTAL_JAR" -X "$method" "$PORTAL_BASE$path")"
  if [[ "$code" =~ ^2 ]]; then
    printf "  \033[1;32m✓\033[0m portal %3s %s -> %s\n" "$method" "$path" "$code" >&2
  else
    printf "  \033[1;31m✗\033[0m portal %3s %s -> %s\n" "$method" "$path" "$code" >&2
    head -c 500 /tmp/smoke-body >&2; printf "\n" >&2
    FAIL=$((FAIL+1))
  fi
done

# Assert at least one app surfaces — empty here means access policy / SQL
# regression like the mxid_org typo we just shipped a fix for.
APPS_COUNT="$(curl -s -b "$PORTAL_JAR" "$PORTAL_BASE/apps" | jq '.data | length')"
if [[ "$APPS_COUNT" == "0" ]]; then
  printf "  \033[1;31m✗\033[0m portal /apps returned 0 apps (expected ≥1)\n" >&2
  FAIL=$((FAIL+1))
else
  printf "  \033[1;32m✓\033[0m portal /apps contains %s app(s)\n" "$APPS_COUNT" >&2
fi

rm -f /tmp/smoke-body

if (( FAIL > 0 )); then
  die "$FAIL probe(s) failed"
fi
green "✓ smoke OK (${#PROBES[@]} console + ${#PORTAL_PROBES[@]} portal probes)"
