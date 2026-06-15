#!/usr/bin/env bash
# seed-test-oidc.sh — provision a minimal OIDC test fixture in the dev backend.
#
# Creates an OIDC application named "oidc-test" with a fixed redirect_uri
# of http://localhost:8090/callback, then prints client_id + client_secret.
# Logs in as the seeded admin first to obtain the console session cookie
# required for the create call.
#
# Prereqs: mxid backend running on localhost:10050, postgres + redis up.
# Default admin credentials match migrations/000009_seed_admin.up.sql:
#   admin / admin123

set -euo pipefail

CONSOLE_BASE="${MXID_CONSOLE_BASE:-http://localhost:10050/api/v1/console}"
ADMIN_USER="${MXID_ADMIN_USER:-admin}"
ADMIN_PASS="${MXID_ADMIN_PASS:-admin123}"
APP_CODE="${MXID_TEST_APP_CODE:-oidc-test}"
REDIRECT_URI="${MXID_TEST_REDIRECT_URI:-http://localhost:8090/callback}"

JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

log() { printf "\033[1;36m[seed]\033[0m %s\n" "$*" >&2; }
die() { printf "\033[1;31m[seed]\033[0m %s\n" "$*" >&2; exit 1; }

log "fetching captcha …"
CAPTCHA_JSON="$(curl -fsS -c "$JAR" "$CONSOLE_BASE/auth/captcha")"
CAPTCHA_ID="$(printf '%s' "$CAPTCHA_JSON" | sed -nE 's/.*"captcha_id":"([^"]+)".*/\1/p')"
CAPTCHA_IMG="$(printf '%s' "$CAPTCHA_JSON" | sed -nE 's/.*"captcha_image":"([^"]+)".*/\1/p')"
[ -n "$CAPTCHA_ID" ] || die "captcha_id missing in response: $CAPTCHA_JSON"

# Surface captcha to the operator. The captcha image is a data: URL so we
# render it as a tmpfile + open via xdg-open / open if available; otherwise
# the user can read the encoded base64.
TMP_IMG="$(mktemp -t mxid-captcha-XXXXXX.png)"
printf '%s' "$CAPTCHA_IMG" | sed 's|^data:image/png;base64,||' | base64 -d > "$TMP_IMG" 2>/dev/null || true
log "captcha saved: $TMP_IMG (open this file then enter the code)"
if command -v open >/dev/null 2>&1; then open "$TMP_IMG"; fi
read -r -p "captcha code: " CAPTCHA_CODE

log "logging in as $ADMIN_USER …"
LOGIN_BODY="$(printf '{"username":"%s","password":"%s","captcha_id":"%s","captcha_code":"%s"}' \
    "$ADMIN_USER" "$ADMIN_PASS" "$CAPTCHA_ID" "$CAPTCHA_CODE")"
LOGIN_RESP="$(curl -fsS -c "$JAR" -b "$JAR" \
    -H 'Content-Type: application/json' \
    -d "$LOGIN_BODY" \
    "$CONSOLE_BASE/auth/login")" || die "login failed: $LOGIN_RESP"

log "creating OIDC application '$APP_CODE' …"
CREATE_BODY=$(cat <<EOF
{
  "name": "OIDC Test Application",
  "code": "$APP_CODE",
  "protocol": "oidc",
  "client_type": "web_app",
  "description": "Auto-provisioned by seed-test-oidc.sh — safe to delete.",
  "home_url": "$REDIRECT_URI",
  "redirect_uris": ["$REDIRECT_URI"],
  "protocol_config": {
    "redirect_uris": ["$REDIRECT_URI"],
    "scopes": ["openid", "profile", "email", "groups"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "client_secret_basic",
    "pkce_required": false,
    "access_token_lifetime": 3600,
    "id_token_lifetime": 3600,
    "refresh_token_lifetime": 2592000,
    "id_token_signing_alg": "RS256",
    "subject_type": "public"
  }
}
EOF
)

CREATE_RESP="$(curl -sS -c "$JAR" -b "$JAR" \
    -H 'Content-Type: application/json' \
    -d "$CREATE_BODY" \
    "$CONSOLE_BASE/apps")"

# Existing app → look it up + rotate secret instead
if printf '%s' "$CREATE_RESP" | grep -q '"code":40901'; then
    log "app exists; will not regenerate — use console to rotate secret manually."
    exit 0
fi

CLIENT_ID="$(printf '%s' "$CREATE_RESP" | sed -nE 's/.*"client_id":"([^"]+)".*/\1/p')"
CLIENT_SECRET="$(printf '%s' "$CREATE_RESP" | sed -nE 's/.*"client_secret":"([^"]+)".*/\1/p')"

if [ -z "$CLIENT_ID" ] || [ -z "$CLIENT_SECRET" ]; then
    die "could not parse client credentials from response: $CREATE_RESP"
fi

cat <<EOF

==================== OIDC TEST APP READY ====================
Issuer        : http://localhost:10050
Discovery     : http://localhost:10050/protocol/oidc/.well-known/openid-configuration
JWKS          : http://localhost:10050/protocol/oidc/jwks
Client ID     : $CLIENT_ID
Client Secret : $CLIENT_SECRET   (shown ONLY once — save it)
Redirect URI  : $REDIRECT_URI

Sample login user (any seeded user works; admin/admin123 by default).

Try the curl flow:    tools/test-rp-curl/run.sh
Try the Go RP:        cd tools/test-rp-go && ISSUER=http://localhost:10050 \\
                          CLIENT_ID='$CLIENT_ID' CLIENT_SECRET='$CLIENT_SECRET' \\
                          REDIRECT_URI='$REDIRECT_URI' go run .
=============================================================
EOF
