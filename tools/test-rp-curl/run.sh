#!/usr/bin/env bash
# run.sh — manual OIDC Authorization Code flow exerciser using nothing but curl.
#
# Walks through every step a relying party would perform against MXID's
# OIDC IdP. Designed to be readable, not automated — pause at each step,
# inspect the output, learn the protocol.
#
# Prereqs:
#   - mxid backend reachable at http://localhost:10050
#   - An OIDC app provisioned via scripts/seed-test-oidc.sh (or console UI)
#   - End-user has logged in at http://localhost:3501/login at least once
#     so that mxid_proto_sid cookie is set in the browser
#
# Usage:
#   CLIENT_ID=client_xxx CLIENT_SECRET=yyy ./run.sh

set -euo pipefail

ISSUER="${ISSUER:-http://localhost:10050}"
CLIENT_ID="${CLIENT_ID:?set CLIENT_ID env var (see seed-test-oidc.sh output)}"
CLIENT_SECRET="${CLIENT_SECRET:?set CLIENT_SECRET env var}"
REDIRECT_URI="${REDIRECT_URI:-http://localhost:8090/callback}"
SCOPE="${SCOPE:-openid profile email groups}"
STATE="state-$(date +%s)"

bold() { printf "\n\033[1m%s\033[0m\n" "$*"; }

# ---------------------------------------------------------------------------
bold "Step 1 — Discovery"
curl -fsS "$ISSUER/protocol/oidc/.well-known/openid-configuration" | head -30
echo

# ---------------------------------------------------------------------------
bold "Step 2 — JWKS"
curl -fsS "$ISSUER/protocol/oidc/jwks" | head -20
echo

# ---------------------------------------------------------------------------
bold "Step 3 — Build authorize URL (open in browser)"
AUTH_URL="$ISSUER/protocol/oidc/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$REDIRECT_URI")&scope=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$SCOPE")&state=$STATE"
echo "$AUTH_URL"
echo
echo "→ open the URL above in a browser that already has an active MXID portal session."
echo "→ on success the browser will hit $REDIRECT_URI?code=…&state=$STATE"
echo

read -r -p "Paste the code value here: " CODE
[ -n "$CODE" ] || { echo "no code provided" >&2; exit 1; }

# ---------------------------------------------------------------------------
bold "Step 4 — Exchange code for tokens"
TOKEN_RESP="$(curl -fsS -u "$CLIENT_ID:$CLIENT_SECRET" \
    -d "grant_type=authorization_code" \
    -d "code=$CODE" \
    -d "redirect_uri=$REDIRECT_URI" \
    "$ISSUER/protocol/oidc/token")"
echo "$TOKEN_RESP"
echo

ACCESS_TOKEN="$(printf '%s' "$TOKEN_RESP" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("access_token",""))')"
ID_TOKEN="$(printf '%s' "$TOKEN_RESP" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("id_token",""))')"
REFRESH_TOKEN="$(printf '%s' "$TOKEN_RESP" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("refresh_token",""))')"

[ -n "$ACCESS_TOKEN" ] || { echo "no access_token in response" >&2; exit 1; }

# ---------------------------------------------------------------------------
bold "Step 5 — Inspect id_token (header.payload, no signature verify here)"
if [ -n "$ID_TOKEN" ]; then
    HEADER_B64="${ID_TOKEN%%.*}"
    REST="${ID_TOKEN#*.}"
    PAYLOAD_B64="${REST%%.*}"
    pad() { case $((${#1} % 4)) in 0) printf '%s' "$1";; 2) printf '%s==' "$1";; 3) printf '%s=' "$1";; esac; }
    echo "header  : $(pad "$HEADER_B64" | base64 --decode 2>/dev/null || true)"
    echo "payload : $(pad "$PAYLOAD_B64" | base64 --decode 2>/dev/null || true)"
fi
echo

# ---------------------------------------------------------------------------
bold "Step 6 — Userinfo"
curl -fsS -H "Authorization: Bearer $ACCESS_TOKEN" "$ISSUER/protocol/oidc/userinfo"
echo

# ---------------------------------------------------------------------------
bold "Step 7 — Refresh (optional)"
if [ -n "$REFRESH_TOKEN" ]; then
    echo "refresh_token: $REFRESH_TOKEN"
    REFRESH_RESP="$(curl -fsS -u "$CLIENT_ID:$CLIENT_SECRET" \
        -d "grant_type=refresh_token" \
        -d "refresh_token=$REFRESH_TOKEN" \
        "$ISSUER/protocol/oidc/token")"
    echo "$REFRESH_RESP"
fi
echo

bold "Done. Save the access_token / refresh_token if you want to call userinfo again later."
