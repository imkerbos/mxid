package app

import (
	"encoding/json"
	"fmt"
	"strings"
)

// renderQuickstart returns a copy-pasteable integration sample for the given
// language. The returned snippet is plain text; the caller wraps it in JSON.
//
// Supported languages: curl, go, node, python.
//
// Templates intentionally inline the app's client_id / issuer / redirect_uri
// so the snippet works without manual edits — matching the Auth0 / Okta
// quickstart UX which is a primary integration on-ramp.
func renderQuickstart(lang string, a *App, host string, https bool) (string, error) {
	scheme := "https"
	if !https {
		scheme = "http"
	}
	issuer := fmt.Sprintf("%s://%s", scheme, host)
	clientID := strDeref(a.ClientID)

	redirectURI := firstRedirectURI(a.RedirectURIs)
	if redirectURI == "" {
		redirectURI = "http://localhost:8090/callback"
	}

	switch strings.ToLower(lang) {
	case "curl":
		return curlSample(issuer, clientID, redirectURI), nil
	case "go":
		return goSample(issuer, clientID, redirectURI), nil
	case "node", "nodejs", "js":
		return nodeSample(issuer, clientID, redirectURI), nil
	case "python", "py":
		return pythonSample(issuer, clientID, redirectURI), nil
	}
	return "", fmt.Errorf("unsupported language: %s", lang)
}

func strDeref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func firstRedirectURI(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var uris []string
	if err := json.Unmarshal(raw, &uris); err != nil {
		return ""
	}
	if len(uris) == 0 {
		return ""
	}
	return uris[0]
}

func curlSample(issuer, clientID, redirectURI string) string {
	return fmt.Sprintf(`# Step 1 — open in browser to obtain authorization code (PKCE)
#   ${issuer}/protocol/oidc/authorize?response_type=code&client_id=${clientID}
#     &redirect_uri=${redirectURI}&scope=openid%%20profile%%20email&state=xyz
#
# Step 2 — exchange code for tokens
curl -X POST '%s/protocol/oidc/token' \
  -u 'CLIENT_ID:CLIENT_SECRET' \
  -d 'grant_type=authorization_code' \
  -d 'code=CODE_FROM_STEP_1' \
  -d 'redirect_uri=%s'

# Step 3 — fetch user info
curl '%s/protocol/oidc/userinfo' \
  -H 'Authorization: Bearer ACCESS_TOKEN_FROM_STEP_2'

# Replace CLIENT_ID with: %s
# CLIENT_SECRET was shown once at app creation; rotate via console if lost.
`, issuer, redirectURI, issuer, clientID)
}

func goSample(issuer, clientID, redirectURI string) string {
	return fmt.Sprintf(`package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func main() {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, %q)
	if err != nil {
		log.Fatal(err)
	}

	cfg := oauth2.Config{
		ClientID:     %q,
		ClientSecret: "CLIENT_SECRET", // value shown once on create
		RedirectURL:  %q,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, cfg.AuthCodeURL("state"), http.StatusFound)
	})
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		token, err := cfg.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		idTok := token.Extra("id_token").(string)
		fmt.Fprintf(w, "id_token: %%s\nuserinfo via %%s/protocol/oidc/userinfo", idTok, %q)
	})
	log.Fatal(http.ListenAndServe(":8090", nil))
}
`, issuer, clientID, redirectURI, issuer)
}

func nodeSample(issuer, clientID, redirectURI string) string {
	return fmt.Sprintf(`// npm i express openid-client
const express = require('express')
const { Issuer, generators } = require('openid-client')

async function main () {
  const issuer = await Issuer.discover(%q)
  const client = new issuer.Client({
    client_id: %q,
    client_secret: 'CLIENT_SECRET', // shown once at create
    redirect_uris: [%q],
    response_types: ['code'],
  })

  const app = express()
  app.get('/', (req, res) => {
    const code_verifier = generators.codeVerifier()
    req.session = { code_verifier }
    res.redirect(client.authorizationUrl({
      scope: 'openid profile email',
      code_challenge: generators.codeChallenge(code_verifier),
      code_challenge_method: 'S256',
    }))
  })
  app.get('/callback', async (req, res) => {
    const params = client.callbackParams(req)
    const tokenSet = await client.callback(%q, params, { code_verifier: req.session.code_verifier })
    const userinfo = await client.userinfo(tokenSet.access_token)
    res.json({ tokenSet, userinfo })
  })
  app.listen(8090)
}
main()
`, issuer, clientID, redirectURI, redirectURI)
}

func pythonSample(issuer, clientID, redirectURI string) string {
	return fmt.Sprintf(`# pip install authlib flask
from flask import Flask, redirect, request, session
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = "dev"

oauth = OAuth(app)
oauth.register(
    name="mxid",
    server_metadata_url="%s/protocol/oidc/.well-known/openid-configuration",
    client_id=%q,
    client_secret="CLIENT_SECRET",  # shown once at create
    client_kwargs={"scope": "openid profile email"},
)

@app.route("/")
def login():
    return oauth.mxid.authorize_redirect(%q)

@app.route("/callback")
def callback():
    token = oauth.mxid.authorize_access_token()
    return token

if __name__ == "__main__":
    app.run(port=8090)
`, issuer, clientID, redirectURI)
}
