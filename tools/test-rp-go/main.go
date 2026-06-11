// test-rp-go — minimal OIDC relying party for end-to-end MXID validation.
//
// Brings up a local HTTP server that completes the Authorization Code flow
// against the MXID IdP, then renders the resulting claim set in the browser.
// Intentionally short — every line maps to a step a real RP would do.
//
// Run:
//
//	ISSUER=http://localhost:10050 \
//	CLIENT_ID=client_xxx \
//	CLIENT_SECRET=yyy \
//	REDIRECT_URI=http://localhost:8090/callback \
//	go run .
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	ctx := context.Background()

	issuer := env("ISSUER", "http://localhost:10050")
	clientID := env("CLIENT_ID", "")
	clientSecret := env("CLIENT_SECRET", "")
	redirectURI := env("REDIRECT_URI", "http://localhost:8090/callback")
	listenAddr := env("LISTEN_ADDR", ":8090")

	if clientID == "" || clientSecret == "" {
		log.Fatal("CLIENT_ID and CLIENT_SECRET env vars are required")
	}

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Fatalf("discover provider: %v", err)
	}

	cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, cfg.AuthCodeURL("state-"+os.Getenv("USER")), http.StatusFound)
	})

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code: "+r.URL.RawQuery, http.StatusBadRequest)
			return
		}
		tok, err := cfg.Exchange(ctx, code)
		if err != nil {
			http.Error(w, fmt.Sprintf("exchange: %v", err), http.StatusBadGateway)
			return
		}
		rawID, _ := tok.Extra("id_token").(string)
		idTok, err := verifier.Verify(ctx, rawID)
		if err != nil {
			http.Error(w, fmt.Sprintf("verify id_token: %v", err), http.StatusBadGateway)
			return
		}
		var claims map[string]any
		_ = idTok.Claims(&claims)
		userinfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(tok))
		if err != nil {
			http.Error(w, fmt.Sprintf("userinfo: %v", err), http.StatusBadGateway)
			return
		}
		var userinfoClaims map[string]any
		_ = userinfo.Claims(&userinfoClaims)
		out := map[string]any{
			"access_token":     tok.AccessToken,
			"refresh_token":    tok.RefreshToken,
			"id_token":         rawID,
			"id_token_claims":  claims,
			"userinfo":         userinfoClaims,
			"token_expires_at": tok.Expiry,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})

	log.Printf("listening on %s — open http://localhost%s/ to start the flow", listenAddr, listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
