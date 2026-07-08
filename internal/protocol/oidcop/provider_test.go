package oidcop

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestWithIdpInitiatedContext_SetsFlagFromRawQuery proves the WS7 ctx-
// propagation mechanism at the http.Handler boundary: idp_initiated=1 on the
// raw request query sets idpInitiatedFromContext(r.Context()) for the wrapped
// handler, and its absence leaves the context untagged. This is the piece
// that must run BEFORE op's own request decoding
// (schema.NewDecoder().IgnoreUnknownKeys(true)), which silently drops
// idp_initiated as an unknown key — see provider.go for the full trace
// against the vendored zitadel/oidc source.
func TestWithIdpInitiatedContext_SetsFlagFromRawQuery(t *testing.T) {
	var got bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = idpInitiatedFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	wrapped := withIdpInitiated(inner)

	req := httptest.NewRequest(http.MethodGet, "/authorize?client_id=app1&idp_initiated=1", nil)
	wrapped.ServeHTTP(httptest.NewRecorder(), req)
	if !got {
		t.Fatalf("idpInitiatedFromContext = false, want true when idp_initiated=1 is present")
	}
}

// TestWithIdpInitiatedContext_AbsentByDefault proves an SP-initiated request
// (no idp_initiated param at all, or any value other than "1") leaves the
// context untagged — the default, safer state (require confirmation).
func TestWithIdpInitiatedContext_AbsentByDefault(t *testing.T) {
	cases := []string{
		"/authorize?client_id=app1",
		"/authorize?client_id=app1&idp_initiated=0",
		"/authorize?client_id=app1&idp_initiated=true",
	}
	for _, target := range cases {
		var got bool
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = idpInitiatedFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		})
		wrapped := withIdpInitiated(inner)

		req := httptest.NewRequest(http.MethodGet, target, nil)
		wrapped.ServeHTTP(httptest.NewRecorder(), req)
		if got {
			t.Errorf("target %q: idpInitiatedFromContext = true, want false", target)
		}
	}
}

// TestMount_PropagatesIdpInitiated_ThroughRealRouting is an integration-level
// proof that provider.go's Mount wires the idp_initiated context tag for the
// REAL mounted path — issuer-prefixed, through gin, and stacked underneath
// the discovery-response filter — not just as a bare http.Handler in
// isolation (TestWithIdpInitiatedContext_SetsFlagFromRawQuery above). This is
// the exact chain op.Authorize's ctx traverses in production: Mount ->
// http.StripPrefix -> filterDiscoveryResponse -> withIdpInitiated -> op's own
// mux -> op.Authorize(ctx=r.Context()) -> Storage.CreateAuthRequest(ctx, ...).
func TestMount_PropagatesIdpInitiated_ThroughRealRouting(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var got bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = idpInitiatedFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	engine := gin.New()
	group := engine.Group("/protocol")
	Mount(group, "/protocol/oidc", inner)

	req := httptest.NewRequest(http.MethodGet, "/protocol/oidc/authorize?client_id=app1&idp_initiated=1", nil)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	if !got {
		t.Fatalf("idpInitiatedFromContext = false through the real Mount path, want true")
	}
}

// TestMount_PropagatesIdpInitiated_AbsentForSPInitiated proves the same real
// Mount path leaves the flag unset for a plain SP-initiated authorize
// request (no idp_initiated param).
func TestMount_PropagatesIdpInitiated_AbsentForSPInitiated(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var got bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = idpInitiatedFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	engine := gin.New()
	group := engine.Group("/protocol")
	Mount(group, "/protocol/oidc", inner)

	req := httptest.NewRequest(http.MethodGet, "/protocol/oidc/authorize?client_id=app1", nil)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	if got {
		t.Fatalf("idpInitiatedFromContext = true through the real Mount path, want false (no idp_initiated param)")
	}
}
