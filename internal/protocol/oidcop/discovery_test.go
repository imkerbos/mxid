package oidcop

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
)

// TestOIDCClient_ResponseTypes_OnlyCode proves the per-client fail-closed
// guarantee (WS6-B): even when an app's stored protocol_config lists
// implicit response types (a pre-migration record, or a stray admin edit),
// the resolved op.Client never advertises anything but "code" — so op's own
// ValidateAuthReqResponseType rejects any implicit request regardless of what
// is on record.
func TestOIDCClient_ResponseTypes_OnlyCode(t *testing.T) {
	app := &resolver.AppConfig{
		ID: 1, ClientID: "legacy-client", ClientType: "web_app", Protocol: "oidc", Status: 1,
		ProtocolConfig: json.RawMessage(`{"response_types":["code","id_token","id_token token"]}`),
	}
	store := NewClientStore(&fixedAppResolver{app: app}, func(string) string { return "" })

	client, err := store.ClientByID(context.Background(), "legacy-client")
	if err != nil {
		t.Fatalf("ClientByID: %v", err)
	}
	got := client.ResponseTypes()
	if len(got) != 1 || got[0] != oidc.ResponseTypeCode {
		t.Fatalf("ResponseTypes() = %v, want exactly [code]", got)
	}
}

// TestValidateAuthReqResponseType_ImplicitRejected proves an authorize
// request for an implicit response_type is rejected at op's own request
// validation (op.ValidateAuthReqResponseType), the function the real
// /authorize handler calls, using a client resolved the same way the live
// engine would.
func TestValidateAuthReqResponseType_ImplicitRejected(t *testing.T) {
	app := &resolver.AppConfig{
		ID: 1, ClientID: "c1", ClientType: "web_app", Protocol: "oidc", Status: 1,
	}
	store := NewClientStore(&fixedAppResolver{app: app}, func(string) string { return "" })
	client, err := store.ClientByID(context.Background(), "c1")
	if err != nil {
		t.Fatalf("ClientByID: %v", err)
	}

	for _, rt := range []oidc.ResponseType{oidc.ResponseTypeIDTokenOnly, oidc.ResponseTypeIDToken} {
		if err := op.ValidateAuthReqResponseType(client, rt); err == nil {
			t.Errorf("ValidateAuthReqResponseType(%q) = nil, want an error (implicit must be rejected)", rt)
		}
	}
	// Sanity: the code flow must still be accepted.
	if err := op.ValidateAuthReqResponseType(client, oidc.ResponseTypeCode); err != nil {
		t.Errorf("ValidateAuthReqResponseType(code) = %v, want nil", err)
	}
}

// TestFilterDiscoveryResponse_StripsImplicit proves the discovery-response
// filter removes the implicit-flow entries that zitadel/oidc v3.47.5
// hardcodes into response_types_supported / grant_types_supported
// (pkg/op/discovery.go's ResponseTypes/GrantTypes helpers have no
// Storage/Config hook to suppress them — confirmed by reading the vendored
// source and probing a live provider, which emits
// ["code","id_token","id_token token"] / [...,"implicit",...]
// unconditionally). Every other discovery field must pass through
// untouched.
func TestFilterDiscoveryResponse_StripsImplicit(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"issuer": "https://issuer.example.com",
			"response_types_supported": ["code", "id_token", "id_token token"],
			"grant_types_supported": ["authorization_code", "implicit", "refresh_token"],
			"scopes_supported": ["openid", "profile"]
		}`))
	})
	wrapped := filterDiscoveryResponse(inner)

	req := httptest.NewRequest(http.MethodGet, oidc.DiscoveryEndpoint, nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode filtered body: %v (body: %s)", err, rec.Body.String())
	}
	rts, _ := doc["response_types_supported"].([]any)
	for _, v := range rts {
		if v == "id_token" || v == "id_token token" {
			t.Errorf("response_types_supported still contains implicit value %v: %v", v, rts)
		}
	}
	if len(rts) != 1 || rts[0] != "code" {
		t.Errorf("response_types_supported = %v, want [\"code\"]", rts)
	}
	gts, _ := doc["grant_types_supported"].([]any)
	for _, v := range gts {
		if v == "implicit" {
			t.Errorf("grant_types_supported still contains \"implicit\": %v", gts)
		}
	}
	if doc["issuer"] != "https://issuer.example.com" {
		t.Errorf("issuer = %v, unrelated field must pass through untouched", doc["issuer"])
	}
	if scopes, _ := doc["scopes_supported"].([]any); len(scopes) != 2 {
		t.Errorf("scopes_supported = %v, unrelated array field must pass through untouched", scopes)
	}
}

// TestFilterDiscoveryResponse_OtherPathsPassThrough proves the filter only
// touches the discovery endpoint — every other route (e.g. /token) is
// forwarded byte-for-byte.
func TestFilterDiscoveryResponse_OtherPathsPassThrough(t *testing.T) {
	const body = `{"access_token":"abc","response_types_supported":["id_token"]}`
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
	wrapped := filterDiscoveryResponse(inner)

	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Body.String() != body {
		t.Fatalf("body = %q, want unmodified passthrough %q", rec.Body.String(), body)
	}
}

// TestMount_DiscoveryEndpoint_HidesImplicit is an integration-level proof
// that provider.go's Mount wires the discovery filter for the real mounted
// path (issuer-prefixed, through gin) — not just as a bare http.Handler in
// isolation.
func TestMount_DiscoveryEndpoint_HidesImplicit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"response_types_supported":["code","id_token","id_token token"],"grant_types_supported":["authorization_code","implicit"]}`))
	})

	engine := gin.New()
	group := engine.Group("/protocol")
	Mount(group, "/protocol/oidc", inner)

	req := httptest.NewRequest(http.MethodGet, "/protocol/oidc"+oidc.DiscoveryEndpoint, nil)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v (body: %s)", err, rec.Body.String())
	}
	rts, _ := doc["response_types_supported"].([]any)
	if len(rts) != 1 || rts[0] != "code" {
		t.Fatalf("response_types_supported = %v, want [\"code\"] through the real Mount path", rts)
	}
	gts, _ := doc["grant_types_supported"].([]any)
	for _, v := range gts {
		if v == "implicit" {
			t.Fatalf("grant_types_supported still contains implicit through Mount: %v", gts)
		}
	}
}

// A response may carry exactly one Access-Control-Allow-Origin. Two of them is
// not a merge a browser performs — it refuses the response outright, and the
// request fails before anything reads the body.
//
// filterDiscoveryResponse buffers discovery so it can strip implicit-flow
// entries, then replayed the buffered headers onto the real writer with Add.
// Anything the outer chain had already set stayed, and the recorder's copy was
// appended beside it: oidcop.CORS reflects the requesting origin on the real
// writer, the library's own CORS answered `*` on the recorder, and discovery
// went out with both. The SPs whose origins we deliberately allow were exactly
// the ones that broke; the endpoints without a recorder were unaffected, which
// is why this looked like a gateway problem for a day.
func TestFilterDiscoveryResponse_SingleAllowOriginHeader(t *testing.T) {
	// The inner handler stands in for the library's CORS writing onto the
	// recorder — the same thing rs/cors did when its options were non-nil.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"issuer":"https://issuer.example.com"}`))
	})
	wrapped := filterDiscoveryResponse(inner)

	req := httptest.NewRequest(http.MethodGet, oidc.DiscoveryEndpoint, nil)
	rec := httptest.NewRecorder()
	// The outer middleware's decision, made before the recorder exists.
	rec.Header().Set("Access-Control-Allow-Origin", "https://sp.example.com")

	wrapped.ServeHTTP(rec, req)

	got := rec.Result().Header.Values("Access-Control-Allow-Origin")
	if len(got) != 1 {
		t.Fatalf("Access-Control-Allow-Origin appears %d times (%v); a browser rejects any response carrying more than one", len(got), got)
	}
	if got[0] != "https://sp.example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want the outer middleware's value — a buffered replay must not overrule a decision made outside it", got[0])
	}
}

// The converse: a header the outer chain did NOT set must still come through,
// or buffering would silently drop whatever the inner handler sets.
func TestFilterDiscoveryResponse_ReplaysHeadersTheOuterChainDidNotSet(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"issuer":"https://issuer.example.com"}`))
	})
	wrapped := filterDiscoveryResponse(inner)

	req := httptest.NewRequest(http.MethodGet, oidc.DiscoveryEndpoint, nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if got := rec.Result().Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store — headers only the inner handler sets must survive the replay", got)
	}
	if got := rec.Result().Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
}
