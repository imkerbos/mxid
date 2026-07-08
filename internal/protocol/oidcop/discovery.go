package oidcop

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// discoveryHiddenResponseTypes / discoveryHiddenGrantTypes are the OAuth 2.1
// implicit-flow values that zitadel/oidc v3.47.5's discovery handler
// advertises unconditionally: pkg/op/discovery.go's ResponseTypes() and
// GrantTypes() helpers hardcode "id_token" / "id_token token" / "implicit"
// into every discovery document with no Storage/Config hook to suppress them
// (confirmed by reading the vendored source, and empirically — a live
// provider with none of our clients configured for implicit still emits
// them). WS6-B drops implicit per the migration decision (code+PKCE only;
// hybrid deferred, not built — see client.go's oidcClient.ResponseTypes(),
// which never advertises anything else per-client). filterDiscoveryResponse
// makes the provider-wide discovery document match that real behavior
// instead of the library's stale hardcoded defaults.
var (
	discoveryHiddenResponseTypes = map[string]bool{
		string(oidc.ResponseTypeIDTokenOnly): true, // "id_token"
		string(oidc.ResponseTypeIDToken):     true, // "id_token token"
	}
	discoveryHiddenGrantTypes = map[string]bool{
		string(oidc.GrantTypeImplicit): true,
	}
)

// filterDiscoveryResponse wraps inner and, only for requests to the OIDC
// discovery endpoint, strips implicit-flow entries from
// response_types_supported and grant_types_supported before the body reaches
// the caller. Every other request/response passes through untouched (no
// buffering, no overhead) — this never touches the hand-rolled engine's own
// /protocol/oidc/.well-known surface, only the zitadel-mounted subtree.
func filterDiscoveryResponse(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != oidc.DiscoveryEndpoint {
			inner.ServeHTTP(w, r)
			return
		}

		rec := &discoveryRecorder{header: make(http.Header), status: http.StatusOK}
		inner.ServeHTTP(rec, r)

		body := rec.body.Bytes()
		filtered, ok := filterDiscoveryBody(body)
		for k, vv := range rec.header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		if ok {
			w.Header().Set("Content-Length", strconv.Itoa(len(filtered)))
			body = filtered
		}
		w.WriteHeader(rec.status)
		_, _ = w.Write(body)
	})
}

// filterDiscoveryBody strips the hidden implicit values from the two
// well-known-array fields of a discovery JSON document. Returns ok=false
// (leaving the caller to forward the original body unmodified) when the body
// is not the JSON object shape discovery always returns — e.g. an upstream
// error response — so a malformed/unexpected body is never mangled.
func filterDiscoveryBody(body []byte) (out []byte, ok bool) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, false
	}
	if raw, present := doc["response_types_supported"]; present {
		doc["response_types_supported"] = filterJSONStringArray(raw, discoveryHiddenResponseTypes)
	}
	if raw, present := doc["grant_types_supported"]; present {
		doc["grant_types_supported"] = filterJSONStringArray(raw, discoveryHiddenGrantTypes)
	}
	filtered, err := json.Marshal(doc)
	if err != nil {
		return nil, false
	}
	return filtered, true
}

// filterJSONStringArray drops any hidden entries from a JSON string-array
// field, returning raw unmodified if it isn't a string array (defensive —
// never worth failing the whole discovery response over one unexpected
// field shape).
func filterJSONStringArray(raw json.RawMessage, hidden map[string]bool) json.RawMessage {
	var items []string
	if err := json.Unmarshal(raw, &items); err != nil {
		return raw
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		if !hidden[it] {
			out = append(out, it)
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return raw
	}
	return b
}

// discoveryRecorder is a minimal http.ResponseWriter that buffers the
// response so filterDiscoveryResponse can rewrite it before it reaches the
// real client — equivalent to httptest.ResponseRecorder but kept local so
// production code does not import net/http/httptest.
type discoveryRecorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *discoveryRecorder) Header() http.Header         { return r.header }
func (r *discoveryRecorder) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *discoveryRecorder) WriteHeader(code int)        { r.status = code }
