package oidc

import "strings"

// parseResponseType splits an OIDC response_type query string into a set of
// requested response components per OIDC Core 1.0 §3.
//
// Acceptable tokens: code, id_token, token. Order is significant in the
// spec only for the canonical name; the actual semantics are set-based, so
// we project to a set here for fast membership checks.
func parseResponseType(rt string) map[string]bool {
	out := map[string]bool{}
	for _, p := range strings.Fields(rt) {
		switch p {
		case "code", "id_token", "token":
			out[p] = true
		}
	}
	return out
}

// isResponseTypeSupported gates the parsed component set to the combinations
// MXID advertises in discovery (Auth Code, Implicit-id_token, Hybrid).
//
// `none` (zero supplied components) is rejected — at least one of
// code/id_token/token must be present.
func isResponseTypeSupported(parts map[string]bool) bool {
	if len(parts) == 0 {
		return false
	}
	// Implicit `token`-only (no id_token) was deprecated by OIDC Best Current
	// Practice. We support id_token / token id_token / code+combinations and
	// reject standalone `token`.
	if parts["token"] && !parts["code"] && !parts["id_token"] {
		return false
	}
	return true
}
