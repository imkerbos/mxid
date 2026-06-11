package oidc

import (
	"errors"
	"net/url"
	"strings"
)

// Errors returned by ValidateRedirectURI for callers that want to surface
// the precise reason. The OIDC handler maps them all to a generic
// "invalid_request" response to avoid oracle-ing client misconfigurations
// to attackers.
var (
	ErrRedirectURIEmpty       = errors.New("redirect_uri: empty")
	ErrRedirectURIMalformed   = errors.New("redirect_uri: malformed URL")
	ErrRedirectURIScheme      = errors.New("redirect_uri: insecure scheme")
	ErrRedirectURIFragment    = errors.New("redirect_uri: fragment forbidden")
	ErrRedirectURINotRelative = errors.New("redirect_uri: must be absolute")
	ErrRedirectURINotAllowed  = errors.New("redirect_uri: not registered")
)

// ValidateRedirectURI enforces the OIDC spec rules around redirect_uri
// against the application's registered list:
//
//   - MUST be an absolute URI (RFC 6749 §3.1.2)
//   - MUST NOT contain a fragment component (RFC 6749 §3.1.2)
//   - MUST use https, except http://localhost / http://127.0.0.1 for
//     development (loopback exemption per OAuth 2.1 §9.4 + RFC 8252 §7.3)
//   - MUST exactly match a registered URI on scheme + host + port + path.
//     Query strings MAY differ (some RPs append per-request state). No
//     wildcard / prefix / suffix matching is supported — see Google's
//     2014 covert-redirect incident for why.
//
// Returns nil on success; one of the sentinel errors above otherwise.
func ValidateRedirectURI(requested string, registered []string) error {
	if requested == "" {
		return ErrRedirectURIEmpty
	}

	requestedURL, err := url.Parse(requested)
	if err != nil {
		return ErrRedirectURIMalformed
	}
	if !requestedURL.IsAbs() {
		return ErrRedirectURINotRelative
	}
	if requestedURL.Fragment != "" || strings.Contains(requested, "#") {
		return ErrRedirectURIFragment
	}
	if !isAcceptableScheme(requestedURL) {
		return ErrRedirectURIScheme
	}

	for _, raw := range registered {
		regURL, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if matchRedirectURI(regURL, requestedURL) {
			return nil
		}
	}
	return ErrRedirectURINotAllowed
}

// isAcceptableScheme allows https universally, and http only for loopback
// addresses (localhost / 127.0.0.1 / ::1). Custom schemes (com.example.app:
// for mobile flows) are also accepted because OIDC native-app guidance
// (RFC 8252 §7.1) permits them — the exact-match rule below still pins
// down the value.
func isAcceptableScheme(u *url.URL) bool {
	switch u.Scheme {
	case "https":
		return true
	case "http":
		host := u.Hostname()
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	case "":
		return false
	}
	// Reserved schemes used to dodge the URL allow-list.
	switch u.Scheme {
	case "javascript", "data", "vbscript", "file":
		return false
	}
	// Custom application schemes (e.g. com.example.app) pass — the exact
	// match against the registered list is what actually gates them.
	return true
}

// matchRedirectURI compares scheme + host + port + path. Query strings may
// differ so RPs can append per-request state. Username/password components
// are required to be empty (defense against `https://user:pass@evil.com`-
// style smuggling tricks).
func matchRedirectURI(registered, requested *url.URL) bool {
	if requested.User != nil {
		return false
	}
	return strings.EqualFold(registered.Scheme, requested.Scheme) &&
		strings.EqualFold(registered.Host, requested.Host) &&
		registered.Path == requested.Path
}
