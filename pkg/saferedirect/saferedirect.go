// Package saferedirect provides FAIL-CLOSED validators for the non-OIDC
// redirect sinks in the platform: post-login return_to, SAML RelayState,
// CAS service URLs, and consent return_to. These sinks all feed into an
// HTTP redirect (or an auto-submitting form) at the end of a flow, so an
// unvalidated value is an open-redirect / token-leak primitive.
//
// Two validators are offered, each for a different trust model:
//
//   - ValidateRelativeOrOrigin: for return_to-style values that the user
//     agent supplies. Accepts a same-origin relative path OR an absolute
//     URL whose origin (scheme+host+port) exactly matches a configured
//     allow-list. Used for post-login return_to and consent return_to,
//     where the legitimate destination is "back into our own app".
//
//   - ValidateAgainstRegistered: for values bound to a pre-registered
//     service provider (CAS `service`, SAML RelayState that carries an
//     ACS/landing URL). Requires an exact full-URL match against the SP's
//     registered list, mirroring the OIDC redirect_uri exact-match rules
//     (see internal/protocol/oidc/redirect.go).
//
// Both validators fail closed: empty, unparseable, or unmatched input
// returns an error and the safe string is "". Callers MUST treat any
// error as "do not redirect" and render a local page instead. There is
// deliberately no permissive fallback (no "default to /", no "strip the
// host and keep the path") because such fallbacks have historically been
// the bug, not the feature.
package saferedirect

import (
	"errors"
	"net/url"
	"strings"
)

// Errors returned by the validators. Callers that want to log the precise
// reason can switch on these; user-facing surfaces should map them all to
// a single generic message to avoid oracle-ing the allow-list to attackers.
var (
	// ErrEmpty is returned when the target is the empty string.
	ErrEmpty = errors.New("saferedirect: empty target")
	// ErrMalformed is returned when the target cannot be parsed as a URL.
	ErrMalformed = errors.New("saferedirect: malformed target")
	// ErrControlChars is returned when the target contains control
	// characters (incl. CR/LF/TAB/NUL) that enable header-injection or
	// parser-confusion tricks.
	ErrControlChars = errors.New("saferedirect: control characters in target")
	// ErrBadRelative is returned when a relative path is not a safe
	// single-slash-rooted path (e.g. "//host", "/\\host", missing leading
	// slash, or it carries a scheme/host).
	ErrBadRelative = errors.New("saferedirect: unsafe relative path")
	// ErrScheme is returned when an absolute URL uses a non-http(s) scheme
	// (javascript:, data:, file:, custom app schemes, ...).
	ErrScheme = errors.New("saferedirect: disallowed scheme")
	// ErrUserInfo is returned when an absolute URL carries a userinfo
	// component (user:pass@host) — a classic origin-confusion smuggle.
	ErrUserInfo = errors.New("saferedirect: userinfo not allowed")
	// ErrNoHost is returned when an absolute URL has no host.
	ErrNoHost = errors.New("saferedirect: missing host")
	// ErrOriginNotAllowed is returned when an absolute URL's origin does
	// not exactly match any entry in the allowed-origins list.
	ErrOriginNotAllowed = errors.New("saferedirect: origin not allowed")
	// ErrNotRegistered is returned when a target does not exactly match
	// any registered URI.
	ErrNotRegistered = errors.New("saferedirect: target not registered")
)

// ValidateRelativeOrOrigin validates a user-agent-supplied return target.
//
// It accepts EITHER:
//
//   - a relative path rooted at a single "/" (e.g. "/apps", "/orgs?id=1").
//     The leading slash must be a single slash: "//evil.com" (protocol-
//     relative) and "/\evil.com" (backslash-as-slash) are rejected because
//     browsers resolve them to a foreign origin. The path must not carry a
//     scheme or host of its own.
//
//   - an absolute URL whose origin (scheme + host + port, case-insensitive
//     host) exactly equals one of allowedOrigins. The scheme must be http
//     or https; userinfo (user:pass@) is rejected; a host is required.
//
// On success it returns the validated target unchanged (so the caller can
// redirect to exactly what was checked) and a nil error. On any failure it
// returns ("", err) — the caller must NOT redirect.
//
// allowedOrigins entries are themselves parsed for their origin; a trailing
// path/query/fragment on an allow-list entry is ignored (only the origin is
// compared). An unparseable or hostless allow-list entry is skipped.
func ValidateRelativeOrOrigin(target string, allowedOrigins []string) (string, error) {
	if target == "" {
		return "", ErrEmpty
	}
	if hasControlChars(target) {
		return "", ErrControlChars
	}

	// Reject the canonical open-redirect shapes BEFORE url.Parse so they
	// always surface as ErrBadRelative rather than leaking into the
	// absolute-origin branch. A raw "//" prefix is a protocol-relative URL
	// (foreign origin); a leading backslash is normalised to a slash by
	// browsers ("/\evil" -> "//evil", "\evil" -> "/evil" or worse).
	if strings.HasPrefix(target, "//") || strings.HasPrefix(target, "/\\") ||
		strings.HasPrefix(target, "\\") {
		return "", ErrBadRelative
	}

	u, err := url.Parse(target)
	if err != nil {
		return "", ErrMalformed
	}

	// Relative target: no scheme and no host on the parsed URL. We still
	// inspect the RAW string for "//" and "/\\" because url.Parse treats
	// "//evil.com" as a host-bearing (scheme-relative) URL — but defense in
	// depth: reject on the raw prefix too.
	if u.Scheme == "" && u.Host == "" && u.Opaque == "" {
		if !isSafeRelativePath(target) {
			return "", ErrBadRelative
		}
		return target, nil
	}

	// Otherwise it must be a well-formed absolute http(s) URL whose origin
	// matches the allow-list.
	if err := validateAbsoluteOrigin(u, allowedOrigins); err != nil {
		return "", err
	}
	return target, nil
}

// ValidateAgainstRegistered validates a target that is bound to a
// pre-registered service provider by requiring an EXACT full-URL match
// against registeredURIs.
//
// Match semantics mirror the OIDC redirect_uri rules in
// internal/protocol/oidc/redirect.go: scheme (case-insensitive) + host
// (case-insensitive) + path must be equal; userinfo on the target is
// rejected. Unlike the OIDC validator, query strings here MUST also match
// exactly, because CAS `service` and SAML RelayState landing URLs are not
// expected to carry per-request state the way an OAuth callback does, and
// allowing query drift would weaken the binding. Prefix / wildcard /
// suffix matching is intentionally NOT supported.
//
// Returns (target, nil) on an exact match, ("", err) otherwise. Fail-closed:
// an empty target or empty/all-unparseable registry yields an error.
func ValidateAgainstRegistered(target string, registeredURIs []string) (string, error) {
	if target == "" {
		return "", ErrEmpty
	}
	if hasControlChars(target) {
		return "", ErrControlChars
	}

	reqURL, err := url.Parse(target)
	if err != nil {
		return "", ErrMalformed
	}
	if reqURL.User != nil {
		return "", ErrUserInfo
	}

	for _, raw := range registeredURIs {
		if raw == "" {
			continue
		}
		regURL, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if exactURLMatch(regURL, reqURL) {
			return target, nil
		}
	}
	return "", ErrNotRegistered
}

// isSafeRelativePath reports whether raw is a path-only target rooted at a
// single slash. It rejects protocol-relative ("//x"), backslash-smuggling
// ("/\\x", "\\x"), and any value not starting with exactly one "/".
func isSafeRelativePath(raw string) bool {
	// Must start with a single forward slash.
	if len(raw) == 0 || raw[0] != '/' {
		return false
	}
	// "//..." is protocol-relative -> foreign origin.
	if len(raw) >= 2 && raw[1] == '/' {
		return false
	}
	// "/\..." — browsers normalise backslash to slash, so "/\evil.com"
	// becomes "//evil.com". Reject any backslash anywhere in the path; a
	// legitimate in-app path never needs one.
	if strings.Contains(raw, "\\") {
		return false
	}
	return true
}

// validateAbsoluteOrigin checks that u is an http(s) URL with a host, no
// userinfo, and an origin matching one of allowedOrigins.
func validateAbsoluteOrigin(u *url.URL, allowedOrigins []string) error {
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		// ok
	default:
		// Catches javascript:, data:, file:, vbscript:, mailto:, custom
		// app schemes, and "" (scheme-relative "//host" parses with an
		// empty scheme but a non-empty host, landing here).
		return ErrScheme
	}
	if u.User != nil {
		return ErrUserInfo
	}
	if u.Hostname() == "" {
		return ErrNoHost
	}

	for _, raw := range allowedOrigins {
		if raw == "" {
			continue
		}
		allowed, err := url.Parse(raw)
		if err != nil || allowed.Hostname() == "" {
			continue
		}
		if sameOrigin(allowed, u) {
			return nil
		}
	}
	return ErrOriginNotAllowed
}

// sameOrigin compares scheme + host + port. Host comparison is
// case-insensitive; the port is taken from url.URL.Port() so that an
// explicit default port (https://x:443) compares equal to an implicit one
// only when both omit it — to keep the rule strict and predictable we
// compare the normalised (scheme, hostname, port) triple, where an empty
// Port() means "scheme default".
func sameOrigin(a, b *url.URL) bool {
	if !strings.EqualFold(a.Scheme, b.Scheme) {
		return false
	}
	if !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	return defaultedPort(a) == defaultedPort(b)
}

// defaultedPort returns the explicit port, or the scheme's default when the
// URL omits it, so that "https://x" and "https://x:443" are treated as the
// same origin while "https://x:8443" is not.
func defaultedPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

// exactURLMatch mirrors oidc.matchRedirectURI but also pins the query
// string. scheme + host are compared case-insensitively; path and query
// are compared verbatim; userinfo on either side is disqualifying.
func exactURLMatch(registered, requested *url.URL) bool {
	if requested.User != nil || registered.User != nil {
		return false
	}
	return strings.EqualFold(registered.Scheme, requested.Scheme) &&
		strings.EqualFold(registered.Host, requested.Host) &&
		registered.Path == requested.Path &&
		registered.RawQuery == requested.RawQuery
}

// hasControlChars reports whether s contains any ASCII control character
// (0x00-0x1F or 0x7F), including CR, LF, TAB, and NUL. These are never
// legitimate in a redirect target and enable response-splitting / parser
// desync.
func hasControlChars(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}
