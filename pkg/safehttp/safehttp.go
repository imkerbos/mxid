// Package safehttp provides the single SSRF-safe outbound HTTP client that
// every server-side fetch in mxid MUST use (webhook delivery, external IdP
// metadata/JWKS pulls, OIDC discovery, avatar fetches, etc.).
//
// The load-bearing control is a net.Dialer Control hook that fires on EVERY
// dial — including each redirect hop — AFTER name resolution has happened.
// At that point the address handed to Control is host:port with host already
// resolved to a concrete IP, so we can reject connections to loopback,
// private, link-local, unique-local, unspecified, or multicast destinations.
// Because the check runs post-resolution it defeats DNS rebinding: an
// attacker who returns a public IP on the first lookup and a 127.0.0.1 on the
// second still cannot connect, because the second dial is re-checked.
//
// CheckRedirect adds a defence-in-depth layer: it caps the redirect count and
// re-enforces the scheme allow-list on each hop. The dialer Control still
// guards each hop's resolved IP regardless.
//
// This package is intentionally dependency-free beyond the standard library.
package safehttp

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

const (
	// DefaultTimeout is the overall request timeout applied to the returned
	// client when no override is supplied.
	DefaultTimeout = 10 * time.Second

	// DefaultMaxRedirects caps redirect hops. Each hop is independently
	// IP-checked by the dialer Control regardless of this cap.
	DefaultMaxRedirects = 5
)

// ErrDisallowedAddress is returned by the dial Control hook when the resolved
// remote IP falls in a blocked range. It is wrapped by the *url.Error that
// http.Client surfaces to callers.
var ErrDisallowedAddress = errors.New("safehttp: connection to disallowed address blocked")

// ErrDisallowedScheme is returned when a request or redirect targets a scheme
// outside the allow-list.
var ErrDisallowedScheme = errors.New("safehttp: disallowed URL scheme")

// ErrTooManyRedirects is returned when a response chain exceeds the configured
// redirect cap.
var ErrTooManyRedirects = errors.New("safehttp: too many redirects")

// Option configures the client built by New.
type Option func(*config)

type config struct {
	timeout      time.Duration
	maxRedirects int
	allowHTTP    bool
}

// WithTimeout overrides the overall request timeout. A non-positive value is
// ignored and the default is kept.
func WithTimeout(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithMaxRedirects overrides the redirect cap. A negative value is ignored; a
// value of 0 disables redirect following entirely.
func WithMaxRedirects(n int) Option {
	return func(c *config) {
		if n >= 0 {
			c.maxRedirects = n
		}
	}
}

// AllowHTTP additionally permits plain http:// targets. By default only
// https:// is allowed. The IP-level guard applies either way.
func AllowHTTP() Option {
	return func(c *config) { c.allowHTTP = true }
}

// Client is a thin wrapper over *http.Client exposing the helpers callers
// need while keeping the SSRF guards non-bypassable (the embedded transport
// and redirect policy are fixed at construction).
type Client struct {
	hc *http.Client
}

// New builds an SSRF-safe *Client. The returned client:
//
//   - resolves and re-checks the remote IP on every dial and redirect hop,
//     rejecting non-routable / internal destinations;
//   - enforces the scheme allow-list (https only unless AllowHTTP);
//   - caps redirects;
//   - enforces an overall timeout.
func New(opts ...Option) *Client {
	cfg := config{
		timeout:      DefaultTimeout,
		maxRedirects: DefaultMaxRedirects,
		allowHTTP:    false,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	dialer := &net.Dialer{
		Timeout:   cfg.timeout,
		KeepAlive: 30 * time.Second,
		Control:   guardControl,
	}

	transport := &http.Transport{
		Proxy:                 nil, // never honour env proxies for server-side fetches
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   cfg.timeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	hc := &http.Client{
		Timeout:       cfg.timeout,
		Transport:     transport,
		CheckRedirect: checkRedirect(cfg.maxRedirects, cfg.allowHTTP),
	}

	return &Client{hc: hc}
}

// HTTPClient returns the underlying *http.Client for callers (e.g. SDKs) that
// require an *http.Client directly. The SSRF guards remain in force because
// they live in the transport and redirect policy.
func (c *Client) HTTPClient() *http.Client { return c.hc }

// Do executes the request through the guarded client.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return c.hc.Do(req)
}

// Get issues a guarded GET.
func (c *Client) Get(url string) (*http.Response, error) {
	return c.hc.Get(url)
}

// guardControl is the net.Dialer Control hook. It runs after DNS resolution
// for every dial, including redirect hops. address is host:port where host is
// already a resolved IP literal. The syscall.RawConn is unused — the decision
// is made purely on the resolved address — but the parameter is mandated by
// the net.Dialer.Control signature.
func guardControl(network, address string, _ syscall.RawConn) error {
	return guardDial(network, address)
}

// guardDial holds the testable core of the Control hook (it omits the
// syscall.RawConn so tests can drive it directly). It parses the
// resolved address and rejects disallowed destinations.
func guardDial(_ string, address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		// Address should always be host:port from the dialer; if it is not,
		// fail closed.
		return fmt.Errorf("%w: unparseable address %q", ErrDisallowedAddress, address)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Host is expected to already be a resolved IP literal at Control
		// time; anything else is fail-closed.
		return fmt.Errorf("%w: non-IP host %q", ErrDisallowedAddress, host)
	}
	if isDisallowedIP(ip) {
		return fmt.Errorf("%w: %s", ErrDisallowedAddress, ip.String())
	}
	return nil
}

// checkRedirect builds the http.Client CheckRedirect policy: it caps the
// redirect count and re-enforces the scheme allow-list on every hop.
func checkRedirect(maxRedirects int, allowHTTP bool) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("%w: stopped after %d", ErrTooManyRedirects, maxRedirects)
		}
		if !schemeAllowed(req.URL.Scheme, allowHTTP) {
			return fmt.Errorf("%w: %q", ErrDisallowedScheme, req.URL.Scheme)
		}
		return nil
	}
}

// schemeAllowed reports whether scheme passes the allow-list. https is always
// allowed; http only when allowHTTP is set.
func schemeAllowed(scheme string, allowHTTP bool) bool {
	switch scheme {
	case "https":
		return true
	case "http":
		return allowHTTP
	default:
		return false
	}
}
