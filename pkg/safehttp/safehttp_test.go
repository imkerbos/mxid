package safehttp

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestIsDisallowedIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		blocked bool
	}{
		// Public — allowed.
		{"google dns v4", "8.8.8.8", false},
		{"cloudflare dns v4", "1.1.1.1", false},
		{"public v6", "2606:4700:4700::1111", false},
		{"routable v4", "93.184.216.34", false},

		// Cloud metadata endpoint — the canonical SSRF target.
		{"aws metadata", "169.254.169.254", true},

		// Loopback.
		{"loopback v4", "127.0.0.1", true},
		{"loopback v4 high", "127.255.255.255", true},
		{"loopback v6", "::1", true},

		// Unspecified.
		{"unspecified v4", "0.0.0.0", true},
		{"unspecified v6", "::", true},

		// Private RFC1918.
		{"private 10/8", "10.0.0.0", true},
		{"private 10/8 host", "10.1.2.3", true},
		{"private 172.16/12", "172.16.5.4", true},
		{"private 192.168/16", "192.168.1.1", true},

		// Link-local unicast.
		{"link-local v4", "169.254.1.1", true},
		{"link-local v6", "fe80::1", true},

		// Unique-local IPv6 fc00::/7.
		{"ula fc00", "fc00::1", true},
		{"ula fd00", "fd12:3456:789a::1", true},

		// Multicast.
		{"multicast v4", "224.0.0.1", true},
		{"multicast v4 high", "239.255.255.255", true},
		{"multicast v6", "ff00::1", true},
		{"link-local multicast v6", "ff02::1", true},

		// IPv4-mapped IPv6 must be unwrapped and re-checked.
		{"mapped loopback", "::ffff:127.0.0.1", true},
		{"mapped private", "::ffff:10.0.0.1", true},
		{"mapped public", "::ffff:8.8.8.8", false},

		// Carrier-grade NAT (RFC 6598) — k8s/cloud internal infra.
		{"cgnat 100.64", "100.64.0.1", true},
		{"cgnat 100.127", "100.127.255.255", true},
		{"cgnat boundary public 100.128", "100.128.0.1", false},

		// Reserved / benchmark / broadcast.
		{"reserved 240/4", "240.0.0.1", true},
		{"broadcast", "255.255.255.255", true},
		{"benchmark 198.18", "198.18.0.1", true},
		{"proto-assign 192.0.0", "192.0.0.171", true},

		// IPv6 transition forms embedding internal v4.
		{"6to4 embeds private 10", "2002:0a00:0001::1", true},
		{"6to4 embeds loopback", "2002:7f00:0001::1", true},
		{"nat64 embeds private 10", "64:ff9b::a00:1", true},
		{"nat64 embeds public 8.8.8.8", "64:ff9b::808:808", true},
		{"6to4 prefix wholesale", "2002:5db8:d822::1", true},

		// Documentation range.
		{"doc 2001:db8", "2001:db8::1", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("ParseIP(%q) returned nil — bad test input", tc.ip)
			}
			if got := isDisallowedIP(ip); got != tc.blocked {
				t.Errorf("isDisallowedIP(%s) = %v, want %v", tc.ip, got, tc.blocked)
			}
		})
	}
}

func TestIsDisallowedIPNilFailsClosed(t *testing.T) {
	if !isDisallowedIP(nil) {
		t.Fatal("nil IP must be treated as disallowed (fail closed)")
	}
}

func TestGuardDial(t *testing.T) {
	tests := []struct {
		name    string
		address string
		wantErr error // nil means allowed
	}{
		{"public host:port allowed", "8.8.8.8:443", nil},
		{"public v6 allowed", "[2606:4700:4700::1111]:443", nil},
		{"loopback blocked", "127.0.0.1:443", ErrDisallowedAddress},
		{"metadata blocked", "169.254.169.254:80", ErrDisallowedAddress},
		{"private blocked", "10.0.0.5:443", ErrDisallowedAddress},
		{"ula blocked", "[fc00::1]:443", ErrDisallowedAddress},
		{"unspecified blocked", "0.0.0.0:443", ErrDisallowedAddress},
		{"missing port fails closed", "8.8.8.8", ErrDisallowedAddress},
		{"non-ip host fails closed", "evil.example.com:443", ErrDisallowedAddress},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := guardDial("tcp", tc.address)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("guardDial(%q) = %v, want nil", tc.address, err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("guardDial(%q) = %v, want errors.Is %v", tc.address, err, tc.wantErr)
			}
		})
	}
}

func TestSchemeAllowed(t *testing.T) {
	tests := []struct {
		scheme    string
		allowHTTP bool
		want      bool
	}{
		{"https", false, true},
		{"https", true, true},
		{"http", false, false},
		{"http", true, true},
		{"ftp", true, false},
		{"file", true, false},
		{"gopher", true, false},
		{"", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.scheme+"_allowHTTP="+boolStr(tc.allowHTTP), func(t *testing.T) {
			if got := schemeAllowed(tc.scheme, tc.allowHTTP); got != tc.want {
				t.Errorf("schemeAllowed(%q, %v) = %v, want %v", tc.scheme, tc.allowHTTP, got, tc.want)
			}
		})
	}
}

func TestCheckRedirect(t *testing.T) {
	mustReq := func(rawURL string) *http.Request {
		u, err := url.Parse(rawURL)
		if err != nil {
			t.Fatalf("parse %q: %v", rawURL, err)
		}
		return &http.Request{URL: u}
	}

	tests := []struct {
		name         string
		maxRedirects int
		allowHTTP    bool
		req          *http.Request
		viaLen       int
		wantErr      error // nil means follow
	}{
		{
			name:         "https within cap follows",
			maxRedirects: 5,
			req:          mustReq("https://example.com/a"),
			viaLen:       2,
			wantErr:      nil,
		},
		{
			name:         "at cap stops",
			maxRedirects: 5,
			req:          mustReq("https://example.com/a"),
			viaLen:       5,
			wantErr:      ErrTooManyRedirects,
		},
		{
			name:         "over cap stops",
			maxRedirects: 3,
			req:          mustReq("https://example.com/a"),
			viaLen:       7,
			wantErr:      ErrTooManyRedirects,
		},
		{
			name:         "zero cap blocks first redirect",
			maxRedirects: 0,
			req:          mustReq("https://example.com/a"),
			viaLen:       0,
			wantErr:      ErrTooManyRedirects,
		},
		{
			name:         "http redirect blocked by default",
			maxRedirects: 5,
			allowHTTP:    false,
			req:          mustReq("http://example.com/a"),
			viaLen:       1,
			wantErr:      ErrDisallowedScheme,
		},
		{
			name:         "http redirect allowed when opted in",
			maxRedirects: 5,
			allowHTTP:    true,
			req:          mustReq("http://example.com/a"),
			viaLen:       1,
			wantErr:      nil,
		},
		{
			name:         "downgrade to file scheme blocked",
			maxRedirects: 5,
			allowHTTP:    true,
			req:          mustReq("file:///etc/passwd"),
			viaLen:       1,
			wantErr:      ErrDisallowedScheme,
		},
		{
			name:         "count cap checked before scheme",
			maxRedirects: 2,
			allowHTTP:    false,
			req:          mustReq("http://example.com/a"), // would be a scheme error, but cap hits first
			viaLen:       2,
			wantErr:      ErrTooManyRedirects,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := checkRedirect(tc.maxRedirects, tc.allowHTTP)
			via := make([]*http.Request, tc.viaLen)
			err := policy(tc.req, via)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("checkRedirect = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("checkRedirect = %v, want errors.Is %v", err, tc.wantErr)
			}
		})
	}
}

func TestNewAppliesOptions(t *testing.T) {
	c := New(WithTimeout(3*time.Second), WithMaxRedirects(2), AllowHTTP())
	hc := c.HTTPClient()
	if hc.Timeout != 3*time.Second {
		t.Errorf("timeout = %v, want 3s", hc.Timeout)
	}
	if hc.CheckRedirect == nil {
		t.Fatal("CheckRedirect must be set")
	}
	tr, ok := hc.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", hc.Transport)
	}
	if tr.DialContext == nil {
		t.Fatal("transport must use a guarded DialContext")
	}
	if tr.Proxy != nil {
		t.Error("transport must not honour an environment proxy")
	}
}

func TestNewDefaults(t *testing.T) {
	c := New()
	hc := c.HTTPClient()
	if hc.Timeout != DefaultTimeout {
		t.Errorf("default timeout = %v, want %v", hc.Timeout, DefaultTimeout)
	}
	// http rejected by default at the redirect policy.
	policy := hc.CheckRedirect
	u, _ := url.Parse("http://example.com")
	if err := policy(&http.Request{URL: u}, nil); !errors.Is(err, ErrDisallowedScheme) {
		t.Errorf("default policy on http = %v, want ErrDisallowedScheme", err)
	}
}

// TestNegativeAndZeroOptions verifies option guards: non-positive timeout and
// negative redirect cap are ignored; a zero redirect cap is honoured.
func TestNegativeAndZeroOptions(t *testing.T) {
	c := New(WithTimeout(-1), WithMaxRedirects(-5))
	hc := c.HTTPClient()
	if hc.Timeout != DefaultTimeout {
		t.Errorf("negative timeout should keep default, got %v", hc.Timeout)
	}
	// negative max redirects ignored -> default of 5 applies; a redirect at
	// via len 4 should still follow.
	u, _ := url.Parse("https://example.com")
	if err := hc.CheckRedirect(&http.Request{URL: u}, make([]*http.Request, 4)); err != nil {
		t.Errorf("with default cap, 5th redirect should follow, got %v", err)
	}

	c0 := New(WithMaxRedirects(0))
	if err := c0.HTTPClient().CheckRedirect(&http.Request{URL: u}, nil); !errors.Is(err, ErrTooManyRedirects) {
		t.Errorf("zero cap should block first redirect, got %v", err)
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
