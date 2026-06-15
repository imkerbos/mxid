package oidc

import (
	"errors"
	"testing"
)

func TestValidateRedirectURI(t *testing.T) {
	registered := []string{
		"https://app.example.com/cb",
		"http://localhost:3000/cb",
		"com.example.app:/oauth",
	}

	cases := []struct {
		name      string
		requested string
		wantErr   error
	}{
		{"empty", "", ErrRedirectURIEmpty},
		{"malformed", "://broken", ErrRedirectURIMalformed},
		{"relative", "/cb", ErrRedirectURINotRelative},
		{"fragment", "https://app.example.com/cb#x", ErrRedirectURIFragment},
		{"insecure scheme http non-loopback", "http://app.example.com/cb", ErrRedirectURIScheme},
		{"javascript scheme", "javascript:alert(1)", ErrRedirectURIScheme},
		{"data scheme", "data:text/html,evil", ErrRedirectURIScheme},
		{"unregistered host", "https://evil.example.com/cb", ErrRedirectURINotAllowed},
		{"unregistered path", "https://app.example.com/evil", ErrRedirectURINotAllowed},
		{"path traversal", "https://app.example.com/cb/../evil", ErrRedirectURINotAllowed},
		{"userinfo smuggling", "https://attacker@app.example.com/cb", ErrRedirectURINotAllowed},
		{"covert prefix", "https://app.example.com.evil.com/cb", ErrRedirectURINotAllowed},

		{"exact https", "https://app.example.com/cb", nil},
		{"exact https with query", "https://app.example.com/cb?state=x", nil},
		{"exact loopback http", "http://localhost:3000/cb", nil},
		{"loopback wrong port", "http://localhost:4000/cb", ErrRedirectURINotAllowed},
		{"native scheme exact", "com.example.app:/oauth", nil},
		{"case-insensitive scheme", "HTTPS://app.example.com/cb", nil},
		{"case-insensitive host", "https://APP.example.com/cb", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRedirectURI(tc.requested, registered)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("ValidateRedirectURI(%q) error = %v, want %v",
					tc.requested, err, tc.wantErr)
			}
		})
	}
}
