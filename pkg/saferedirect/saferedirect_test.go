package saferedirect

import (
	"errors"
	"testing"
)

func TestValidateRelativeOrOrigin(t *testing.T) {
	allowed := []string{
		"https://app.example.com",
		"https://app.example.com:8443",
		"http://localhost:3000",
	}

	tests := []struct {
		name        string
		target      string
		allowed     []string
		wantSafe    string
		wantErr     error
		wantErrKind bool // when true, only require err != nil (any error)
	}{
		// --- valid relative paths ---
		{name: "valid relative simple", target: "/apps", allowed: allowed, wantSafe: "/apps"},
		{name: "valid relative with query", target: "/orgs?id=1&x=2", allowed: allowed, wantSafe: "/orgs?id=1&x=2"},
		{name: "valid relative root", target: "/", allowed: allowed, wantSafe: "/"},
		{name: "valid relative with fragment", target: "/page#section", allowed: allowed, wantSafe: "/page#section"},
		{name: "valid relative deep", target: "/a/b/c", allowed: allowed, wantSafe: "/a/b/c"},

		// --- valid absolute, allowed origin ---
		{name: "valid allowed origin", target: "https://app.example.com/dashboard", allowed: allowed, wantSafe: "https://app.example.com/dashboard"},
		{name: "valid allowed origin root", target: "https://app.example.com", allowed: allowed, wantSafe: "https://app.example.com"},
		{name: "valid allowed origin with query", target: "https://app.example.com/x?y=1", allowed: allowed, wantSafe: "https://app.example.com/x?y=1"},
		{name: "valid allowed origin host case-insensitive", target: "https://APP.example.com/x", allowed: allowed, wantSafe: "https://APP.example.com/x"},
		{name: "valid allowed origin explicit default port", target: "https://app.example.com:443/x", allowed: allowed, wantSafe: "https://app.example.com:443/x"},
		{name: "valid allowed non-default port", target: "https://app.example.com:8443/x", allowed: allowed, wantSafe: "https://app.example.com:8443/x"},
		{name: "valid allowed localhost http", target: "http://localhost:3000/cb", allowed: allowed, wantSafe: "http://localhost:3000/cb"},

		// --- open-redirect / smuggling attempts ---
		{name: "protocol-relative //evil", target: "//evil.com", allowed: allowed, wantErr: ErrBadRelative},
		{name: "protocol-relative //evil path", target: "//evil.com/x", allowed: allowed, wantErr: ErrBadRelative},
		{name: "backslash /\\evil", target: "/\\evil.com", allowed: allowed, wantErr: ErrBadRelative},
		{name: "backslash leading \\evil", target: "\\evil.com", allowed: allowed, wantErr: ErrBadRelative},
		{name: "backslash mid path", target: "/foo\\bar", allowed: allowed, wantErr: ErrBadRelative},
		{name: "https evil not allowed", target: "https://evil.com/x", allowed: allowed, wantErr: ErrOriginNotAllowed},
		{name: "javascript scheme", target: "javascript:alert(1)", allowed: allowed, wantErrKind: true},
		{name: "data scheme", target: "data:text/html,<script>", allowed: allowed, wantErrKind: true},
		{name: "userinfo smuggle", target: "http://user@evil.com/", allowed: allowed, wantErr: ErrUserInfo},
		{name: "userpass smuggle against allowed host", target: "https://app.example.com@evil.com/", allowed: allowed, wantErr: ErrUserInfo},
		{name: "port mismatch", target: "https://app.example.com:9999/x", allowed: allowed, wantErr: ErrOriginNotAllowed},
		{name: "scheme mismatch http vs https", target: "http://app.example.com/x", allowed: allowed, wantErr: ErrOriginNotAllowed},
		{name: "subdomain not allowed", target: "https://evil.app.example.com/x", allowed: allowed, wantErr: ErrOriginNotAllowed},

		// --- malformed / empty / control ---
		{name: "empty", target: "", allowed: allowed, wantErr: ErrEmpty},
		{name: "lone double slash", target: "//", allowed: allowed, wantErr: ErrBadRelative},
		{name: "CRLF injection", target: "/foo\r\nSet-Cookie: x", allowed: allowed, wantErr: ErrControlChars},
		{name: "tab control char", target: "/foo\tbar", allowed: allowed, wantErr: ErrControlChars},
		{name: "null byte", target: "/foo\x00bar", allowed: allowed, wantErr: ErrControlChars},
		{name: "not rooted relative", target: "apps", allowed: allowed, wantErr: ErrBadRelative},
		{name: "absolute missing host", target: "https://", allowed: allowed, wantErr: ErrNoHost},
		{name: "control char in scheme separator", target: "ht\x01tp://app.example.com", allowed: allowed, wantErr: ErrControlChars},

		// --- empty allow-list fails closed for absolute ---
		{name: "empty allowlist rejects absolute", target: "https://app.example.com/x", allowed: nil, wantErr: ErrOriginNotAllowed},
		{name: "empty allowlist still allows relative", target: "/apps", allowed: nil, wantSafe: "/apps"},

		// --- garbage allow-list entries are skipped, not crash ---
		{name: "garbage allowlist entry skipped", target: "https://app.example.com/x", allowed: []string{"::bad::", "", "https://app.example.com"}, wantSafe: "https://app.example.com/x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			safe, err := ValidateRelativeOrOrigin(tt.target, tt.allowed)

			if tt.wantErr == nil && !tt.wantErrKind {
				if err != nil {
					t.Fatalf("expected success, got err=%v", err)
				}
				if safe != tt.wantSafe {
					t.Fatalf("safe = %q, want %q", safe, tt.wantSafe)
				}
				return
			}

			// expecting an error
			if err == nil {
				t.Fatalf("expected error, got safe=%q nil err", safe)
			}
			if safe != "" {
				t.Fatalf("fail-closed violated: safe = %q, want empty on error", safe)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAgainstRegistered(t *testing.T) {
	registered := []string{
		"https://sp.example.com/acs",
		"https://sp.example.com/landing?tenant=acme",
		"https://cas.example.com/app/login",
	}

	tests := []struct {
		name       string
		target     string
		registered []string
		wantSafe   string
		wantErr    error
	}{
		// --- exact matches ---
		{name: "exact match", target: "https://sp.example.com/acs", registered: registered, wantSafe: "https://sp.example.com/acs"},
		{name: "exact match with query", target: "https://sp.example.com/landing?tenant=acme", registered: registered, wantSafe: "https://sp.example.com/landing?tenant=acme"},
		{name: "scheme case-insensitive", target: "HTTPS://sp.example.com/acs", registered: registered, wantSafe: "HTTPS://sp.example.com/acs"},
		{name: "host case-insensitive", target: "https://SP.example.com/acs", registered: registered, wantSafe: "https://SP.example.com/acs"},

		// --- prefix / suffix / drift must be rejected ---
		{name: "prefix only rejected", target: "https://sp.example.com/acs/extra", registered: registered, wantErr: ErrNotRegistered},
		{name: "path prefix of registered rejected", target: "https://sp.example.com/ac", registered: registered, wantErr: ErrNotRegistered},
		{name: "extra query rejected", target: "https://sp.example.com/acs?evil=1", registered: registered, wantErr: ErrNotRegistered},
		{name: "missing query rejected", target: "https://sp.example.com/landing", registered: registered, wantErr: ErrNotRegistered},
		{name: "different query value rejected", target: "https://sp.example.com/landing?tenant=evil", registered: registered, wantErr: ErrNotRegistered},
		{name: "host suffix attack rejected", target: "https://sp.example.com.evil.com/acs", registered: registered, wantErr: ErrNotRegistered},
		{name: "scheme downgrade rejected", target: "http://sp.example.com/acs", registered: registered, wantErr: ErrNotRegistered},
		{name: "trailing slash differs", target: "https://sp.example.com/acs/", registered: registered, wantErr: ErrNotRegistered},
		{name: "port added rejected", target: "https://sp.example.com:8443/acs", registered: registered, wantErr: ErrNotRegistered},

		// --- smuggling ---
		{name: "userinfo rejected", target: "https://user:pass@sp.example.com/acs", registered: registered, wantErr: ErrUserInfo},

		// --- fail-closed ---
		{name: "empty target", target: "", registered: registered, wantErr: ErrEmpty},
		{name: "empty registry", target: "https://sp.example.com/acs", registered: nil, wantErr: ErrNotRegistered},
		{name: "control chars", target: "https://sp.example.com/acs\r\n", registered: registered, wantErr: ErrControlChars},
		{name: "all-garbage registry skipped", target: "https://sp.example.com/acs", registered: []string{"::bad::", ""}, wantErr: ErrNotRegistered},
		{name: "garbage entry then match", target: "https://sp.example.com/acs", registered: []string{"::bad::", "https://sp.example.com/acs"}, wantSafe: "https://sp.example.com/acs"},
		{name: "javascript target rejected", target: "javascript:alert(1)", registered: registered, wantErr: ErrNotRegistered},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			safe, err := ValidateAgainstRegistered(tt.target, tt.registered)

			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("expected success, got err=%v", err)
				}
				if safe != tt.wantSafe {
					t.Fatalf("safe = %q, want %q", safe, tt.wantSafe)
				}
				return
			}

			if err == nil {
				t.Fatalf("expected error, got safe=%q nil err", safe)
			}
			if safe != "" {
				t.Fatalf("fail-closed violated: safe = %q, want empty on error", safe)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
