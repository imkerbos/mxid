package cas

import "testing"

// TestIsValidServiceFailClosed locks down the CAS `service` open-redirect /
// service-ticket-leak fix (sink cas-login-service, cas-logout-service). The
// pre-fix behaviour fell back to a shape-only check that accepted ANY https
// host when ServiceURLs was empty; these cases assert the validator is now
// fail-closed and exact-host bound.
func TestIsValidServiceFailClosed(t *testing.T) {
	h := &Handler{}

	cases := []struct {
		name        string
		serviceURLs []string
		service     string
		want        bool
	}{
		// --- FAIL-CLOSED: empty allow-list must reject everything ---
		{name: "empty allowlist rejects https host (documented exploit)", serviceURLs: nil, service: "https://evil.com/", want: false},
		{name: "empty allowlist rejects even plausible host", serviceURLs: nil, service: "https://app.example.com/cas", want: false},
		{name: "empty allowlist rejects loopback", serviceURLs: nil, service: "http://localhost:8080/cb", want: false},

		// --- non-empty allow-list: exact host/scheme bound ---
		{name: "exact registered service accepted", serviceURLs: []string{"https://app.example.com/cas"}, service: "https://app.example.com/cas", want: true},
		{name: "registered prefix path accepted (CAS convention)", serviceURLs: []string{"https://app.example.com/cas"}, service: "https://app.example.com/cas/login", want: true},
		{name: "registered root covers subpaths", serviceURLs: []string{"https://app.example.com/"}, service: "https://app.example.com/anything", want: true},

		// --- open-redirect / smuggling attempts rejected ---
		{name: "foreign host rejected", serviceURLs: []string{"https://app.example.com/cas"}, service: "https://evil.com/", want: false},
		{name: "host suffix attack rejected", serviceURLs: []string{"https://app.example.com/cas"}, service: "https://app.example.com.evil.com/cas", want: false},
		{name: "scheme downgrade rejected", serviceURLs: []string{"https://app.example.com/cas"}, service: "http://app.example.com/cas", want: false},
		{name: "userinfo smuggle rejected", serviceURLs: []string{"https://app.example.com/cas"}, service: "https://app.example.com@evil.com/cas", want: false},
		{name: "javascript scheme rejected", serviceURLs: []string{"https://app.example.com/cas"}, service: "javascript:alert(1)", want: false},
		{name: "relative (non-absolute) rejected", serviceURLs: []string{"https://app.example.com/cas"}, service: "/cas", want: false},
		{name: "partial path prefix not a path-segment boundary rejected", serviceURLs: []string{"https://app.example.com/cas"}, service: "https://app.example.com/cas-evil", want: false},
		{name: "host case-insensitive still matches", serviceURLs: []string{"https://app.example.com/cas"}, service: "https://APP.example.com/cas", want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &CASConfig{ServiceURLs: tc.serviceURLs}
			got := h.isValidService(cfg, tc.service)
			if got != tc.want {
				t.Fatalf("isValidService(%q) with allowlist %v = %v, want %v",
					tc.service, tc.serviceURLs, got, tc.want)
			}
		})
	}
}
