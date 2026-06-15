package oidc

// MED-C / MED-C2 regression guard.
//
// OIDC client-secret comparisons MUST be constant-time (subtle.ConstantTimeCompare,
// usually via the shared verifyClientSecret helper). A plain Go `==` / `!=` on a
// secret value short-circuits on the first differing byte and leaks the secret
// length/prefix via response timing. This guard scans every .go file in the
// oidc package and fails if it finds a direct (in)equality comparison against a
// client-secret value. Empty-string guards (`== ""`) are allowed; those compare
// against a constant, not the secret, and carry no timing signal.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// bannedSecretCompare matches `<x>ClientSecret ==/!= <y>` or
// `clientSecret ==/!= <y>` where the right-hand side is NOT the empty-string
// literal "". Case covered: app.ClientSecret == clientSecret, clientSecret != x.
var bannedSecretCompare = regexp.MustCompile(`(?i)(client_?secret)\s*(==|!=)\s*([^"\s][^\n]*|"[^"]+")`)

func TestClientSecretCompareIsConstantTime(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		if strings.HasSuffix(name, "_test.go") {
			continue // this guard references the banned pattern in its regex/comments
		}
		data, rErr := os.ReadFile(name)
		if rErr != nil {
			t.Fatalf("read %s: %v", name, rErr)
		}
		for i, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			m := bannedSecretCompare.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			// Allow comparisons against the empty-string literal: `== ""` /
			// `!= ""` are presence checks, not secret-value compares.
			rhs := strings.TrimSpace(m[3])
			if rhs == `""` || strings.HasPrefix(rhs, `"" `) || rhs == `"" &&` {
				continue
			}
			t.Errorf("%s:%d compares a client secret with %q (%q) — use subtle.ConstantTimeCompare "+
				"or the shared verifyClientSecret helper instead of Go ==/!=, which leaks the secret "+
				"length/prefix via timing.\n  %s", name, i+1, m[2], strings.TrimSpace(line), filepath.Base(name))
		}
	}
}
