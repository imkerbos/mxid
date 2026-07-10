package app

import "testing"

func strp(s string) *string { return &s }

func TestNormalizeEnv(t *testing.T) {
	cases := []struct {
		name string
		in   *string
		want *string
	}{
		{"nil stays nil", nil, nil},
		{"empty collapses to nil", strp(""), nil},
		{"whitespace collapses to nil", strp("   "), nil},
		{"trims", strp("  prod  "), strp("prod")},
		{"lowercases", strp("PROD"), strp("prod")},
		{"mixed case custom", strp("Canary"), strp("canary")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := normalizeEnv(c.in)
			switch {
			case got == nil && c.want == nil:
				// ok
			case got == nil || c.want == nil:
				t.Fatalf("normalizeEnv(%v) = %v, want %v", deref(c.in), deref(got), deref(c.want))
			case *got != *c.want:
				t.Fatalf("normalizeEnv(%q) = %q, want %q", deref(c.in), *got, *c.want)
			}
		})
	}
}

func deref(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}
