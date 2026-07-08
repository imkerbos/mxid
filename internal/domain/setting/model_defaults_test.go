package setting

import "testing"

func TestDefaultSecurityPolicy_RateLimit(t *testing.T) {
	got := DefaultSecurityPolicy().RateLimit.PerUserPerMinute
	if got != 600 {
		t.Fatalf("DefaultSecurityPolicy().RateLimit.PerUserPerMinute = %d, want 600", got)
	}
}
