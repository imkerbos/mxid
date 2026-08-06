package dberr_test

import (
	"testing"

	"github.com/imkerbos/mxid/pkg/dberr"
)

func TestEscapeLike(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain text untouched", "engineering", "engineering"},
		{"percent escaped", "50%", `50\%`},
		{"underscore escaped", "dept_code", `dept\_code`},
		{"both escaped", "a%b_c", `a\%b\_c`},
		// The escape character must be doubled FIRST. Escaping % and _ before
		// the backslash would let a trailing backslash in the input swallow the
		// escape this function just added.
		{"backslash doubled", `a\b`, `a\\b`},
		{"trailing backslash cannot eat the wildcard", `x\`, `x\\`},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := dberr.EscapeLike(c.in); got != c.want {
				t.Errorf("EscapeLike(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestEscapeLikeIsIdempotentlySafeForPatternBuilding(t *testing.T) {
	// The whole point is that the wildcards a CALLER adds stay wildcards while
	// the ones a USER typed do not.
	pattern := "%" + dberr.EscapeLike("100%") + "%"
	if pattern != `%100\%%` {
		t.Fatalf("pattern = %q, want %q — the caller's surrounding wildcards must "+
			"survive while the user's literal %% is escaped", pattern, `%100\%%`)
	}
}
