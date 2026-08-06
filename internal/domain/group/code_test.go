package group

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The code travels in the OIDC `groups` claim and the SAML group attribute, and
// downstream systems match it verbatim. Every rejected case below was accepted
// before this validation existed — the console created the group, returned 201,
// and the breakage only appeared later, in a different product, with no way to
// repair it short of deleting the group (the code is immutable after create).
func TestValidateGroupCode(t *testing.T) {
	valid := []string{
		"engineering",
		"devops",
		"admins",
		"team-a",
		"team_a",
		"a",
		"9lives",
		"ops-2026_q1",
	}
	for _, c := range valid {
		if err := ValidateGroupCode(c); err != nil {
			t.Errorf("ValidateGroupCode(%q) = %v, want nil", c, err)
		}
	}

	invalid := []struct {
		code string
		why  string
	}{
		{"has space", "a space breaks claim parsing in several consumers"},
		{"研发组", "non-ASCII does not survive every attribute transport"},
		{"UPPER", "case is not preserved consistently by downstream matchers"},
		{"MixedCase", "same"},
		{"<script>alert(1)</script>", "reaches other systems' UIs verbatim"},
		{"-leading-hyphen", "must start with a letter or digit"},
		{"_leading_underscore", "must start with a letter or digit"},
		{"", "empty"},
		{"has.dot", "dot is a separator in several group syntaxes"},
		{"has/slash", "slash is a path separator downstream"},
		{"has:colon", "colon separates scheme/namespace downstream"},
		{"tab\there", "whitespace of any kind"},
	}
	for _, c := range invalid {
		err := ValidateGroupCode(c.code)
		if err == nil {
			t.Errorf("ValidateGroupCode(%q) = nil, want an error — %s", c.code, c.why)
			continue
		}
		if !errors.Is(err, ErrInvalidGroupCode) {
			t.Errorf("ValidateGroupCode(%q) error does not wrap ErrInvalidGroupCode: %v", c.code, err)
		}
		// The operator has to be told what to type instead, and see what they
		// typed — a bare "invalid code" leaves them guessing which character.
		// Compared in quoted form because that is how the message renders it,
		// and it is the more useful form: a tab shows up as \t rather than as
		// invisible whitespace the operator cannot see in the error either.
		if !strings.Contains(err.Error(), fmt.Sprintf("%q", c.code)) {
			t.Errorf("ValidateGroupCode(%q) message does not echo the input: %v", c.code, err)
		}
	}
}
