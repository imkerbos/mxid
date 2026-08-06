package app

import (
	"strings"
	"testing"
	"unicode"

	"github.com/imkerbos/mxid/internal/domain/setting"
)

// -generate exists so an operator recovering a locked-out install does not have
// to invent a password that satisfies whatever policy that deployment
// configured. If the generated one can fail validation, the flag is a trap:
// the command reports a policy error at the exact moment nobody can sign in.
func TestGeneratePasswordSatisfiesTheStrictestPolicy(t *testing.T) {
	for range 200 {
		pw, err := generatePassword()
		if err != nil {
			t.Fatalf("generatePassword: %v", err)
		}

		var upper, lower, digit, special bool
		for _, r := range pw {
			switch {
			case unicode.IsUpper(r):
				upper = true
			case unicode.IsLower(r):
				lower = true
			case unicode.IsDigit(r):
				digit = true
			default:
				special = true
			}
		}
		if !upper || !lower || !digit || !special {
			t.Fatalf("generated %q missing a class: upper=%v lower=%v digit=%v special=%v",
				pw, upper, lower, digit, special)
		}

		// The product's own default policy is the floor every deployment starts
		// from; a deployment can only tighten MinLength, and 24 leaves room.
		if min := setting.DefaultSecurityPolicy().Password.MinLength; len(pw) < min {
			t.Fatalf("generated %q is %d chars, below the default policy minimum %d",
				pw, len(pw), min)
		}
	}
}

// The guaranteed one-per-class characters are appended before the fill, so
// without the shuffle every generated password would start with upper, lower,
// digit, special in that order — a fixed prefix pattern in a credential.
func TestGeneratePasswordDoesNotLeaveAFixedClassPrefix(t *testing.T) {
	firstFour := map[string]int{}
	for range 100 {
		pw, err := generatePassword()
		if err != nil {
			t.Fatalf("generatePassword: %v", err)
		}
		var shape strings.Builder
		for _, r := range pw[:4] {
			switch {
			case unicode.IsUpper(r):
				shape.WriteByte('U')
			case unicode.IsLower(r):
				shape.WriteByte('l')
			case unicode.IsDigit(r):
				shape.WriteByte('d')
			default:
				shape.WriteByte('s')
			}
		}
		firstFour[shape.String()]++
	}
	if len(firstFour) == 1 {
		for shape := range firstFour {
			t.Fatalf("every password starts with the same class pattern %q — not shuffled", shape)
		}
	}
}

// Prompting is the default, and it needs a TTY. Under `kubectl exec` without
// -it there is none, and the failure has to say so — a prompt that reads a
// truncated line off a pipe would set a password nobody knows.
func TestPromptPasswordRefusesWithoutATerminal(t *testing.T) {
	// `go test` runs with stdin detached, so this is the no-TTY case.
	if _, err := promptPassword(); err == nil {
		t.Fatal("promptPassword succeeded without a terminal")
	} else if !strings.Contains(err.Error(), "no terminal") {
		t.Errorf("want a message naming the missing terminal, got %v", err)
	}
}
