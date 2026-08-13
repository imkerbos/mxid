package saferedirect_test

import (
	"errors"
	"testing"

	"github.com/imkerbos/mxid/pkg/saferedirect"
)

// ValidateShape is the validator for a sink whose legitimate origins cannot be
// enumerated at the point of validation — the consent return_to, which points
// at a protocol-replay URL on an admin-editable issuer. It is deliberately
// weaker than ValidateRelativeOrOrigin: it rejects what is hostile regardless
// of origin, and nothing else.

func TestValidateShape_RejectsHostileShapes(t *testing.T) {
	for name, target := range map[string]string{
		"empty":                  "",
		"javascript scheme":      "javascript:alert(1)",
		"data scheme":            "data:text/html,<script>alert(1)</script>",
		"file scheme":            "file:///etc/passwd",
		"protocol-relative":      "//evil.example/path",
		"backslash smuggle":      "/\\evil.example",
		"leading backslash":      "\\evil.example",
		"userinfo confusion":     "https://trusted.example@evil.example/",
		"carriage return":        "/path\r\nSet-Cookie: a=b",
		"newline":                "/path\nX-Injected: 1",
		"null byte":              "/path\x00",
		"relative without slash": "evil.example/path",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := saferedirect.ValidateShape(target)
			if err == nil {
				t.Fatalf("accepted %q; this value reaches the browser as a navigation target "+
					"carrying a freshly minted confirmation token", target)
			}
			if got != "" {
				t.Fatalf("a rejected target must return the empty string, got %q", got)
			}
		})
	}
}

func TestValidateShape_AcceptsWhatTheFlowActuallySends(t *testing.T) {
	// The real values: a protocol-replay URL on the issuer, and the relative
	// form used when portal and issuer share an origin.
	for name, target := range map[string]string{
		"absolute issuer URL": "https://id.example.com/protocol/oidc/authorize?authRequestID=abc",
		"absolute with port":  "https://id.example.com:8443/protocol/saml/resume?id=1",
		"plain http issuer":   "http://id.example.com/protocol/cas/login?service=x",
		"relative path":       "/protocol/oidc/authorize?authRequestID=abc",
		"relative with hash":  "/apps#recent",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := saferedirect.ValidateShape(target)
			if err != nil {
				t.Fatalf("rejected %q (%v); this is a legitimate destination and refusing it "+
					"breaks the login it was meant to complete", target, err)
			}
			if got != target {
				t.Fatalf("returned %q, want the target unchanged (%q)", got, target)
			}
		})
	}
}

// TestValidateShape_DoesNotPretendToCheckOrigin states the limit out loud: a
// caller that needs off-site rejection must use ValidateRelativeOrOrigin.
func TestValidateShape_DoesNotPretendToCheckOrigin(t *testing.T) {
	got, err := saferedirect.ValidateShape("https://attacker.example/steal")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == "" {
		t.Fatal("expected the off-site URL to pass the shape check")
	}

	// ...and the stronger validator is the one that stops it.
	if _, err := saferedirect.ValidateRelativeOrOrigin(
		"https://attacker.example/steal", []string{"https://id.example.com"},
	); !errors.Is(err, saferedirect.ErrOriginNotAllowed) {
		t.Fatalf("ValidateRelativeOrOrigin should reject an off-list origin, got %v", err)
	}
}
