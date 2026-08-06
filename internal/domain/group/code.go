package group

import (
	"errors"
	"fmt"
	"regexp"
)

// ErrInvalidGroupCode rejects a group code that downstream systems cannot use.
var ErrInvalidGroupCode = errors.New("invalid user group code")

// groupCodePattern is what a group code may look like: lowercase letters,
// digits, hyphen and underscore, starting with a letter or digit.
//
// The code is not an internal label. It is what travels in the OIDC `groups`
// claim and the SAML group attribute, and downstream systems match on it
// verbatim — Harbor maps a claim value to a project role, GitLab to a group.
// So the character set has to be one those systems, and the transports in
// between, all agree on.
//
// It was previously unvalidated, and the console happily accepted a code with
// spaces, one in Chinese, and `<script>alert(1)</script>`. None of those are
// caught later either: the code is immutable after creation, so the only repair
// is to delete the group and re-grant everything that referenced it.
var groupCodePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// ValidateGroupCode checks a code against groupCodePattern.
//
// Deliberately not applied to existing rows: it runs on create only. Any code
// already stored keeps working — a stricter rule must not turn a running
// deployment's groups into ones the API refuses to serve.
func ValidateGroupCode(code string) error {
	if groupCodePattern.MatchString(code) {
		return nil
	}
	return fmt.Errorf(
		"%w: use lowercase letters, digits, hyphen or underscore, starting with a letter or digit (got %q)",
		ErrInvalidGroupCode, code,
	)
}
