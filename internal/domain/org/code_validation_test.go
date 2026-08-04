package org

// An org code is concatenated straight into the organisation's ltree path, so
// Postgres rejects the whole INSERT for anything outside a valid ltree label.
// Unvalidated, that surfaced as a bare 500 with "ltree syntax error" in the
// server log and nothing actionable in the response.
//
// The case that actually bit was the hyphen — the console's own hint recommended
// "lowercase + hyphens" and offered "tech-team" as the worked example, so an
// admin following the interface exactly was guaranteed to hit it.

import "testing"

func TestOrgCodeAcceptsWhatLtreeAccepts(t *testing.T) {
	for _, code := range []string{
		"root", "engineering", "tech_team", "TeamA", "team2", "a", "_leading",
		"ALL_CAPS_9",
	} {
		if !orgCodeRe.MatchString(code) {
			t.Errorf("%q is a valid ltree label but was rejected", code)
		}
	}
}

func TestOrgCodeRejectsWhatLtreeRejects(t *testing.T) {
	cases := map[string]string{
		"tech-team":   "hyphen — the value the console's own hint used to recommend",
		"tech team":   "space",
		"tech.team":   "dot separates ltree labels; a code containing one forges a level",
		"tech/team":   "slash",
		"团队":          "non-ASCII",
		"":            "empty",
		"tech@team":   "at sign",
		"tech+team":   "plus",
		"tech:team":   "colon",
		"tech'team":   "quote",
		"tech;--team": "sql-ish punctuation",
	}
	for code, why := range cases {
		if orgCodeRe.MatchString(code) {
			t.Errorf("%q was accepted (%s); Postgres will reject the INSERT and the "+
				"admin gets a 500 with no explanation", code, why)
		}
	}
}

// The dot deserves its own note: it is legal *between* labels, so a code
// containing one would silently create an org whose path claims a depth it does
// not have — "a.b" under root becomes "root.a.b", indistinguishable from a real
// two-level subtree. Rejecting it keeps the path a faithful record of the tree.
func TestOrgCodeRejectsTheLtreeSeparator(t *testing.T) {
	if orgCodeRe.MatchString("a.b") {
		t.Fatal("a code containing a dot was accepted; it would forge a level in the ltree path")
	}
}
