package dberr

import "strings"

// LikeEscapeChar is the escape character every LIKE/ILIKE pattern built by
// EscapeLike expects. Postgres defaults to backslash, but the default is not
// guaranteed across settings, so queries state `ESCAPE '\'` explicitly.
const LikeEscapeChar = `\`

// EscapeLike neutralizes LIKE's own metacharacters in a value that came from a
// user and is meant to be matched literally.
//
// A placeholder stops SQL injection; it does NOT stop `%` and `_` from being
// read as wildcards, and that difference is easy to miss because the query
// looks parameterized and safe. It bit this codebase in two places:
//
//   - Console search: typing "%" returned every row, and "_" matched any single
//     character, so searching for a code containing a literal underscore gave
//     back the whole table.
//   - Dynamic-group rules: a rule value containing "%" widened the match, so a
//     group meant for one team silently enrolled people outside it. Membership
//     drives app access, which makes that an authorization question, not a
//     cosmetic one.
//
// Callers must pair this with an explicit ESCAPE clause:
//
//	q.Where(`name ILIKE @kw ESCAPE '\'`, map[string]any{"kw": "%" + dberr.EscapeLike(s) + "%"})
//
// The escape character itself is escaped first — otherwise a trailing
// backslash in the input would escape the wildcard this function just added.
func EscapeLike(s string) string {
	r := strings.NewReplacer(
		LikeEscapeChar, LikeEscapeChar+LikeEscapeChar,
		"%", LikeEscapeChar+"%",
		"_", LikeEscapeChar+"_",
	)
	return r.Replace(s)
}
