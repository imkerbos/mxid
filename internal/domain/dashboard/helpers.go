package dashboard

import "strconv"

// statusActive mirrors user.StatusActive (1). Duplicated as a local const so
// the reporting module doesn't import the user domain just for one integer.
const statusActive = 1

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
