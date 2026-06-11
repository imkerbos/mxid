// Package idstr converts between snowflake int64 IDs and their JSON-string
// wire form. The frontend serialises every large integer as a string (JS
// Number loses precision past 2^53), so API request DTOs that carry lists
// of IDs receive []string from clients and need to parse each entry into
// int64 before handing it to the service layer.
package idstr

import (
	"fmt"
	"strconv"
)

// ParseList converts a list of decimal-string IDs into int64s.
// Returns ErrInvalidID with the offending value on first parse failure.
func ParseList(in []string) ([]int64, error) {
	out := make([]int64, 0, len(in))
	for i, s := range in {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid id at index %d (%q): %w", i, s, err)
		}
		out = append(out, v)
	}
	return out, nil
}
