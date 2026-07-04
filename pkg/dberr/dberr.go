// Package dberr abstracts persistence-layer error sentinels so service and
// gateway code can test for conditions like "row not found" without importing
// the ORM directly. This keeps gorm an implementation detail of the repository
// layer (dependency inversion): if the ORM is ever swapped, only this package
// changes instead of every service that pattern-matched gorm.ErrRecordNotFound.
package dberr

import (
	"errors"

	"gorm.io/gorm"
)

// IsNotFound reports whether err (or anything it wraps) is the "no row matched"
// error a repository read returns when the record is absent.
func IsNotFound(err error) bool {
	return errors.Is(err, gorm.ErrRecordNotFound)
}
