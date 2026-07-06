// Package dberr abstracts persistence-layer error sentinels so service and
// gateway code can test for conditions like "row not found" without importing
// the ORM directly. This keeps gorm an implementation detail of the repository
// layer (dependency inversion): if the ORM is ever swapped, only this package
// changes instead of every service that pattern-matched gorm.ErrRecordNotFound.
package dberr

import (
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

// IsNotFound reports whether err (or anything it wraps) is the "no row matched"
// error a repository read returns when the record is absent.
func IsNotFound(err error) bool {
	return errors.Is(err, gorm.ErrRecordNotFound)
}

// IsUniqueViolation reports whether err (or anything it wraps) is a unique
// constraint violation from the underlying driver. Recognizes Postgres
// (pgconn.PgError code 23505) and sqlite (the glebarez/sqlite driver used in
// unit tests, whose error message contains "UNIQUE constraint failed"). Used
// to tolerate benign races such as two replicas concurrently minting the same
// singleton row: the loser reloads the winner's row instead of erroring.
func IsUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// IsUniqueViolationOn reports whether err is a unique violation raised by one of
// the named constraints/indexes (or, on sqlite, an error whose message mentions
// one of the names — e.g. the offending "table.column"). Use this instead of the
// broad IsUniqueViolation when a caller wants to swallow ONE specific constraint
// (e.g. a single-active-key index) without also masking an unrelated unique
// violation on the same table (e.g. a kid collision), which would hide a real bug.
// With no names it degenerates to IsUniqueViolation.
func IsUniqueViolationOn(err error, names ...string) bool {
	if !IsUniqueViolation(err) {
		return false
	}
	if len(names) == 0 {
		return true
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		for _, n := range names {
			if pgErr.ConstraintName == n {
				return true
			}
		}
		return false
	}
	msg := err.Error()
	for _, n := range names {
		if strings.Contains(msg, n) {
			return true
		}
	}
	return false
}
