package dberr

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

func TestIsNotFound(t *testing.T) {
	if !IsNotFound(gorm.ErrRecordNotFound) {
		t.Error("direct gorm.ErrRecordNotFound should be not-found")
	}
	if !IsNotFound(fmt.Errorf("get user: %w", gorm.ErrRecordNotFound)) {
		t.Error("wrapped gorm.ErrRecordNotFound should be not-found")
	}
	if IsNotFound(errors.New("some other error")) {
		t.Error("unrelated error must not be not-found")
	}
	if IsNotFound(nil) {
		t.Error("nil must not be not-found")
	}
}

func TestIsUniqueViolation(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "23505", Message: "duplicate key value violates unique constraint"}
	if !IsUniqueViolation(pgErr) {
		t.Error("pg 23505 should be a unique violation")
	}
	if !IsUniqueViolation(fmt.Errorf("insert: %w", pgErr)) {
		t.Error("wrapped pg 23505 should be a unique violation")
	}

	otherPGErr := &pgconn.PgError{Code: "23503", Message: "foreign key violation"}
	if IsUniqueViolation(otherPGErr) {
		t.Error("pg foreign-key violation must not be a unique violation")
	}

	sqliteErr := errors.New("UNIQUE constraint failed: mxid_oidc_keyset.kid")
	if !IsUniqueViolation(sqliteErr) {
		t.Error("sqlite UNIQUE constraint message should be a unique violation")
	}

	if IsUniqueViolation(errors.New("some other error")) {
		t.Error("unrelated error must not be a unique violation")
	}
	if IsUniqueViolation(nil) {
		t.Error("nil must not be a unique violation")
	}
}
