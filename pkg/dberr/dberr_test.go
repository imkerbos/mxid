package dberr

import (
	"errors"
	"fmt"
	"testing"

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
