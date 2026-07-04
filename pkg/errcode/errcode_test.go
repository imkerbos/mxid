package errcode

import (
	"errors"
	"fmt"
	"testing"
)

func TestBindAndLookup(t *testing.T) {
	sentinel := errors.New("thing not found")
	code := Code{HTTP: 404, Num: 41234}
	Bind(sentinel, code)

	if got, ok := Lookup(sentinel); !ok || got != code {
		t.Fatalf("direct lookup: got %+v ok=%v, want %+v", got, ok, code)
	}
	// Resolves through a wrapping error (errors.Is via %w).
	if got, ok := Lookup(fmt.Errorf("service layer: %w", sentinel)); !ok || got != code {
		t.Fatalf("wrapped lookup: got %+v ok=%v, want %+v", got, ok, code)
	}
	if _, ok := Lookup(errors.New("unregistered")); ok {
		t.Errorf("unregistered error must not resolve")
	}
	if _, ok := Lookup(nil); ok {
		t.Errorf("nil must not resolve")
	}
}

func TestBindSameCodeIsIdempotent(t *testing.T) {
	s := errors.New("dup")
	c := Code{HTTP: 400, Num: 40001}
	Bind(s, c)
	Bind(s, c) // same code again — must not panic
}

func TestBindDifferentCodePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Errorf("re-binding a sentinel to a different code must panic")
		}
	}()
	s := errors.New("conflict")
	Bind(s, Code{HTTP: 400, Num: 1})
	Bind(s, Code{HTTP: 400, Num: 2})
}
