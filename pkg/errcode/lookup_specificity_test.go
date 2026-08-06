package errcode_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/imkerbos/mxid/pkg/errcode"
)

// A narrow sentinel that wraps a broad one must resolve to the narrow code,
// every time.
//
// Password policy is the live case: ErrPasswordTooShort wraps ErrWeakPassword,
// and both are bound. Before Lookup preferred the more specific match it
// returned whichever the map iteration reached first — so the same rejected
// password could answer 40004 ("weak password", server-worded) on one process
// start and 40025 ("at least N characters", SPA-worded) on the next. Nothing
// would fail; the wrong sentence would just appear intermittently, which is the
// worst way to find a bug.
//
// Registered here under private sentinels so the test does not depend on the
// user domain's numbering.
var (
	errBroadTest  = errors.New("test: broad umbrella")
	errNarrowTest = fmt.Errorf("%w: narrow case", errBroadTest)

	codeBroadTest  = errcode.Code{HTTP: 400, Num: 49001}
	codeNarrowTest = errcode.Code{HTTP: 400, Num: 49002}
)

func init() {
	errcode.Bind(errBroadTest, codeBroadTest)
	errcode.Bind(errNarrowTest, codeNarrowTest)
}

func TestLookupPrefersTheMoreSpecificSentinel(t *testing.T) {
	// Repeat: map iteration order varies per run, and a single pass can pick the
	// right answer by luck. This many iterations makes luck implausible.
	for i := range 200 {
		got, ok := errcode.Lookup(errNarrowTest)
		if !ok {
			t.Fatal("Lookup found no code for the narrow sentinel")
		}
		if got != codeNarrowTest {
			t.Fatalf("iteration %d: Lookup(narrow) = %+v, want %+v — the umbrella "+
				"binding won, so the caller gets the broad code and the SPA "+
				"prints the server's sentence instead of a localized one",
				i, got, codeNarrowTest)
		}
	}
}

func TestLookupStillResolvesTheUmbrellaAlone(t *testing.T) {
	// An error that is only the broad sentinel must still resolve — narrowing
	// must not have made the umbrella unreachable.
	got, ok := errcode.Lookup(errBroadTest)
	if !ok {
		t.Fatal("Lookup found no code for the umbrella sentinel")
	}
	if got != codeBroadTest {
		t.Fatalf("Lookup(broad) = %+v, want %+v", got, codeBroadTest)
	}
}

func TestLookupWalksWrappedChains(t *testing.T) {
	// The real callers wrap with context before returning.
	wrapped := fmt.Errorf("updating password: %w", errNarrowTest)
	got, ok := errcode.Lookup(wrapped)
	if !ok {
		t.Fatal("Lookup found no code through a wrapped chain")
	}
	if got != codeNarrowTest {
		t.Fatalf("Lookup(wrapped narrow) = %+v, want %+v", got, codeNarrowTest)
	}
}
