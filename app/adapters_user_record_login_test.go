package app

import (
	"context"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// The EE seam hands over a pointer, and a caller that builds the input
// conditionally can hand over nil. The adapter must drop it rather than
// dereference it: a nil here means "nothing to record", and a panic inside a
// login handler takes the sign-in down with it. Passing a nil recorder proves
// the guard returns before touching the delegate at all.
func TestRecordLoginAdapter_NilInputIsDropped(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked on a nil input: %v", r)
		}
	}()
	recordLoginAdapter(nil)(context.Background(), nil)
}

// Same contract for the conditional-access seam: a nil gin context or a
// zero user id means there is nothing to assess, and a federated login must
// not die on bookkeeping. Passing a nil service proves the guard returns
// before touching it.
func TestAssessLoginRiskAdapter_NoSubjectIsDropped(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked: %v", r)
		}
	}()
	f := assessLoginRiskAdapter(nil, "", false, zap.NewNop())
	f(nil, 1, 2, false)
	f(&gin.Context{}, 1, 0, false)
}
