// Package safego starts goroutines that cannot take the process with them.
//
// An unrecovered panic in ANY goroutine terminates the whole program — not just
// that goroutine. For a server this turns a defect with a blast radius of one
// background job into a total outage, and when the trigger is persisted data it
// does not even end there: the process restarts, reads the same row, panics
// again. A deployment sat in CrashLoopBackOff exactly this way, and the only
// recovery was finding and deleting the offending row while every login in the
// installation was down.
//
// So every `go` in this codebase goes through here. A guard test
// (pkg/safego/no_bare_goroutines_test.go) fails the build on a bare `go func`
// in production code, because the rule is only worth as much as its weakest
// call site — the outage above happened in the one goroutine that had been
// written before the rule existed.
//
// Recovering is NOT a substitute for fixing the panic. The stack is logged at
// ERROR precisely so the underlying defect stays findable; what this changes is
// whether finding it happens under an outage.
package safego

import (
	"runtime/debug"

	"go.uber.org/zap"
)

// Go runs fn in a new goroutine, containing any panic.
//
// name identifies the work in the log — "casbin policy resync", "oidc
// back-channel logout" — so an operator reading the ERROR knows which job
// stopped without decoding the stack.
func Go(logger *zap.Logger, name string, fn func()) {
	go Run(logger, name, fn)
}

// Run executes fn on the CURRENT goroutine with the same protection. Use it
// when the caller has already started the goroutine and only needs the body
// guarded — App.SpawnWorker does this, because it must register with a
// WaitGroup before the work begins.
func Run(logger *zap.Logger, name string, fn func()) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		if logger == nil {
			// Never silently swallow: without a logger the stack going to stderr
			// is the only trace there will be.
			logger = zap.NewNop()
		}
		logger.Error("goroutine panicked and stopped; the process was kept alive deliberately",
			zap.String("job", name),
			zap.Any("recover", r),
			zap.ByteString("stack", debug.Stack()))
	}()
	fn()
}
