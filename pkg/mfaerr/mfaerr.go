// Package mfaerr holds the sentinel errors an MFA verification can fail with.
//
// They live in a public leaf package because the EE module is a separate Go
// module and cannot import `internal/...`: without this, every error crossing
// the registry.VerifyStepUpTOTPFunc seam collapsed into "something went wrong",
// and the external-IdP MFA handler rendered a rate-limit lockout as "invalid
// mfa code" — a user locked out for fifteen minutes was told, every single
// time, that their code was wrong. The local-login path, which can import the
// internal package, told them the truth.
//
// The package has no dependencies on purpose: the internal domain packages
// alias these, so importing it can never introduce a cycle.
package mfaerr

import (
	"errors"
	"time"
)

var (
	// ErrVerifyFailed — the code was wrong.
	ErrVerifyFailed = errors.New("mfa verification failed")

	// ErrCodeReused — the digits were right but that TOTP step was already
	// spent. The user must wait for the next code; telling them the code was
	// "wrong" sends them to re-read the same digits off their phone.
	ErrCodeReused = errors.New("mfa code already used this window")

	// ErrNotConfigured — no verifier is wired, or the user holds no factor.
	// A server-side wiring fault, not user error.
	ErrNotConfigured = errors.New("mfa verifier not configured")

	// ErrRateLimited — too many failed attempts; the account is temporarily
	// locked. Callers should surface a 429 with Retry-After, never a
	// code-was-wrong message: the next attempt fails no matter what the user
	// types, so "try again" is actively misleading advice.
	ErrRateLimited = errors.New("too many MFA verification attempts; account temporarily locked")
)

// RetryAfterer is implemented by a rate-limit error that knows how long its
// lock has left. Handlers use it to emit a Retry-After header so the UI can
// count down instead of inviting a retry that cannot succeed. The concrete
// type lives in an internal CE package; this interface is how callers outside
// that module reach the duration.
type RetryAfterer interface {
	RetryAfterDuration() time.Duration
}
