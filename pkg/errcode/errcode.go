// Package errcode is the single registry mapping domain sentinel errors to the
// stable (HTTP status, numeric business code) pairs the API returns.
//
// Why it exists: before this, every handler open-coded a
// `switch { case errors.Is(err, ErrX): response.NotFound(c, 40401, ...) }`
// block, so the numeric codes were magic ints scattered across ~90 sites with
// colliding, undocumented meanings. Here each domain declares its codes once
// (as named Code values next to its sentinels) and Bind()s each sentinel to
// one; response.MapError then does the lookup, collapsing all those switches.
//
// The numeric code is a FROZEN contract with the frontend, which localizes some
// responses by it (see web/packages/shared/src/api/client.ts). Values therefore
// must not change even as the names/organisation improve — this package keeps
// the same numbers the handlers already emitted.
package errcode

import (
	"errors"
	"sync"
)

// Code pairs an HTTP status with the stable numeric business code.
type Code struct {
	HTTP int
	Num  int
}

var (
	mu       sync.RWMutex
	registry = map[error]Code{}
)

// Bind associates a sentinel error with a Code. Call it from a domain package's
// init() alongside the sentinel + code declarations. Panics on a nil sentinel or
// a re-bind to a DIFFERENT code, so an accidental double registration fails
// loudly at startup rather than silently shadowing.
func Bind(sentinel error, c Code) {
	if sentinel == nil {
		panic("errcode: Bind called with nil sentinel")
	}
	mu.Lock()
	defer mu.Unlock()
	if existing, ok := registry[sentinel]; ok && existing != c {
		panic("errcode: sentinel already bound to a different code")
	}
	registry[sentinel] = c
}

// Lookup returns the Code bound to any sentinel that err wraps (errors.Is), and
// whether one was found.
//
// When several bound sentinels match, the MOST SPECIFIC one wins — the one that
// itself wraps the others. Sentinels used to be mutually exclusive, so the map
// iteration order did not matter; password policy broke that. Its five rules
// each need their own code (the SPA writes the sentence, so "needs a digit" and
// "too short" cannot share a number) while every existing handler still matches
// the ErrWeakPassword umbrella with errors.Is. Both are bound, both match, and
// picking whichever the map yielded first would return a different code from
// one process start to the next.
func Lookup(err error) (Code, bool) {
	if err == nil {
		return Code{}, false
	}
	mu.RLock()
	defer mu.RUnlock()
	var best error
	var bestCode Code
	for sentinel, c := range registry {
		if !errors.Is(err, sentinel) {
			continue
		}
		// sentinel wraps best ⇒ sentinel is the narrower of the two.
		if best == nil || errors.Is(sentinel, best) {
			best, bestCode = sentinel, c
		}
	}
	return bestCode, best != nil
}

// detailed carries a localization parameter alongside a coded error.
//
// A localized code stands for a fixed sentence, which is the point — the SPA
// owns the wording. But some of those sentences need one number from the
// server: "at least 8 characters" is useful, "too short" is not, and the 8
// comes from a policy the frontend cannot see. Detail carries exactly that one
// value; it is interpolated into the translated string, never displayed alone.
type detailed struct {
	error
	detail string
}

func (d detailed) Unwrap() error { return d.error }

// WithDetail attaches a localization parameter to err. response.MapError puts
// it in the response Detail field, where extractMessage feeds it to i18next.
func WithDetail(err error, detail string) error {
	if err == nil {
		return nil
	}
	return detailed{error: err, detail: detail}
}

// DetailOf returns the parameter attached by WithDetail anywhere in err's
// chain, or "" when there is none.
func DetailOf(err error) string {
	var d detailed
	if errors.As(err, &d) {
		return d.detail
	}
	return ""
}

// Shared, cross-cutting codes. The step-up / MFA-enroll / EE-feature codes are a
// FROZEN contract with the frontend (client.ts CODE_* constants + toast.tsx
// LOCALIZED_CODES) — the SPA branches on these exact numbers, so never renumber
// them. EEFeatureRequired is also emitted from pkg/ee/feature.
var (
	StepUpRequired    = Code{HTTP: 403, Num: 40330}
	MFAEnrollRequired = Code{HTTP: 403, Num: 40331}
	EEFeatureRequired = Code{HTTP: 403, Num: 40332}
)
