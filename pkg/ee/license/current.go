package license

import "sync/atomic"

// current holds the process-wide active license, set once at startup (and
// swappable if the admin pastes a new token without a restart). Reads are
// lock-free. Before SetCurrent runs, Current() reports CE.
var current atomic.Pointer[Manager]

// SetCurrent installs the active license Manager. Call at boot after loading
// the token, and again if the license setting changes at runtime.
func SetCurrent(m *Manager) {
	if m == nil {
		m = CE()
	}
	current.Store(m)
}

// Current returns the active license Manager — never nil (CE until set). Gates
// across the app call license.Current().Has(feature).
func Current() *Manager {
	if m := current.Load(); m != nil {
		return m
	}
	return CE()
}
